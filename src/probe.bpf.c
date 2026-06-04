// rstat eBPF probe: per-PID CPU, RSS, IO via sched_switch tracepoint
// All per-process metrics collected in-kernel, no /proc walk needed.
// Runtime-compiled with clang -target bpf -O2 -g.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TASK_COMM_LEN 16
#define MAX_PIDS 8192
#define PF_KTHREAD 0x00200000UL

struct pid_key {
    __u32 pid;
    __u32 _pad;
    __u64 generation;
};

// Per-PID-generation stats: cumulative cpu_ns, latest snapshots for rss/io
struct pid_stats {
    __u64 cpu_ns;       // cumulative on-CPU nanoseconds
    __u64 rss_pages;    // latest RSS snapshot (file+anon+shm pages)
    __u64 io_rb;        // cumulative read_bytes from task->ioac
    __u64 io_wb;        // cumulative write_bytes from task->ioac
    __u32 tgid;         // thread-group id (process id)
    char  comm[TASK_COMM_LEN];
    __u8  state;        // 'D' = uninterruptible, 'Z' = zombie, 0 = normal
    __u8  seen;         // client sets on first observation; cleared on exit/free
    __u8  is_kthread;   // task->flags & PF_KTHREAD
    __u8  _pad;
};

_Static_assert(sizeof(struct pid_key) == 16, "pid_key ABI drift");
_Static_assert(sizeof(struct pid_stats) == 56, "pid_stats ABI drift");
#define ABI_OFFSET(type, field, offset) \
    _Static_assert(__builtin_offsetof(type, field) == offset, #type "." #field " ABI drift")
ABI_OFFSET(struct pid_key, pid, 0);
ABI_OFFSET(struct pid_key, _pad, 4);
ABI_OFFSET(struct pid_key, generation, 8);
ABI_OFFSET(struct pid_stats, cpu_ns, 0);
ABI_OFFSET(struct pid_stats, rss_pages, 8);
ABI_OFFSET(struct pid_stats, io_rb, 16);
ABI_OFFSET(struct pid_stats, io_wb, 24);
ABI_OFFSET(struct pid_stats, tgid, 32);
ABI_OFFSET(struct pid_stats, comm, 36);
ABI_OFFSET(struct pid_stats, state, 52);
ABI_OFFSET(struct pid_stats, seen, 53);
ABI_OFFSET(struct pid_stats, is_kthread, 54);
ABI_OFFSET(struct pid_stats, _pad, 55);

struct sched_in {
    __u64 ts;
};

// Per-PID-generation stats map: userspace iterates this
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_PIDS);
    __type(key, struct pid_key);
    __type(value, struct pid_stats);
} stats SEC(".maps");

// Per-PID schedule-in timestamp (internal)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_PIDS);
    __type(key, __u32);
    __type(value, struct sched_in);
} sched_start SEC(".maps");

// Current process generation for each PID. This keeps userspace deltas and
// zombie acks from crossing PID reuse.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_PIDS);
    __type(key, __u32);
    __type(value, __u64);
} pid_gen SEC(".maps");

// Self-timing histogram: 32 log2(ns) buckets
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 32);
    __type(key, __u32);
    __type(value, __u64);
} latency SEC(".maps");

static __always_inline __u32 log2_u64(__u64 v)
{
    __u32 r = 0;
    if (v > 0xFFFFFFFF) { v >>= 32; r += 32; }
    if (v > 0xFFFF) { v >>= 16; r += 16; }
    if (v > 0xFF) { v >>= 8; r += 8; }
    if (v > 0xF) { v >>= 4; r += 4; }
    if (v > 0x3) { v >>= 2; r += 2; }
    if (v > 0x1) { r += 1; }
    return r;
}

// sched_switch tracepoint context
struct sched_switch_args {
    unsigned short common_type;
    unsigned char  common_flags;
    unsigned char  common_preempt_count;
    int            common_pid;
    char           prev_comm[16];
    int            prev_pid;
    int            prev_prio;
    long           prev_state;
    char           next_comm[16];
    int            next_pid;
    int            next_prio;
};

// 4-byte reads for tracepoint ctx (verifier rejects 8-byte ctx access)
static __always_inline void read_tp_comm(char *dst, const char *src)
{
    *(__u32 *)(dst + 0)  = *(__u32 *)(src + 0);
    *(__u32 *)(dst + 4)  = *(__u32 *)(src + 4);
    *(__u32 *)(dst + 8)  = *(__u32 *)(src + 8);
    *(__u32 *)(dst + 12) = *(__u32 *)(src + 12);
}

// Snapshot RSS and IO from task_struct into pid_stats
static __always_inline __u64 read_task_generation(struct task_struct *task, __u64 fallback)
{
    __u64 generation = 0;
    bpf_probe_read_kernel(&generation, sizeof(generation), &task->start_time);
    return generation ? generation : fallback;
}

static __always_inline __u64 pid_generation(__u32 pid, struct task_struct *task, __u64 fallback)
{
    __u64 *existing = bpf_map_lookup_elem(&pid_gen, &pid);
    if (existing)
        return *existing;

    __u64 generation = read_task_generation(task, fallback);
    bpf_map_update_elem(&pid_gen, &pid, &generation, BPF_NOEXIST);
    existing = bpf_map_lookup_elem(&pid_gen, &pid);
    return existing ? *existing : generation;
}

// Snapshot RSS and IO from task_struct into pid_stats
static __always_inline void snapshot_task(struct pid_stats *s, struct task_struct *task)
{
    // Process identity (aggregate per-process in userspace)
    __u32 tgid = 0;
    bpf_probe_read_kernel(&tgid, sizeof(tgid), &task->tgid);
    s->tgid = tgid;

    unsigned long flags = 0;
    bpf_probe_read_kernel(&flags, sizeof(flags), &task->flags);
    s->is_kthread = (flags & PF_KTHREAD) ? 1 : 0;

    // RSS: mm->rss_stat[0..3].count (percpu_counter approx value)
    // indices: 0=file, 1=anon, 2=swap, 3=shmem; RSS = file+anon+shmem
    struct mm_struct *mm = 0;
    bpf_probe_read_kernel(&mm, sizeof(mm), &task->mm);
    if (mm) {
        __s64 file = 0, anon = 0, shm = 0;
        bpf_probe_read_kernel(&file, sizeof(file), &mm->rss_stat[0].count);
        bpf_probe_read_kernel(&anon, sizeof(anon), &mm->rss_stat[1].count);
        bpf_probe_read_kernel(&shm,  sizeof(shm),  &mm->rss_stat[3].count);
        __s64 total = file + anon + shm;
        s->rss_pages = total > 0 ? (__u64)total : 0;
    }

    // IO: task->ioac.read_bytes, write_bytes (cumulative)
    __u64 rb = 0, wb = 0;
    bpf_probe_read_kernel(&rb, sizeof(rb), &task->ioac.read_bytes);
    bpf_probe_read_kernel(&wb, sizeof(wb), &task->ioac.write_bytes);
    s->io_rb = rb;
    s->io_wb = wb;
}

SEC("tracepoint/sched/sched_switch")
int handle_sched_switch(struct sched_switch_args *ctx)
{
    __u64 now = bpf_ktime_get_ns();
    __u32 prev = ctx->prev_pid;
    __u32 next = ctx->next_pid;

    // Account time for prev (switching out)
    if (prev != 0) {
        struct sched_in *si = bpf_map_lookup_elem(&sched_start, &prev);
        if (si && si->ts > 0) {
            __u64 delta = now - si->ts;
            struct task_struct *task = (void *)bpf_get_current_task();
            __u64 generation = pid_generation(prev, task, now);
            struct pid_key key = { .pid = prev, .generation = generation };
            struct pid_stats *s = bpf_map_lookup_elem(&stats, &key);
            if (s) {
                __sync_fetch_and_add(&s->cpu_ns, delta);
                snapshot_task(s, task);
                if (ctx->prev_state & 0x02)
                    s->state = 'D';
            } else {
                struct pid_stats ns = {};
                ns.cpu_ns = delta;
                if (ctx->prev_state & 0x02)
                    ns.state = 'D';
                read_tp_comm(ns.comm, ctx->prev_comm);
                snapshot_task(&ns, task);
                bpf_map_update_elem(&stats, &key, &ns, BPF_NOEXIST);
            }
        }
        bpf_map_delete_elem(&sched_start, &prev);
    }

    // Record schedule-in time for next and clear D-state if this PID is known.
    if (next != 0) {
        struct sched_in new_si = { .ts = now };
        bpf_map_update_elem(&sched_start, &next, &new_si, BPF_ANY);

        __u64 *generation = bpf_map_lookup_elem(&pid_gen, &next);
        if (generation) {
            struct pid_key key = { .pid = next, .generation = *generation };
            struct pid_stats *ns = bpf_map_lookup_elem(&stats, &key);
            if (ns && ns->state == 'D')
                ns->state = 0;
        }
    }

    // Self-timing: record probe latency in log2(ns) histogram
    __u64 _dt = bpf_ktime_get_ns() - now;
    __u32 _bk = log2_u64(_dt);
    if (_bk > 31) _bk = 31;
    __u64 *_bv = bpf_map_lookup_elem(&latency, &_bk);
    if (_bv) __sync_fetch_and_add(_bv, 1);

    return 0;
}

// Clean up on process exit
struct sched_process_exit_args {
    unsigned short common_type;
    unsigned char  common_flags;
    unsigned char  common_preempt_count;
    int            common_pid;
    char           comm[16];
    int            pid;
    int            prio;
};

SEC("tracepoint/sched/sched_process_exit")
int handle_sched_exit(struct sched_process_exit_args *ctx)
{
    __u32 pid = ctx->pid;
    bpf_map_delete_elem(&sched_start, &pid);
    __u64 *generation = bpf_map_lookup_elem(&pid_gen, &pid);
    if (generation) {
        struct pid_key key = { .pid = pid, .generation = *generation };
        struct pid_stats *s = bpf_map_lookup_elem(&stats, &key);
        if (s) {
            s->state = 'Z';
            s->seen = 0;
        }
    }
    return 0;
}

// Clean up on process reap (zombie -> freed)
struct sched_process_free_args {
    unsigned short common_type;
    unsigned char  common_flags;
    unsigned char  common_preempt_count;
    int            common_pid;
    // tracepoint format is __data_loc char[] comm (u32 location/size descriptor)
    __u32          comm_loc;
    int            pid;
    int            prio;
};

SEC("tracepoint/sched/sched_process_free")
int handle_sched_free(struct sched_process_free_args *ctx)
{
    __u32 pid = ctx->pid;
    bpf_map_delete_elem(&sched_start, &pid);
    __u64 *generation = bpf_map_lookup_elem(&pid_gen, &pid);
    if (generation) {
        struct pid_key key = { .pid = pid, .generation = *generation };
        bpf_map_delete_elem(&stats, &key);
    }
    bpf_map_delete_elem(&pid_gen, &pid);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
