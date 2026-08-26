use std::collections::HashMap;
use std::fmt::Write as FmtWrite;
use std::io::{self, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use std::{fs, thread};

const INTERVALS: [u64; 6] = [500, 250, 100, 2000, 1000, 500];
static INTERVAL_MS: AtomicU64 = AtomicU64::new(500);
static INCLUDE_KTHREADS: AtomicBool = AtomicBool::new(true);
static MAP_CAP_WARNED: AtomicBool = AtomicBool::new(false);
const TOP_N: usize = 5;
const MIN_CPU_PCT: f64 = 1.0;
const MIN_MEM_BYTES: u64 = 250 * 1048576;
const MIN_IO_BYTES: u64 = 1048576;
const COMM_LEN: usize = 16;
const MAX_PIDS: usize = 8192;

// --- Top-N tracking (stack-allocated, no heap) ---

#[derive(Clone, Copy)]
struct TopEntry {
    val: u64,
    comm: [u8; COMM_LEN],
    cl: u8,
}
#[derive(Clone, Copy)]
struct IoEntry {
    total: u64,
    dr: u64,
    dw: u64,
    comm: [u8; COMM_LEN],
    cl: u8,
}

struct Top5 {
    e: [TopEntry; TOP_N],
    n: usize,
}
struct IoTop5 {
    e: [IoEntry; TOP_N],
    n: usize,
}

const EMPTY_TE: TopEntry = TopEntry {
    val: 0,
    comm: [0; COMM_LEN],
    cl: 0,
};
const EMPTY_IE: IoEntry = IoEntry {
    total: 0,
    dr: 0,
    dw: 0,
    comm: [0; COMM_LEN],
    cl: 0,
};

impl Top5 {
    fn new() -> Self {
        Self {
            e: [EMPTY_TE; TOP_N],
            n: 0,
        }
    }
    fn insert(&mut self, val: u64, comm: &[u8]) {
        let mut c = [0u8; COMM_LEN];
        let l = comm.len().min(COMM_LEN);
        c[..l].copy_from_slice(&comm[..l]);
        let e = TopEntry {
            val,
            comm: c,
            cl: l as u8,
        };
        if self.n < TOP_N {
            self.e[self.n] = e;
            self.n += 1;
        } else {
            let mi = self.min_idx();
            if val > self.e[mi].val {
                self.e[mi] = e;
            }
        }
    }
    fn min_idx(&self) -> usize {
        let (mut mi, mut mv) = (0, self.e[0].val);
        let mut i = 1;
        while i < self.n {
            if self.e[i].val < mv {
                mi = i;
                mv = self.e[i].val;
            }
            i += 1;
        }
        mi
    }
    fn sorted(&mut self) -> &[TopEntry] {
        self.e[..self.n].sort_unstable_by_key(|entry| std::cmp::Reverse(entry.val));
        &self.e[..self.n]
    }
}

impl IoTop5 {
    fn new() -> Self {
        Self {
            e: [EMPTY_IE; TOP_N],
            n: 0,
        }
    }
    fn insert(&mut self, total: u64, dr: u64, dw: u64, comm: &[u8]) {
        let mut c = [0u8; COMM_LEN];
        let l = comm.len().min(COMM_LEN);
        c[..l].copy_from_slice(&comm[..l]);
        let e = IoEntry {
            total,
            dr,
            dw,
            comm: c,
            cl: l as u8,
        };
        if self.n < TOP_N {
            self.e[self.n] = e;
            self.n += 1;
        } else {
            let mi = self.min_idx();
            if total > self.e[mi].total {
                self.e[mi] = e;
            }
        }
    }
    fn min_idx(&self) -> usize {
        let (mut mi, mut mv) = (0, self.e[0].total);
        let mut i = 1;
        while i < self.n {
            if self.e[i].total < mv {
                mi = i;
                mv = self.e[i].total;
            }
            i += 1;
        }
        mi
    }
    fn sorted(&mut self) -> &[IoEntry] {
        self.e[..self.n].sort_unstable_by_key(|entry| std::cmp::Reverse(entry.total));
        &self.e[..self.n]
    }
}

const MAX_BLOCKED: usize = 10;
#[derive(Clone, Copy)]
struct StateEntry {
    state: u8,
    comm: [u8; COMM_LEN],
    cl: u8,
}
const EMPTY_SE: StateEntry = StateEntry {
    state: 0,
    comm: [0; COMM_LEN],
    cl: 0,
};

struct StateList {
    e: [StateEntry; MAX_BLOCKED],
    n: usize,
}
impl StateList {
    fn new() -> Self {
        Self {
            e: [EMPTY_SE; MAX_BLOCKED],
            n: 0,
        }
    }
    fn push(&mut self, state: u8, comm: &[u8]) {
        if self.n >= MAX_BLOCKED {
            return;
        }
        let mut c = [0u8; COMM_LEN];
        let l = comm.len().min(COMM_LEN);
        c[..l].copy_from_slice(&comm[..l]);
        self.e[self.n] = StateEntry {
            state,
            comm: c,
            cl: l as u8,
        };
        self.n += 1;
    }
    fn sorted(&mut self) -> &[StateEntry] {
        self.e[..self.n].sort_unstable_by_key(|e| e.state);
        &self.e[..self.n]
    }
}

fn push_lossy(out: &mut String, bytes: &[u8]) {
    let mut rest = bytes;
    while !rest.is_empty() {
        match std::str::from_utf8(rest) {
            Ok(valid) => {
                out.push_str(valid);
                break;
            }
            Err(error) => {
                let valid = error.valid_up_to();
                // SAFETY: valid_up_to identifies a valid UTF-8 prefix.
                out.push_str(unsafe { std::str::from_utf8_unchecked(&rest[..valid]) });
                out.push(char::REPLACEMENT_CHARACTER);
                rest = &rest[valid + error.error_len().unwrap_or(rest.len() - valid)..];
            }
        }
    }
}

fn push_comm(out: &mut String, c: &[u8; COMM_LEN], l: u8) {
    push_lossy(out, &c[..l as usize]);
}

// --- sysfs file handles (pread, no seek syscall) ---

struct ThrottleFile {
    file: fs::File,
    name: [u8; 32],
    nl: u8,
}

struct SysFds {
    temp: Option<fs::File>,
    freq: Option<fs::File>,
    fmax: Option<fs::File>,
    rc6: Option<fs::File>,
    gpu_freq: Option<fs::File>,
    gpu_max: Option<fs::File>,
    profile: Option<fs::File>,
    psi_mem: Option<fs::File>,
    vmstat: Option<fs::File>,
    meminfo: Option<fs::File>,
    throttle: Vec<ThrottleFile>,
}

impl SysFds {
    fn open() -> Self {
        let gpu_dir = find_gpu_dir();
        let mut throttle = Vec::new();
        if let Some(dir) = &gpu_dir
            && let Ok(rd) = fs::read_dir(dir)
        {
            for e in rd.flatten() {
                let fname = e.file_name();
                let n = fname.as_encoded_bytes();
                if !n.starts_with(b"throttle_reason_") {
                    continue;
                }
                let sfx = &n[16..];
                if sfx == b"status" || sfx.starts_with(b"pl") {
                    continue;
                }
                if let Ok(f) = fs::File::open(e.path()) {
                    let mut name = [0u8; 32];
                    let l = sfx.len().min(32);
                    name[..l].copy_from_slice(&sfx[..l]);
                    throttle.push(ThrottleFile {
                        file: f,
                        name,
                        nl: l as u8,
                    });
                }
            }
        }
        Self {
            temp: find_cpu_temp(),
            freq: fs::File::open("/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq").ok(),
            fmax: fs::File::open("/sys/devices/system/cpu/cpu0/cpufreq/scaling_max_freq").ok(),
            rc6: gpu_dir
                .as_ref()
                .and_then(|d| fs::File::open(d.join("rc6_residency_ms")).ok()),
            gpu_freq: gpu_dir
                .as_ref()
                .and_then(|d| fs::File::open(d.join("rps_act_freq_mhz")).ok()),
            gpu_max: gpu_dir
                .as_ref()
                .and_then(|d| fs::File::open(d.join("rps_max_freq_mhz")).ok()),
            profile: fs::File::open("/sys/firmware/acpi/platform_profile").ok(),
            psi_mem: fs::File::open("/proc/pressure/memory").ok(),
            vmstat: fs::File::open("/proc/vmstat").ok(),
            meminfo: fs::File::open("/proc/meminfo").ok(),
            throttle,
        }
    }
}

fn find_cpu_temp() -> Option<fs::File> {
    let zones = fs::read_dir("/sys/class/thermal").ok();
    if let Some(zones) = zones {
        for entry in zones.flatten() {
            let path = entry.path();
            let name = entry.file_name();
            if !name.as_encoded_bytes().starts_with(b"thermal_zone") {
                continue;
            }
            let Ok(kind) = fs::read_to_string(path.join("type")) else {
                continue;
            };
            let kind = kind.trim().to_ascii_lowercase();
            if (kind.contains("cpu") || kind.contains("package") || kind.contains("x86_pkg"))
                && let Ok(file) = fs::File::open(path.join("temp"))
            {
                return Some(file);
            }
        }
    }

    let hwmons = fs::read_dir("/sys/class/hwmon").ok()?;
    for entry in hwmons.flatten() {
        let path = entry.path();
        let Ok(name) = fs::read_to_string(path.join("name")) else {
            continue;
        };
        if !matches!(
            name.trim(),
            "coretemp" | "k10temp" | "zenpower" | "cpu_thermal"
        ) {
            continue;
        }

        let mut fallback = None;
        let Ok(files) = fs::read_dir(&path) else {
            continue;
        };
        for file in files.flatten() {
            let file_name = file.file_name();
            let bytes = file_name.as_encoded_bytes();
            let Some(stem) = bytes.strip_suffix(b"_input") else {
                continue;
            };
            if !stem.starts_with(b"temp") || stem[4..].iter().any(|b| !b.is_ascii_digit()) {
                continue;
            }
            let Ok(input) = fs::File::open(file.path()) else {
                continue;
            };
            let label_path = path.join(format!("{}_label", String::from_utf8_lossy(stem)));
            let preferred = fs::read_to_string(label_path)
                .map(|label| {
                    let label = label.trim().to_ascii_lowercase();
                    label.contains("package")
                        || label == "tctl"
                        || label == "tdie"
                        || label.contains("cpu")
                })
                .unwrap_or(false);
            if preferred {
                return Some(input);
            }
            if bytes == b"temp1_input" {
                fallback = Some(input);
            }
        }
        if fallback.is_some() {
            return fallback;
        }
    }
    None
}

fn find_gpu_dir() -> Option<PathBuf> {
    let rd = fs::read_dir("/sys/class/drm").ok()?;
    for entry in rd.flatten() {
        let name = entry.file_name();
        let nb = name.as_encoded_bytes();
        if !nb.starts_with(b"card") || nb.iter().skip(4).any(|b| !b.is_ascii_digit()) {
            continue;
        }
        let gt = entry.path().join("gt/gt0");
        if gt.join("rc6_residency_ms").is_file()
            || gt.join("rps_act_freq_mhz").is_file()
            || gt.join("rps_max_freq_mhz").is_file()
        {
            return Some(gt);
        }
    }
    None
}

#[inline]
fn pread_raw(f: &fs::File, buf: &mut [u8]) -> usize {
    loop {
        let n = unsafe {
            libc::pread(
                f.as_raw_fd(),
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                0,
            )
        };
        if n >= 0 {
            return n as usize;
        }
        if io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            return 0;
        }
    }
}

#[inline]
fn pread_u64(f: &fs::File, buf: &mut [u8]) -> u64 {
    let n = pread_raw(f, buf);
    parse_u64_trim(&buf[..n])
}

fn pread_u64_opt(f: Option<&fs::File>, buf: &mut [u8]) -> Option<u64> {
    f.map(|f| pread_u64(f, buf))
}

fn parse_u64_trim(b: &[u8]) -> u64 {
    let mut v = 0u64;
    let mut started = false;
    for &c in b {
        if c == b'\n' {
            break;
        }
        if c.is_ascii_digit() {
            v = v * 10 + (c - b'0') as u64;
            started = true;
        } else if started {
            break;
        }
    }
    v
}

fn parse_psi_total(line: &[u8]) -> Option<u64> {
    let mut i = 0usize;
    while i + 6 <= line.len() {
        if &line[i..i + 6] == b"total=" {
            return Some(parse_u64_trim(&line[i + 6..]));
        }
        i += 1;
    }
    None
}

fn parse_psi_memory_totals(b: &[u8]) -> (Option<u64>, Option<u64>) {
    let mut some = None;
    let mut full = None;
    for line in b.split(|&c| c == b'\n') {
        if line.starts_with(b"some ") {
            some = parse_psi_total(line);
        } else if line.starts_with(b"full ") {
            full = parse_psi_total(line);
        }
    }
    (some, full)
}

fn parse_vmstat_swap_pages(b: &[u8]) -> (Option<u64>, Option<u64>) {
    let mut pswpin = None;
    let mut pswpout = None;
    for line in b.split(|&c| c == b'\n') {
        if line.starts_with(b"pswpin ") {
            pswpin = Some(parse_u64_trim(&line[7..]));
        } else if line.starts_with(b"pswpout ") {
            pswpout = Some(parse_u64_trim(&line[8..]));
        }
    }
    (pswpin, pswpout)
}

fn parse_meminfo_bytes(b: &[u8]) -> (Option<u64>, Option<u64>) {
    let mut total = None;
    let mut available = None;
    for line in b.split(|&c| c == b'\n') {
        if let Some(value) = line.strip_prefix(b"MemTotal:") {
            total = Some(parse_u64_trim(value).saturating_mul(1024));
        } else if let Some(value) = line.strip_prefix(b"MemAvailable:") {
            available = Some(parse_u64_trim(value).saturating_mul(1024));
        }
    }
    (total, available)
}

fn parse_cpu_list(input: &str) -> Option<Vec<i32>> {
    let mut cpus = Vec::new();
    for part in input.trim().split(',') {
        if part.is_empty() {
            return None;
        }
        let (first, last) = part.split_once('-').map_or_else(
            || part.parse::<i32>().ok().map(|cpu| (cpu, cpu)),
            |(a, b)| Some((a.parse::<i32>().ok()?, b.parse::<i32>().ok()?)),
        )?;
        if first < 0 || last < first {
            return None;
        }
        cpus.extend(first..=last);
    }
    cpus.sort_unstable();
    cpus.dedup();
    (!cpus.is_empty()).then_some(cpus)
}

fn online_cpus() -> Option<Vec<i32>> {
    fs::read_to_string("/sys/devices/system/cpu/online")
        .ok()
        .and_then(|list| parse_cpu_list(&list))
        .or_else(|| {
            let count = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) };
            (count > 0).then(|| (0..count as i32).collect())
        })
}

fn read_raw(path: &str, buf: &mut [u8]) -> Option<usize> {
    let mut f = fs::File::open(path).ok()?;
    std::io::Read::read(&mut f, buf).ok()
}

fn get_sysinfo() -> libc::sysinfo {
    let mut si: libc::sysinfo = unsafe { std::mem::zeroed() };
    unsafe { libc::sysinfo(&mut si) };
    si
}

// --- Sorted PID stats (zero-alloc steady state) ---

#[repr(C)]
#[derive(Clone, Copy, Default, Eq, PartialEq, Ord, PartialOrd)]
struct BpfPidKey {
    pid: u32,
    _pad: u32,
    generation: u64,
}

struct PidStats {
    entries: Vec<(BpfPidKey, BpfPidStats)>,
}

impl PidStats {
    fn with_capacity(n: usize) -> Self {
        Self {
            entries: Vec::with_capacity(n),
        }
    }
    fn clear(&mut self) {
        self.entries.clear();
    }
    fn push(&mut self, key: BpfPidKey, st: BpfPidStats) {
        self.entries.push((key, st));
    }
    fn sort(&mut self) {
        self.entries.sort_unstable_by_key(|e| e.0);
    }
    fn get(&self, key: BpfPidKey) -> Option<&BpfPidStats> {
        self.entries
            .binary_search_by_key(&key, |e| e.0)
            .ok()
            .map(|i| &self.entries[i].1)
    }
    fn len(&self) -> usize {
        self.entries.len()
    }
}

// --- eBPF loader ---

const BPF_MAP_CREATE: u32 = 0;
const BPF_MAP_LOOKUP_ELEM: u32 = 1;
const BPF_MAP_UPDATE_ELEM: u32 = 2;
const BPF_MAP_DELETE_ELEM: u32 = 3;
const BPF_MAP_GET_NEXT_KEY: u32 = 4;
const BPF_PROG_LOAD: u32 = 5;
const BPF_MAP_LOOKUP_BATCH: u32 = 24;

const BPF_MAP_TYPE_HASH: u32 = 1;
const BPF_MAP_TYPE_ARRAY: u32 = 2;
const BPF_PROG_TYPE_TRACEPOINT: u32 = 5;

const PERF_TYPE_TRACEPOINT: u32 = 2;
const PERF_EVENT_IOC_ENABLE: u64 = 0x2400;
const PERF_EVENT_IOC_SET_BPF: u64 = 0x40042408;

const BPF_INSN_SIZE: usize = 8;
const BPF_LD_IMM64: u8 = 0x18;

#[repr(C)]
struct BpfAttrMapCreate {
    map_type: u32,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
}

#[derive(Clone, Copy)]
struct BpfMapDef {
    name: &'static str,
    map_type: u32,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    fd: RawFd,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct BpfPidStats {
    cpu_ns: u64,
    rss_pages: u64,
    io_rb: u64,
    io_wb: u64,
    snapshot_ns: u64,
    tgid: u32,
    comm: [u8; 16],
    state: u8,
    reserved: u8,
    is_kthread: u8,
    io_baseline: u8,
}

const _: () = assert!(std::mem::size_of::<BpfPidKey>() == 16);
const _: () = assert!(std::mem::align_of::<BpfPidKey>() == 8);
const _: () = assert!(std::mem::offset_of!(BpfPidKey, pid) == 0);
const _: () = assert!(std::mem::offset_of!(BpfPidKey, _pad) == 4);
const _: () = assert!(std::mem::offset_of!(BpfPidKey, generation) == 8);
const _: () = assert!(std::mem::size_of::<BpfPidStats>() == 64);
const _: () = assert!(std::mem::align_of::<BpfPidStats>() == 8);
const _: () = assert!(std::mem::offset_of!(BpfPidStats, cpu_ns) == 0);
const _: () = assert!(std::mem::offset_of!(BpfPidStats, rss_pages) == 8);
const _: () = assert!(std::mem::offset_of!(BpfPidStats, io_rb) == 16);
const _: () = assert!(std::mem::offset_of!(BpfPidStats, io_wb) == 24);
const _: () = assert!(std::mem::offset_of!(BpfPidStats, snapshot_ns) == 32);
const _: () = assert!(std::mem::offset_of!(BpfPidStats, tgid) == 40);
const _: () = assert!(std::mem::offset_of!(BpfPidStats, comm) == 44);
const _: () = assert!(std::mem::offset_of!(BpfPidStats, state) == 60);
const _: () = assert!(std::mem::offset_of!(BpfPidStats, reserved) == 61);
const _: () = assert!(std::mem::offset_of!(BpfPidStats, is_kthread) == 62);
const _: () = assert!(std::mem::offset_of!(BpfPidStats, io_baseline) == 63);

#[repr(C)]
struct BpfAttrBatch {
    in_batch: u64,
    out_batch: u64,
    keys: u64,
    values: u64,
    count: u32,
    map_fd: u32,
    elem_flags: u64,
    flags: u64,
}

struct BpfLoader {
    maps: [BpfMapDef; 4],
    prog_fds: Vec<RawFd>,
    perf_fds: Vec<RawFd>,
    stats_fd: RawFd,
    pid_gen_fd: RawFd,
    latency_fd: RawFd,
    use_batch: bool,
    bk: Vec<BpfPidKey>,
    bv: Vec<BpfPidStats>,
}

fn bytes_of<T>(v: &T) -> &[u8] {
    unsafe { std::slice::from_raw_parts(v as *const _ as *const u8, std::mem::size_of::<T>()) }
}

fn bytes_of_mut<T>(v: &mut T) -> &mut [u8] {
    unsafe { std::slice::from_raw_parts_mut(v as *mut _ as *mut u8, std::mem::size_of::<T>()) }
}

unsafe fn bpf_sys(cmd: u32, attr: *const u8, size: u32) -> i64 {
    unsafe { libc::syscall(libc::SYS_bpf, cmd as i64, attr as i64, size as i64) }
}

fn bpf_map_create(mt: u32, ks: u32, vs: u32, me: u32) -> Option<RawFd> {
    let a = BpfAttrMapCreate {
        map_type: mt,
        key_size: ks,
        value_size: vs,
        max_entries: me,
    };
    let fd = unsafe {
        bpf_sys(
            BPF_MAP_CREATE,
            &a as *const _ as *const u8,
            std::mem::size_of::<BpfAttrMapCreate>() as u32,
        )
    };
    if fd < 0 { None } else { Some(fd as RawFd) }
}

fn bpf_map_lookup(fd: RawFd, key: &[u8], val: &mut [u8]) -> bool {
    #[repr(C)]
    struct A {
        fd: u32,
        _p: u32,
        key: u64,
        val: u64,
    }
    let a = A {
        fd: fd as u32,
        _p: 0,
        key: key.as_ptr() as u64,
        val: val.as_mut_ptr() as u64,
    };
    unsafe {
        bpf_sys(
            BPF_MAP_LOOKUP_ELEM,
            &a as *const _ as *const u8,
            std::mem::size_of::<A>() as u32,
        ) == 0
    }
}

fn bpf_map_update(fd: RawFd, key: &[u8], val: &[u8], flags: u64) -> bool {
    #[repr(C)]
    struct A {
        fd: u32,
        _p: u32,
        key: u64,
        val: u64,
        flags: u64,
    }
    let a = A {
        fd: fd as u32,
        _p: 0,
        key: key.as_ptr() as u64,
        val: val.as_ptr() as u64,
        flags,
    };
    unsafe {
        bpf_sys(
            BPF_MAP_UPDATE_ELEM,
            &a as *const _ as *const u8,
            std::mem::size_of::<A>() as u32,
        ) == 0
    }
}

fn bpf_map_delete(fd: RawFd, key: &[u8]) -> bool {
    #[repr(C)]
    struct Attr {
        fd: u32,
        _pad: u32,
        key: u64,
    }
    let attr = Attr {
        fd: fd as u32,
        _pad: 0,
        key: key.as_ptr() as u64,
    };
    unsafe {
        bpf_sys(
            BPF_MAP_DELETE_ELEM,
            &attr as *const _ as *const u8,
            std::mem::size_of::<Attr>() as u32,
        ) == 0
    }
}

fn bpf_map_get_next_key(fd: RawFd, key: Option<&[u8]>, next: &mut [u8]) -> bool {
    #[repr(C)]
    struct A {
        fd: u32,
        _p: u32,
        key: u64,
        next: u64,
    }
    let kp = key.map(|k| k.as_ptr() as u64).unwrap_or(0);
    let a = A {
        fd: fd as u32,
        _p: 0,
        key: kp,
        next: next.as_mut_ptr() as u64,
    };
    unsafe {
        bpf_sys(
            BPF_MAP_GET_NEXT_KEY,
            &a as *const _ as *const u8,
            std::mem::size_of::<A>() as u32,
        ) == 0
    }
}

fn bpf_prog_load(pt: u32, insns: &[u8], lic: &[u8], log: &mut [u8]) -> Option<RawFd> {
    #[repr(C)]
    struct A {
        prog_type: u32,
        insn_cnt: u32,
        insns: u64,
        license: u64,
        log_level: u32,
        log_size: u32,
        log_buf: u64,
        kern_version: u32,
        prog_flags: u32,
        _pad: [u64; 16],
    }
    let a = A {
        prog_type: pt,
        insn_cnt: (insns.len() / BPF_INSN_SIZE) as u32,
        insns: insns.as_ptr() as u64,
        license: lic.as_ptr() as u64,
        log_level: if log.is_empty() { 0 } else { 1 },
        log_size: log.len() as u32,
        log_buf: log.as_mut_ptr() as u64,
        kern_version: 0,
        prog_flags: 0,
        _pad: [0; 16],
    };
    let fd = unsafe {
        bpf_sys(
            BPF_PROG_LOAD,
            &a as *const _ as *const u8,
            std::mem::size_of::<A>() as u32,
        )
    };
    if fd < 0 { None } else { Some(fd as RawFd) }
}

fn tracepoint_id(cat: &str, name: &str) -> Option<u64> {
    let p = format!("/sys/kernel/tracing/events/{cat}/{name}/id");
    let mut buf = [0u8; 32];
    let n = read_raw(&p, &mut buf)?;
    Some(parse_u64_trim(&buf[..n]))
}

fn perf_event_open_tracepoint(tp_id: u64, cpu: i32) -> Option<RawFd> {
    #[repr(C)]
    struct PerfEventAttr {
        type_: u32,
        size: u32,
        config: u64,
        sample_period: u64,
        sample_type: u64,
        read_format: u64,
        flags: u64,
        wakeup_events: u32,
        bp_type: u32,
        config1: u64,
    }
    let mut a: PerfEventAttr = unsafe { std::mem::zeroed() };
    a.type_ = PERF_TYPE_TRACEPOINT;
    a.size = std::mem::size_of::<PerfEventAttr>() as u32;
    a.config = tp_id;
    let fd = unsafe {
        libc::syscall(
            libc::SYS_perf_event_open,
            &a as *const _,
            -1i32,
            cpu,
            -1i32,
            0u64,
        )
    };
    if fd < 0 { None } else { Some(fd as RawFd) }
}

fn effective_caps_nonzero() -> bool {
    let Ok(status) = fs::read_to_string("/proc/self/status") else {
        return false;
    };
    for line in status.lines() {
        let Some(hex) = line.strip_prefix("CapEff:\t") else {
            continue;
        };
        return u64::from_str_radix(hex.trim(), 16).unwrap_or(0) != 0;
    }
    false
}

fn privileged_context() -> bool {
    let uid = unsafe { libc::getuid() };
    let euid = unsafe { libc::geteuid() };
    uid != euid || euid == 0 || effective_caps_nonzero()
}

fn tool_path(compiled_path: Option<&'static str>, fallback: &str) -> Option<String> {
    if let Some(path) = compiled_path {
        return Some(path.to_string());
    }
    if privileged_context() {
        return None;
    }
    Some(fallback.to_string())
}

fn runtime_probe_source(vmlinux_h: &[u8]) -> Option<Vec<u8>> {
    const BPF_SOURCE: &[u8] = include_bytes!("probe.bpf.c");
    const VMLINUX_INCLUDE: &[u8] = b"#include \"vmlinux.h\"\n";

    let Some(pos) = BPF_SOURCE
        .windows(VMLINUX_INCLUDE.len())
        .position(|w| w == VMLINUX_INCLUDE)
    else {
        eprintln!("rstat: bundled probe source is missing vmlinux.h include");
        return None;
    };

    let mut source = Vec::with_capacity(BPF_SOURCE.len() + vmlinux_h.len());
    source.extend_from_slice(&BPF_SOURCE[..pos]);
    source.extend_from_slice(vmlinux_h);
    source.push(b'\n');
    source.extend_from_slice(&BPF_SOURCE[pos + VMLINUX_INCLUDE.len()..]);
    Some(source)
}

fn build_runtime_probe(instrumented: bool) -> Option<Vec<u8>> {
    const LIVE_BTF: &str = "/sys/kernel/btf/vmlinux";

    if !Path::new(LIVE_BTF).is_file() {
        eprintln!("rstat: live kernel BTF not found at {LIVE_BTF}");
        return None;
    }

    let bpftool = match tool_path(option_env!("RSTAT_BPFTOOL"), "bpftool") {
        Some(path) => path,
        None => {
            eprintln!("rstat: privileged probe build requires RSTAT_BPFTOOL at compile time");
            return None;
        }
    };
    let clang = match tool_path(option_env!("RSTAT_CLANG"), "clang") {
        Some(path) => path,
        None => {
            eprintln!("rstat: privileged probe build requires RSTAT_CLANG at compile time");
            return None;
        }
    };

    let btf_output = match Command::new(&bpftool)
        .args(["btf", "dump", "file", LIVE_BTF, "format", "c"])
        .output()
    {
        Ok(output) if output.status.success() && !output.stdout.is_empty() => output,
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.trim().is_empty() {
                eprintln!(
                    "rstat: bpftool failed while dumping live kernel BTF: {}",
                    output.status
                );
            } else {
                eprintln!(
                    "rstat: bpftool failed while dumping live kernel BTF: {}\n{}",
                    output.status,
                    stderr.trim_end()
                );
            }
            return None;
        }
        Err(e) => {
            eprintln!("rstat: failed to run bpftool ({bpftool}): {e}");
            return None;
        }
    };
    let source = runtime_probe_source(&btf_output.stdout)?;

    let mut clang_cmd = Command::new(&clang);
    clang_cmd.args([
        "-target", "bpf", "-O2", "-g", "-x", "c", "-c", "-", "-o", "-",
    ]);
    if instrumented {
        clang_cmd.arg("-DRSTAT_PROFILE");
    }
    if let Some(include) = option_env!("RSTAT_LIBBPF_INCLUDE") {
        clang_cmd.arg("-I").arg(include);
    }

    let mut child = match clang_cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(e) => {
            eprintln!("rstat: failed to run clang ({clang}): {e}");
            return None;
        }
    };
    let Some(mut stdin) = child.stdin.take() else {
        eprintln!("rstat: failed to open clang stdin");
        return None;
    };
    if let Err(e) = stdin.write_all(&source) {
        eprintln!("rstat: failed to write probe source to clang: {e}");
        return None;
    }
    drop(stdin);

    match child.wait_with_output() {
        Ok(output) if output.status.success() && !output.stdout.is_empty() => Some(output.stdout),
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.trim().is_empty() {
                eprintln!(
                    "rstat: clang failed while compiling live-BTF probe: {}",
                    output.status
                );
            } else {
                eprintln!(
                    "rstat: clang failed while compiling live-BTF probe: {}\n{}",
                    output.status,
                    stderr.trim_end()
                );
            }
            None
        }
        Err(e) => {
            eprintln!("rstat: failed to wait for clang ({clang}): {e}");
            None
        }
    }
}

impl BpfLoader {
    fn load(data: &[u8], online_cpus: &[i32]) -> Option<Self> {
        let elf = goblin::elf::Elf::parse(data).ok()?;

        let mut maps = [
            BpfMapDef {
                name: "stats",
                map_type: BPF_MAP_TYPE_HASH,
                key_size: std::mem::size_of::<BpfPidKey>() as u32,
                value_size: std::mem::size_of::<BpfPidStats>() as u32,
                max_entries: MAX_PIDS as u32,
                fd: -1,
            },
            BpfMapDef {
                name: "sched_start",
                map_type: BPF_MAP_TYPE_HASH,
                key_size: 4,
                value_size: 8,
                max_entries: MAX_PIDS as u32,
                fd: -1,
            },
            BpfMapDef {
                name: "pid_gen",
                map_type: BPF_MAP_TYPE_HASH,
                key_size: 4,
                value_size: 8,
                max_entries: MAX_PIDS as u32,
                fd: -1,
            },
            BpfMapDef {
                name: "latency",
                map_type: BPF_MAP_TYPE_ARRAY,
                key_size: 4,
                value_size: 8,
                max_entries: 32,
                fd: -1,
            },
        ];
        for m in &mut maps {
            m.fd = bpf_map_create(m.map_type, m.key_size, m.value_size, m.max_entries)?;
        }

        let maps_shndx = elf.section_headers.iter().position(|s| {
            elf.shdr_strtab
                .get_at(s.sh_name)
                .map(|n| n == ".maps")
                .unwrap_or(false)
        });

        fn close_all(maps: &[BpfMapDef; 4], prog_fds: &[RawFd], perf_fds: &[RawFd]) {
            for m in maps {
                unsafe {
                    libc::close(m.fd);
                }
            }
            for f in prog_fds {
                unsafe {
                    libc::close(*f);
                }
            }
            for f in perf_fds {
                unsafe {
                    libc::close(*f);
                }
            }
        }

        let mut prog_fds = Vec::new();
        let mut perf_fds = Vec::new();
        let mut sym_to_fd = HashMap::new();
        let mut found_maps = [false; 4];
        if let Some(mi) = maps_shndx {
            for (si, sym) in elf.syms.iter().enumerate() {
                if sym.st_shndx == mi {
                    let name = elf.strtab.get_at(sym.st_name).unwrap_or("");
                    let mut known = false;
                    for (idx, m) in maps.iter().enumerate() {
                        if m.name == name {
                            sym_to_fd.insert(si, m.fd);
                            found_maps[idx] = true;
                            known = true;
                        }
                    }
                    if !known && !name.is_empty() {
                        eprintln!("bpf: object contains unknown map {name}");
                        close_all(&maps, &prog_fds, &perf_fds);
                        return None;
                    }
                }
            }
        }
        for (idx, m) in maps.iter().enumerate() {
            if !found_maps[idx] {
                eprintln!("bpf: required map missing from object: {}", m.name);
                close_all(&maps, &prog_fds, &perf_fds);
                return None;
            }
        }

        let stats_fd = maps[0].fd;
        let pid_gen_fd = maps[2].fd;
        let license = b"GPL\0";

        let prog_sections: Vec<(usize, String)> = elf
            .section_headers
            .iter()
            .enumerate()
            .filter_map(|(i, s)| {
                let name = elf.shdr_strtab.get_at(s.sh_name)?;
                if name.starts_with("tracepoint/")
                    && s.sh_type == goblin::elf::section_header::SHT_PROGBITS
                    && s.sh_size > 0
                {
                    Some((i, name.to_string()))
                } else {
                    None
                }
            })
            .collect();

        const REQUIRED_SECTIONS: [&str; 4] = [
            "tracepoint/sched/sched_switch",
            "tracepoint/sched/sched_process_fork",
            "tracepoint/sched/sched_process_exit",
            "tracepoint/sched/sched_process_free",
        ];
        for req in REQUIRED_SECTIONS {
            if !prog_sections.iter().any(|(_, n)| n == req) {
                eprintln!("bpf: required program section missing: {req}");
                close_all(&maps, &prog_fds, &perf_fds);
                return None;
            }
        }

        if online_cpus.is_empty() {
            eprintln!("bpf: no online CPUs found");
            close_all(&maps, &prog_fds, &perf_fds);
            return None;
        }

        for (shndx, sec_name) in &prog_sections {
            let sh = &elf.section_headers[*shndx];
            let mut insns =
                data[sh.sh_offset as usize..(sh.sh_offset + sh.sh_size) as usize].to_vec();

            for rel_sh in &elf.section_headers {
                if rel_sh.sh_type != goblin::elf::section_header::SHT_REL {
                    continue;
                }
                if rel_sh.sh_info as usize != *shndx {
                    continue;
                }
                let rd =
                    &data[rel_sh.sh_offset as usize..(rel_sh.sh_offset + rel_sh.sh_size) as usize];
                let rc = rel_sh.sh_size as usize / 16;
                for i in 0..rc {
                    let off = i * 16;
                    let r_offset = u64::from_le_bytes(rd[off..off + 8].try_into().unwrap());
                    let r_info = u64::from_le_bytes(rd[off + 8..off + 16].try_into().unwrap());
                    let sym_idx = (r_info >> 32) as usize;
                    if let Some(&fd) = sym_to_fd.get(&sym_idx) {
                        let io = r_offset as usize;
                        if io + 16 <= insns.len() && insns[io] == BPF_LD_IMM64 {
                            insns[io + 4..io + 8].copy_from_slice(&(fd as u32).to_le_bytes());
                            insns[io + 1] = (insns[io + 1] & 0x0f) | 0x10;
                        }
                    }
                }
            }

            let mut log = vec![0u8; 65536];
            let fd = match bpf_prog_load(BPF_PROG_TYPE_TRACEPOINT, &insns, license, &mut log) {
                Some(f) => f,
                None => {
                    let ls = std::str::from_utf8(&log)
                        .unwrap_or("")
                        .trim_end_matches('\0');
                    if !ls.is_empty() {
                        eprintln!("bpf: prog load failed for {sec_name}:\n{ls}");
                    } else {
                        eprintln!(
                            "bpf: prog load failed for {sec_name}: {}",
                            io::Error::last_os_error()
                        );
                    }
                    close_all(&maps, &prog_fds, &perf_fds);
                    return None;
                }
            };
            prog_fds.push(fd);

            let parts = sec_name.splitn(3, '/').collect::<Vec<&str>>();
            if parts.len() != 3 {
                eprintln!("bpf: invalid section name format: {sec_name}");
                close_all(&maps, &prog_fds, &perf_fds);
                return None;
            }
            let (cat, tp) = (parts[1], parts[2]);
            let tp_id = match tracepoint_id(cat, tp) {
                Some(id) => id,
                None => {
                    eprintln!("bpf: tracepoint {cat}/{tp} not found");
                    close_all(&maps, &prog_fds, &perf_fds);
                    return None;
                }
            };

            let mut sec_perf = Vec::with_capacity(online_cpus.len());
            for &cpu in online_cpus {
                let Some(pfd) = perf_event_open_tracepoint(tp_id, cpu) else {
                    eprintln!("bpf: perf_event_open failed for {sec_name} cpu {cpu}");
                    for fd in &sec_perf {
                        unsafe { libc::close(*fd) };
                    }
                    close_all(&maps, &prog_fds, &perf_fds);
                    return None;
                };
                sec_perf.push(pfd);
            }

            if sec_perf.is_empty() {
                eprintln!("bpf: no perf fds opened for {sec_name}");
                close_all(&maps, &prog_fds, &perf_fds);
                return None;
            }
            perf_fds.extend(sec_perf.iter().copied());

            let mut attached = false;
            for (&cpu, pfd) in online_cpus.iter().zip(&sec_perf) {
                let set_r =
                    unsafe { libc::ioctl(*pfd, PERF_EVENT_IOC_SET_BPF as libc::c_ulong, fd) };
                if set_r < 0 {
                    let error = io::Error::last_os_error();
                    // Tracepoints keep a global program array. The first
                    // per-CPU perf event installs this program; attaching the
                    // same program for the remaining CPUs returns EEXIST.
                    if error.raw_os_error() != Some(libc::EEXIST) || !attached {
                        eprintln!("bpf: attach failed for {sec_name} cpu {cpu}: {error}");
                        close_all(&maps, &prog_fds, &perf_fds);
                        return None;
                    }
                } else {
                    attached = true;
                }
                let er = unsafe { libc::ioctl(*pfd, PERF_EVENT_IOC_ENABLE as libc::c_ulong, 0) };
                if er < 0 {
                    eprintln!(
                        "bpf: enable failed for {sec_name} cpu {cpu}: {}",
                        io::Error::last_os_error()
                    );
                    close_all(&maps, &prog_fds, &perf_fds);
                    return None;
                }
            }
        }

        if prog_fds.is_empty() {
            close_all(&maps, &prog_fds, &perf_fds);
            return None;
        }

        let latency_fd = maps[3].fd;
        Some(BpfLoader {
            maps,
            prog_fds,
            perf_fds,
            stats_fd,
            pid_gen_fd,
            latency_fd,
            use_batch: true,
            bk: vec![BpfPidKey::default(); MAX_PIDS],
            bv: vec![BpfPidStats::default(); MAX_PIDS],
        })
    }

    fn read_stats(&mut self, out: &mut PidStats) {
        out.clear();
        if self.use_batch {
            if self.read_batch(out) {
                out.sort();
                if out.len() >= MAX_PIDS && !MAP_CAP_WARNED.swap(true, Ordering::Relaxed) {
                    eprintln!(
                        "rstat: stats map reached MAX_PIDS ({MAX_PIDS}); results may be truncated"
                    );
                }
                return;
            }
            self.use_batch = false;
            eprintln!("rstat: batch lookup unsupported, using iterative");
        }
        self.read_iter(out);
        out.sort();
        if out.len() >= MAX_PIDS && !MAP_CAP_WARNED.swap(true, Ordering::Relaxed) {
            eprintln!("rstat: stats map reached MAX_PIDS ({MAX_PIDS}); results may be truncated");
        }
    }

    fn read_batch(&mut self, out: &mut PidStats) -> bool {
        // Hash-map batch cursors are opaque keys. The kernel copies key_size
        // bytes through these pointers, so this must match the 16-byte map key.
        let mut token = BpfPidKey::default();
        let mut total = 0usize;
        let mut first = true;
        loop {
            let rem = MAX_PIDS - total;
            if rem == 0 {
                break;
            }
            let mut attr = BpfAttrBatch {
                in_batch: if first { 0 } else { &token as *const _ as u64 },
                out_batch: &mut token as *mut _ as u64,
                keys: unsafe { self.bk.as_mut_ptr().add(total) } as u64,
                values: unsafe { self.bv.as_mut_ptr().add(total) } as u64,
                count: rem as u32,
                map_fd: self.stats_fd as u32,
                elem_flags: 0,
                flags: 0,
            };
            let r = unsafe {
                bpf_sys(
                    BPF_MAP_LOOKUP_BATCH,
                    &mut attr as *mut _ as *const u8,
                    std::mem::size_of::<BpfAttrBatch>() as u32,
                )
            };
            total += attr.count as usize;
            if r < 0 {
                let e = io::Error::last_os_error();
                if e.raw_os_error() == Some(libc::ENOENT) {
                    break;
                }
                if total == 0 {
                    return false;
                }
                break;
            }
            first = false;
        }
        for i in 0..total {
            out.push(self.bk[i], self.bv[i]);
        }
        true
    }

    // sched_process_free leaves final counters in the map with state X. Delete
    // them only after the userspace sample has consumed those counters.
    fn reap_freed(&self, stats: &PidStats) {
        for &(key, ref st) in &stats.entries {
            if st.state == b'X' {
                bpf_map_delete(self.stats_fd, bytes_of(&key));
            }
        }
    }

    fn read_iter(&self, out: &mut PidStats) {
        let mut key = BpfPidKey::default();
        let mut pk: Option<BpfPidKey> = None;
        let mut val = BpfPidStats::default();
        while bpf_map_get_next_key(
            self.stats_fd,
            pk.as_ref().map(bytes_of),
            bytes_of_mut(&mut key),
        ) {
            if bpf_map_lookup(self.stats_fd, bytes_of(&key), bytes_of_mut(&mut val)) {
                out.push(key, val);
            }
            pk = Some(key);
        }
    }
}

impl Drop for BpfLoader {
    fn drop(&mut self) {
        for f in &self.perf_fds {
            unsafe {
                libc::close(*f);
            }
        }
        for f in &self.prog_fds {
            unsafe {
                libc::close(*f);
            }
        }
        for m in &self.maps {
            unsafe {
                libc::close(m.fd);
            }
        }
    }
}

// --- Sampling ---

struct Sample {
    cpu_pct: f64,
    mem_total: u64,
    mem_available: u64,
    load: [f64; 3],
    cores: u32,
    gpu_rc6_ms: Option<u64>,
    gpu_freq: Option<u64>,
    gpu_max: Option<u64>,
    cpu_temp: Option<u64>,
    cpu_freq: Option<u64>,
    cpu_fmax: Option<u64>,
    throttle: ([u8; 64], usize),
    profile: [u8; 32],
    profile_len: u8,
    include_kthreads: bool,
    io_total_dr: u64,
    io_total_dw: u64,
    psi_mem_some_total_us: Option<u64>,
    psi_mem_full_total_us: Option<u64>,
    pswpin_pages: Option<u64>,
    pswpout_pages: Option<u64>,
    top_cpu: Top5,
    top_mem: Top5,
    top_io: IoTop5,
    blocked: StateList,
    ts: Instant,
}

fn sample_throttle(files: &mut [ThrottleFile], buf: &mut [u8]) -> ([u8; 64], usize) {
    let mut out = [0u8; 64];
    let mut pos = 0;
    for tf in files.iter_mut() {
        let n = pread_raw(&tf.file, buf);
        if n > 0 && buf[0] == b'1' {
            if pos > 0 && pos + 2 < 64 {
                out[pos] = b',';
                out[pos + 1] = b' ';
                pos += 2;
            }
            let l = (tf.nl as usize).min(64 - pos);
            out[pos..pos + l].copy_from_slice(&tf.name[..l]);
            pos += l;
        }
    }
    (out, pos)
}

#[derive(Clone, Copy)]
struct ProcAgg {
    cpu_ns: u64,
    rss_bytes: u64,
    rss_snapshot_ns: u64,
    io_dr: u64,
    io_dw: u64,
    has_d: bool,
    has_z: bool,
    comm: [u8; COMM_LEN],
    cl: u8,
    comm_is_leader: bool,
}

impl ProcAgg {
    fn new() -> Self {
        Self {
            cpu_ns: 0,
            rss_bytes: 0,
            rss_snapshot_ns: 0,
            io_dr: 0,
            io_dw: 0,
            has_d: false,
            has_z: false,
            comm: [0; COMM_LEN],
            cl: 0,
            comm_is_leader: false,
        }
    }

    fn set_comm(&mut self, comm: &[u8], is_leader: bool) {
        if self.cl != 0 && (!is_leader || self.comm_is_leader) {
            return;
        }
        let l = comm.len().min(COMM_LEN);
        if l == 0 {
            return;
        }
        self.comm[..l].copy_from_slice(&comm[..l]);
        self.cl = l as u8;
        self.comm_is_leader = is_leader;
    }

    fn update_rss(&mut self, rss_bytes: u64, snapshot_ns: u64) {
        if snapshot_ns >= self.rss_snapshot_ns {
            self.rss_bytes = rss_bytes;
            self.rss_snapshot_ns = snapshot_ns;
        }
    }
}

fn io_delta(current: &BpfPidStats, previous: Option<&BpfPidStats>) -> (u64, u64) {
    match previous {
        Some(previous) if current.io_baseline != 0 && previous.snapshot_ns == 0 => (0, 0),
        Some(previous) => (
            current.io_rb.saturating_sub(previous.io_rb),
            current.io_wb.saturating_sub(previous.io_wb),
        ),
        None if current.io_baseline != 0 => (0, 0),
        None => (current.io_rb, current.io_wb),
    }
}

struct SampleScratch {
    user_procs: HashMap<u32, ProcAgg>,
    kernel_tasks: HashMap<[u8; COMM_LEN], ProcAgg>,
}

impl SampleScratch {
    fn new() -> Self {
        Self {
            user_procs: HashMap::with_capacity(MAX_PIDS),
            kernel_tasks: HashMap::with_capacity(MAX_PIDS),
        }
    }

    fn clear(&mut self) {
        self.user_procs.clear();
        self.kernel_tasks.clear();
    }
}

struct Sampler {
    buf: [u8; 64],
    mem_buf: [u8; 4096],
    psi_buf: [u8; 256],
    vm_buf: [u8; 8192],
    fds: SysFds,
    cores: u32,
    page_size: u64,
    scratch: SampleScratch,
}

impl Sampler {
    fn new(cores: u32, page_size: u64) -> Self {
        Self {
            buf: [0; 64],
            mem_buf: [0; 4096],
            psi_buf: [0; 256],
            vm_buf: [0; 8192],
            fds: SysFds::open(),
            cores,
            page_size,
            scratch: SampleScratch::new(),
        }
    }

    fn take_sample(
        &mut self,
        elapsed_s: f64,
        cur: &PidStats,
        prev: &PidStats,
        sample_ts: Instant,
    ) -> Sample {
        let Self {
            buf,
            mem_buf,
            psi_buf,
            vm_buf,
            fds,
            cores,
            page_size,
            scratch,
        } = self;
        let cores = *cores;
        let page_size = *page_size;

        let si = get_sysinfo();
        let mu = si.mem_unit.max(1) as u64;
        let fallback_total = si.totalram.saturating_mul(mu);
        let fallback_available = (si.freeram + si.bufferram).saturating_mul(mu);
        let (mem_total, mem_available) = fds
            .meminfo
            .as_ref()
            .map(|file| {
                let n = pread_raw(file, mem_buf);
                parse_meminfo_bytes(&mem_buf[..n])
            })
            .and_then(|(total, available)| total.zip(available))
            .unwrap_or((fallback_total, fallback_available));
        let load = [
            si.loads[0] as f64 / 65536.0,
            si.loads[1] as f64 / 65536.0,
            si.loads[2] as f64 / 65536.0,
        ];

        let rc6 = pread_u64_opt(fds.rc6.as_ref(), buf);
        let gf = pread_u64_opt(fds.gpu_freq.as_ref(), buf);
        let gm = pread_u64_opt(fds.gpu_max.as_ref(), buf);
        let ct = pread_u64_opt(fds.temp.as_ref(), buf);
        let cf = pread_u64_opt(fds.freq.as_ref(), buf);
        let cfm = pread_u64_opt(fds.fmax.as_ref(), buf);
        let thr = sample_throttle(&mut fds.throttle, buf);

        let (psi_mem_some_total_us, psi_mem_full_total_us) = if let Some(f) = &fds.psi_mem {
            let n = pread_raw(f, psi_buf);
            parse_psi_memory_totals(&psi_buf[..n])
        } else {
            (None, None)
        };

        let (pswpin_pages, pswpout_pages) = if let Some(f) = &fds.vmstat {
            let n = pread_raw(f, vm_buf);
            parse_vmstat_swap_pages(&vm_buf[..n])
        } else {
            (None, None)
        };

        let mut profile = [0u8; 32];
        let mut pl = fds.profile.as_ref().map(|f| pread_raw(f, buf)).unwrap_or(0);
        while pl > 0 && (buf[pl - 1] == b'\n' || buf[pl - 1] == b' ') {
            pl -= 1;
        }
        let pl = pl.min(32);
        profile[..pl].copy_from_slice(&buf[..pl]);

        let total_ns = (elapsed_s * 1_000_000_000.0 * cores as f64) as u64;
        let include_kthreads = INCLUDE_KTHREADS.load(Ordering::Relaxed);
        let mut top_cpu = Top5::new();
        let mut top_mem = Top5::new();
        let mut top_io = IoTop5::new();
        let mut blocked = StateList::new();
        scratch.clear();
        let min_io = if elapsed_s > 0.0 {
            (MIN_IO_BYTES as f64 * elapsed_s) as u64
        } else {
            u64::MAX
        };
        let mut busy_process_ns = 0u64;
        let mut busy_kthread_ns = 0u64;
        let mut io_total_dr = 0u64;
        let mut io_total_dw = 0u64;

        for &(pid_key, ref st) in &cur.entries {
            let pid = pid_key.pid;
            if pid == 0 {
                continue;
            }
            let cl = st.comm.iter().position(|&b| b == 0).unwrap_or(16);
            if cl == 0 {
                continue;
            }
            let prev_st = prev.get(pid_key);
            let prev_cpu = prev_st.map(|p| p.cpu_ns).unwrap_or(0);
            let dcpu = st.cpu_ns.saturating_sub(prev_cpu);
            let (drb, dwb) = io_delta(st, prev_st);

            if st.is_kthread != 0 {
                busy_kthread_ns = busy_kthread_ns.saturating_add(dcpu);
                let mut key = [0u8; COMM_LEN];
                key[..cl].copy_from_slice(&st.comm[..cl]);
                let e = scratch.kernel_tasks.entry(key).or_insert_with(ProcAgg::new);
                e.cpu_ns = e.cpu_ns.saturating_add(dcpu);
                e.update_rss(st.rss_pages.saturating_mul(page_size), st.snapshot_ns);
                e.io_dr = e.io_dr.saturating_add(drb);
                e.io_dw = e.io_dw.saturating_add(dwb);
                e.has_d |= st.state == b'D';
                e.has_z |= st.state == b'Z';
                e.set_comm(&st.comm[..cl], false);
                continue;
            }

            busy_process_ns = busy_process_ns.saturating_add(dcpu);
            let tgid = if st.tgid != 0 { st.tgid } else { pid };
            let e = scratch.user_procs.entry(tgid).or_insert_with(ProcAgg::new);
            e.cpu_ns = e.cpu_ns.saturating_add(dcpu);
            e.update_rss(st.rss_pages.saturating_mul(page_size), st.snapshot_ns);
            e.io_dr = e.io_dr.saturating_add(drb);
            e.io_dw = e.io_dw.saturating_add(dwb);
            e.has_d |= st.state == b'D';
            e.has_z |= st.state == b'Z';
            e.set_comm(&st.comm[..cl], pid == tgid);
        }

        for e in scratch.user_procs.values() {
            if e.cl == 0 {
                continue;
            }

            io_total_dr = io_total_dr.saturating_add(e.io_dr);
            io_total_dw = io_total_dw.saturating_add(e.io_dw);

            if e.has_d {
                blocked.push(b'D', &e.comm[..e.cl as usize]);
            } else if e.has_z {
                blocked.push(b'Z', &e.comm[..e.cl as usize]);
            }

            if total_ns > 0 && e.cpu_ns > 0 {
                let thr_ns = (MIN_CPU_PCT * total_ns as f64 / 100.0) as u64;
                if e.cpu_ns >= thr_ns {
                    top_cpu.insert(e.cpu_ns, &e.comm[..e.cl as usize]);
                }
            }

            if e.rss_bytes >= MIN_MEM_BYTES {
                top_mem.insert(e.rss_bytes, &e.comm[..e.cl as usize]);
            }

            let dt = e.io_dr.saturating_add(e.io_dw);
            if dt >= min_io {
                top_io.insert(dt, e.io_dr, e.io_dw, &e.comm[..e.cl as usize]);
            }
        }

        if include_kthreads {
            for e in scratch.kernel_tasks.values() {
                if e.cl == 0 {
                    continue;
                }

                io_total_dr = io_total_dr.saturating_add(e.io_dr);
                io_total_dw = io_total_dw.saturating_add(e.io_dw);

                if e.has_d {
                    blocked.push(b'D', &e.comm[..e.cl as usize]);
                } else if e.has_z {
                    blocked.push(b'Z', &e.comm[..e.cl as usize]);
                }

                if total_ns > 0 && e.cpu_ns > 0 {
                    let thr_ns = (MIN_CPU_PCT * total_ns as f64 / 100.0) as u64;
                    if e.cpu_ns >= thr_ns {
                        top_cpu.insert(e.cpu_ns, &e.comm[..e.cl as usize]);
                    }
                }

                if e.rss_bytes >= MIN_MEM_BYTES {
                    top_mem.insert(e.rss_bytes, &e.comm[..e.cl as usize]);
                }

                let dt = e.io_dr.saturating_add(e.io_dw);
                if dt >= min_io {
                    top_io.insert(dt, e.io_dr, e.io_dw, &e.comm[..e.cl as usize]);
                }
            }
        }

        let busy_ns = if include_kthreads {
            busy_process_ns.saturating_add(busy_kthread_ns)
        } else {
            busy_process_ns
        };

        let cpu_pct = if total_ns > 0 && elapsed_s > 0.0 {
            (busy_ns as f64 / total_ns as f64 * 100.0).clamp(0.0, 100.0)
        } else {
            0.0
        };

        Sample {
            cpu_pct,
            mem_total,
            mem_available,
            load,
            cores,
            gpu_rc6_ms: rc6,
            gpu_freq: gf,
            gpu_max: gm,
            cpu_temp: ct,
            cpu_freq: cf,
            cpu_fmax: cfm,
            throttle: thr,
            profile,
            profile_len: pl as u8,
            include_kthreads,
            io_total_dr,
            io_total_dw,
            psi_mem_some_total_us,
            psi_mem_full_total_us,
            pswpin_pages,
            pswpout_pages,
            top_cpu,
            top_mem,
            top_io,
            blocked,
            ts: sample_ts,
        }
    }
}

// --- JSON output (hand-written, no serde) ---

fn json_str(out: &mut String, s: &str) {
    out.push('"');
    for b in s.bytes() {
        match b {
            b'"' => out.push_str("\\\""),
            b'\\' => out.push_str("\\\\"),
            b'\n' => out.push_str("\\n"),
            c if c < 0x20 => {}
            c => unsafe { out.as_mut_vec().push(c) },
        }
    }
    out.push('"');
}

fn render(
    prev: Option<&Sample>,
    cur: &mut Sample,
    dur: Duration,
    tt: &mut String,
    json: &mut String,
    text_buf: &mut String,
) {
    let elapsed_s = prev
        .map(|p| cur.ts.duration_since(p.ts).as_secs_f64())
        .unwrap_or(0.0);

    let mt = cur.mem_total;
    let mused = mt.saturating_sub(cur.mem_available);
    let mpct = (100 * mused).checked_div(mt).unwrap_or(0);
    let mused_g = mused as f64 / 1_073_741_824.0;
    let mtotal_g = mt as f64 / 1_073_741_824.0;

    let mut psi_some_pct = None;
    let mut psi_full_pct = None;
    let mut swap_in_ps = None;
    let mut swap_out_ps = None;
    if let Some(p) = prev
        && elapsed_s > 0.0
    {
        if let (Some(cur_some), Some(prev_some)) =
            (cur.psi_mem_some_total_us, p.psi_mem_some_total_us)
        {
            psi_some_pct = Some(
                (cur_some.saturating_sub(prev_some) as f64 / (elapsed_s * 1_000_000.0) * 100.0)
                    .clamp(0.0, 100.0),
            );
        }
        if let (Some(cur_full), Some(prev_full)) =
            (cur.psi_mem_full_total_us, p.psi_mem_full_total_us)
        {
            psi_full_pct = Some(
                (cur_full.saturating_sub(prev_full) as f64 / (elapsed_s * 1_000_000.0) * 100.0)
                    .clamp(0.0, 100.0),
            );
        }
        if let (Some(cur_in), Some(prev_in)) = (cur.pswpin_pages, p.pswpin_pages) {
            swap_in_ps = Some(cur_in.saturating_sub(prev_in) as f64 / elapsed_s);
        }
        if let (Some(cur_out), Some(prev_out)) = (cur.pswpout_pages, p.pswpout_pages) {
            swap_out_ps = Some(cur_out.saturating_sub(prev_out) as f64 / elapsed_s);
        }
    }

    let ratio = cur.load[0] / cur.cores.max(1) as f64;
    let class = if ratio >= 2.0 {
        "critical"
    } else if ratio >= 1.0 {
        "warning"
    } else {
        "normal"
    };

    // Build tooltip
    tt.clear();
    let _ = write!(
        tt,
        "Load: {:.2} {:.2} {:.2} ({} cores)",
        cur.load[0], cur.load[1], cur.load[2], cur.cores
    );

    tt.push_str("\niGPU: ");
    if let (Some(freq), Some(max)) = (cur.gpu_freq, cur.gpu_max) {
        if let Some(p) = prev
            && let (Some(cur_rc6), Some(prev_rc6)) = (cur.gpu_rc6_ms, p.gpu_rc6_ms)
        {
            let dt_ms = (elapsed_s * 1000.0) as u64;
            if dt_ms > 0 {
                let d = cur_rc6.saturating_sub(prev_rc6);
                let busy = (100.0 - d as f64 * 100.0 / dt_ms as f64).max(0.0);
                let _ = write!(tt, "{busy:.0}% @ ");
            }
        }
        let _ = write!(tt, "{freq}/{max} MHz");
    } else {
        tt.push_str("n/a");
    }

    tt.push_str("\nProfile: ");
    if cur.profile_len > 0 {
        push_lossy(tt, &cur.profile[..cur.profile_len as usize]);
    } else {
        tt.push_str("n/a");
    }
    if cur.throttle.1 > 0 {
        tt.push_str("\n⚠ Throttled: ");
        push_lossy(tt, &cur.throttle.0[..cur.throttle.1]);
    }

    tt.push_str("\n\n CPU    ");
    if let Some(temp) = cur.cpu_temp {
        let _ = write!(tt, "{}°C    ", temp / 1000);
    } else {
        tt.push_str("n/a    ");
    }
    if prev.is_some() {
        let _ = write!(tt, "{:.0}", cur.cpu_pct);
    } else {
        tt.push('?');
    }
    tt.push_str("%    ");
    if let (Some(freq), Some(max)) = (cur.cpu_freq, cur.cpu_fmax) {
        let _ = write!(
            tt,
            "CPU0 {:.1}/{:.1} GHz",
            freq as f64 / 1_000_000.0,
            max as f64 / 1_000_000.0
        );
    } else {
        tt.push_str("n/a");
    }
    let blk = cur.blocked.sorted();
    for e in blk {
        let _ = write!(tt, "\n    {}  ", e.state as char);
        push_comm(tt, &e.comm, e.cl);
    }
    let entries = cur.top_cpu.sorted();
    if entries.is_empty() && blk.is_empty() {
        tt.push_str("\n  ---");
    }
    let total_ns = elapsed_s * cur.cores as f64 * 1_000_000_000.0;
    for e in entries {
        let pct = if total_ns > 0.0 {
            e.val as f64 * 100.0 / total_ns
        } else {
            0.0
        };
        let _ = write!(tt, "\n{pct:5.1}%  ");
        push_comm(tt, &e.comm, e.cl);
    }

    let _ = write!(
        tt,
        "\n\n Memory    {mused_g:.1}/{mtotal_g:.1} GiB ({mpct}%)"
    );
    match (psi_some_pct, psi_full_pct) {
        (Some(some), Some(full)) => {
            let _ = write!(tt, "\n PSI some/full: {some:.1}%/{full:.1}%");
        }
        _ => tt.push_str("\n PSI some/full: n/a"),
    }
    match (swap_in_ps, swap_out_ps) {
        (Some(sin), Some(sout)) => {
            let _ = write!(
                tt,
                "\n Swap: {:.0} pages/s (in:{sin:.0} out:{sout:.0})",
                sin + sout
            );
        }
        _ => tt.push_str("\n Swap: n/a"),
    }
    let entries = cur.top_mem.sorted();
    if entries.is_empty() {
        tt.push_str("\n  ---");
    } else {
        for e in entries {
            let mb = e.val as f64 / 1_048_576.0;
            let _ = write!(tt, "\n{mb:5.0}M  ");
            push_comm(tt, &e.comm, e.cl);
        }
    }

    tt.push_str("\n\n Task IO/s");
    if elapsed_s > 0.0 {
        let tr = cur.io_total_dr as f64 / 1_048_576.0 / elapsed_s;
        let tw = cur.io_total_dw as f64 / 1_048_576.0 / elapsed_s;
        let ttot = tr + tw;
        let _ = write!(tt, " {ttot:.1}M/s (R:{tr:.1} W:{tw:.1})");
    }
    let entries = cur.top_io.sorted();
    if entries.is_empty() {
        tt.push_str("\n  ---");
    } else {
        for e in entries {
            let t = e.total as f64 / 1_048_576.0 / elapsed_s;
            let r = e.dr as f64 / 1_048_576.0 / elapsed_s;
            let w = e.dw as f64 / 1_048_576.0 / elapsed_s;
            let _ = write!(tt, "\n{t:5.1}M/s  ");
            push_comm(tt, &e.comm, e.cl);
            let _ = write!(tt, " (R:{r:.1} W:{w:.1})");
        }
    }

    let ival = INTERVAL_MS.load(Ordering::Relaxed);
    let _ = write!(
        tt,
        "\n\nCollected in {:.1}ms (every {ival}ms)",
        dur.as_secs_f64() * 1000.0
    );
    let _ = write!(
        tt,
        "\nKernel threads {}",
        if cur.include_kthreads {
            "included"
        } else {
            "excluded"
        }
    );

    // Build JSON directly
    json.clear();
    json.push_str("{\"text\":");
    text_buf.clear();
    let _ = write!(text_buf, "{:.2}", cur.load[0]);
    json_str(json, text_buf);
    json.push_str(",\"tooltip\":");
    json_str(json, tt);
    json.push_str(",\"class\":");
    json_str(json, class);
    json.push('}');
}

fn write_json(json: &str) {
    let stdout = io::stdout();
    let mut lock = stdout.lock();
    let _ = lock.write_all(json.as_bytes());
    let _ = lock.write_all(b"\n");
    let _ = lock.flush();
}

// --- Click-to-cycle interval control ---

extern "C" fn sig_cycle(_: libc::c_int) {
    let cur = INTERVAL_MS.load(Ordering::Relaxed);
    let next = INTERVALS
        .iter()
        .skip_while(|&&v| v != cur)
        .nth(1)
        .copied()
        .unwrap_or(INTERVALS[0]);
    INTERVAL_MS.store(next, Ordering::Relaxed);
}

extern "C" fn sig_kthreads(_: libc::c_int) {
    INCLUDE_KTHREADS.fetch_xor(true, Ordering::Relaxed);
}

fn sleep_or_signal(ms: u64) {
    let ts = libc::timespec {
        tv_sec: (ms / 1000) as libc::time_t,
        tv_nsec: ((ms % 1000) * 1_000_000) as libc::c_long,
    };
    unsafe { libc::nanosleep(&ts, std::ptr::null_mut()) };
}

fn print_histogram(fd: RawFd, secs: f64) {
    let mut bk = [0u64; 32];
    for i in 0..32u32 {
        let kb = i.to_ne_bytes();
        let mut vb = [0u8; 8];
        if bpf_map_lookup(fd, &kb, &mut vb) {
            bk[i as usize] = u64::from_ne_bytes(vb);
        }
    }
    let first = bk.iter().position(|&v| v > 0).unwrap_or(0);
    let last = bk.iter().rposition(|&v| v > 0).unwrap_or(0);
    let mx = *bk.iter().max().unwrap_or(&1).max(&1);
    let total: u64 = bk.iter().sum();
    let mut sum_ns = 0u64;
    for (i, &c) in bk.iter().enumerate() {
        // midpoint of [2^i, 2^(i+1)) ≈ 1.5 * 2^i
        sum_ns += ((3u64 << i) >> 1) * c;
    }
    let avg = sum_ns.checked_div(total).unwrap_or(0);
    let per_sec = total as f64 / secs;
    let body_pct = avg as f64 * per_sec / 1e9 * 100.0;
    eprintln!(
        "\nrstat instrumented sched_switch body ({total} calls, {per_sec:.0}/s over {secs:.1}s):\n"
    );
    eprintln!("    {:>13}    {:>8}  distribution", "ns", "count");
    for (i, &count) in bk.iter().enumerate().take(last + 1).skip(first) {
        let lo = 1u64 << i;
        let hi = (1u64 << (i + 1)) - 1;
        let w = (count * 40 / mx) as usize;
        let bar = "*".repeat(w);
        eprintln!("    {lo:>5}-{hi:<8} {count:>8}  |{bar:<40}|");
    }
    eprintln!(
        "\n  estimated body midpoint: ~{avg}ns  measured body time: {body_pct:.4}% of one core ({:.3}ms/s)\n  excludes the profiling histogram update and isn't a production-overhead measurement",
        avg as f64 * per_sec / 1e6
    );
}

/// Seed one task that was already blocked or zombified when the probes attached.
fn seed_dz_task(stats_fd: RawFd, pid_gen_fd: RawFd, tgid: u32, tid: u32, buf: &mut [u8]) -> bool {
    let path = format!("/proc/{tgid}/task/{tid}/stat");
    let Some(len) = read_raw(&path, buf) else {
        return false;
    };
    let stat = &buf[..len];
    let Some(comm_start) = stat
        .iter()
        .position(|&byte| byte == b'(')
        .map(|pos| pos + 1)
    else {
        return false;
    };
    let Some(comm_end) = stat.iter().rposition(|&byte| byte == b')') else {
        return false;
    };
    let mut fields = stat[comm_end + 1..]
        .split(|&byte| byte == b' ')
        .filter(|field| !field.is_empty());
    let state = match fields.next() {
        Some([state @ (b'D' | b'Z')]) if *state != b'Z' || tid == tgid => *state,
        _ => return false,
    };

    // Starting after field 3 (state), advance through fields 4..21.
    if fields.by_ref().take(18).count() != 18 {
        return false;
    }
    let Some(generation) = fields.next().map(parse_u64_trim).map(|value| value.max(1)) else {
        return false;
    };
    let Some(is_kthread) = fields.next().map(|vsize| parse_u64_trim(vsize) == 0) else {
        return false;
    };

    let mut stats = BpfPidStats {
        tgid,
        state,
        is_kthread: u8::from(is_kthread),
        io_baseline: 1,
        ..BpfPidStats::default()
    };
    let comm = &stat[comm_start..comm_end];
    let comm_len = comm.len().min(COMM_LEN);
    stats.comm[..comm_len].copy_from_slice(&comm[..comm_len]);

    let tid_bytes = tid.to_ne_bytes();
    let generation_bytes = generation.to_ne_bytes();
    let generation = if bpf_map_update(pid_gen_fd, &tid_bytes, &generation_bytes, 1) {
        generation
    } else {
        let mut existing = [0u8; 8];
        if !bpf_map_lookup(pid_gen_fd, &tid_bytes, &mut existing) {
            return false;
        }
        u64::from_ne_bytes(existing)
    };
    let key = BpfPidKey {
        pid: tid,
        _pad: 0,
        generation,
    };
    // BPF_NOEXIST: don't overwrite a task the live probe already observed.
    bpf_map_update(stats_fd, bytes_of(&key), bytes_of(&stats), 1)
}

/// The probes only see state transitions after attachment. This one-time scan
/// covers every existing thread so D-state workers aren't missed.
fn seed_existing_dz(stats_fd: RawFd, pid_gen_fd: RawFd) -> usize {
    let Ok(processes) = fs::read_dir("/proc") else {
        return 0;
    };
    let mut count = 0;
    let mut buf = [0u8; 512];
    for process in processes.flatten() {
        let tgid = parse_u64_trim(process.file_name().as_encoded_bytes()) as u32;
        if tgid == 0 {
            continue;
        }
        let Ok(tasks) = fs::read_dir(process.path().join("task")) else {
            continue;
        };
        for task in tasks.flatten() {
            let tid = parse_u64_trim(task.file_name().as_encoded_bytes()) as u32;
            if tid != 0 && seed_dz_task(stats_fd, pid_gen_fd, tgid, tid, &mut buf) {
                count += 1;
            }
        }
    }
    count
}

struct InstanceLock {
    _file: fs::File,
}

fn acquire_instance_lock() -> Option<InstanceLock> {
    let uid = unsafe { libc::geteuid() };
    let mut dir = std::env::var("XDG_RUNTIME_DIR").ok().filter(|path| {
        fs::metadata(path)
            .map(|metadata| metadata.is_dir() && metadata.uid() == uid)
            .unwrap_or(false)
    });
    if dir.is_none() {
        let run_user = format!("/run/user/{uid}");
        dir = if fs::metadata(&run_user)
            .map(|metadata| metadata.is_dir() && metadata.uid() == uid)
            .unwrap_or(false)
        {
            Some(run_user)
        } else if uid == 0 {
            Some("/run".to_string())
        } else {
            Some("/tmp".to_string())
        };
    }
    let dir = dir.unwrap_or_else(|| "/tmp".to_string());
    let name = if dir == "/tmp" {
        format!("rstat-{uid}.lock")
    } else {
        "rstat.lock".to_string()
    };
    let p = format!("{dir}/{name}");
    let f = match fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&p)
    {
        Ok(v) => v,
        Err(e) => {
            eprintln!("rstat: failed to open lockfile {p}: {e}");
            return None;
        }
    };
    if f.metadata().map(|metadata| metadata.uid()).ok() != Some(uid) {
        eprintln!("rstat: refusing lockfile not owned by uid {uid}: {p}");
        return None;
    }
    let r = unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if r != 0 {
        let e = io::Error::last_os_error();
        let oe = e.raw_os_error();
        if oe == Some(libc::EWOULDBLOCK) || oe == Some(libc::EAGAIN) {
            eprintln!("rstat: another instance is already running");
        } else {
            eprintln!("rstat: failed to acquire lock {p}: {e}");
        }
        return None;
    }
    Some(InstanceLock { _file: f })
}

fn positive_arg(args: &[String], flag: &str, default: u64) -> Result<Option<u64>, String> {
    let Some(index) = args.iter().position(|arg| arg == flag) else {
        return Ok(None);
    };
    let value = match args.get(index + 1) {
        Some(value) if !value.starts_with("--") => value
            .parse::<u64>()
            .map_err(|_| format!("rstat: {flag} requires a positive integer"))?,
        _ => default,
    };
    if value == 0 {
        Err(format!("rstat: {flag} requires a positive integer"))
    } else {
        Ok(Some(value))
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let profile_secs = positive_arg(&args, "--profile", 5).unwrap_or_else(|error| {
        eprintln!("{error}");
        std::process::exit(2);
    });
    let bench_n = positive_arg(&args, "--bench", 100).unwrap_or_else(|error| {
        eprintln!("{error}");
        std::process::exit(2);
    });
    if profile_secs.is_some() && bench_n.is_some() {
        eprintln!("rstat: --profile and --bench can't be used together");
        std::process::exit(2);
    }

    let online_cpus = online_cpus().unwrap_or_else(|| {
        eprintln!("rstat: couldn't determine the online CPU set");
        std::process::exit(1);
    });
    let cores = online_cpus.len() as u32;
    let raw_page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if raw_page_size <= 0 {
        eprintln!("rstat: couldn't determine the system page size");
        std::process::exit(1);
    }
    let page_size = raw_page_size as u64;
    let mut sampler = Sampler::new(cores, page_size);

    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_flags = libc::SA_RESTART;
        sa.sa_sigaction = sig_cycle as *const () as usize;
        libc::sigaction(libc::SIGRTMIN(), &sa, std::ptr::null_mut());
        sa.sa_sigaction = sig_kthreads as *const () as usize;
        libc::sigaction(libc::SIGRTMIN() + 1, &sa, std::ptr::null_mut());
    }

    let _lock = acquire_instance_lock().unwrap_or_else(|| {
        std::process::exit(1);
    });

    let mut bpf = {
        let probe_obj = build_runtime_probe(profile_secs.is_some()).unwrap_or_else(|| {
            std::process::exit(1);
        });
        let bpf = BpfLoader::load(&probe_obj, &online_cpus).unwrap_or_else(|| {
            eprintln!("rstat: failed to load runtime eBPF probe");
            std::process::exit(1);
        });
        eprintln!("rstat: eBPF active (runtime-compiled live-BTF probe loaded from memory)");
        bpf
    };

    if let Some(profile_secs) = profile_secs {
        eprintln!("rstat: profiling BPF probe for {profile_secs}s...");
        thread::sleep(Duration::from_secs(profile_secs));
        print_histogram(bpf.latency_fd, profile_secs as f64);
        return;
    }

    let seeded = seed_existing_dz(bpf.stats_fd, bpf.pid_gen_fd);
    if seeded > 0 {
        eprintln!("rstat: seeded {seeded} pre-existing D/Z processes from /proc");
    }

    if args.iter().any(|a| a == "--ludicrous") {
        INTERVAL_MS.store(16, Ordering::Relaxed);
    }

    // Pre-allocated, reused every tick.
    let mut cur = PidStats::with_capacity(MAX_PIDS);
    let mut prev = PidStats::with_capacity(MAX_PIDS);
    let mut tt = String::with_capacity(1024);
    let mut json = String::with_capacity(1536);
    let mut text_buf = String::with_capacity(16);

    if let Some(bench_n) = bench_n {
        let bench_n = usize::try_from(bench_n).unwrap_or_else(|_| {
            eprintln!("rstat: --bench value is too large for this platform");
            std::process::exit(2);
        });
        let first_ts = Instant::now();
        bpf.read_stats(&mut prev);
        let mut prev_sample = sampler.take_sample(0.0, &prev, &cur, first_ts);
        bpf.reap_freed(&prev);
        thread::sleep(Duration::from_millis(10));

        let mut times = Vec::with_capacity(bench_n);
        for _ in 0..bench_n {
            thread::sleep(Duration::from_millis(1));
            let t0 = Instant::now();
            let es = t0.duration_since(prev_sample.ts).as_secs_f64();
            bpf.read_stats(&mut cur);
            let mut sample = sampler.take_sample(es, &cur, &prev, t0);
            let collection_duration = t0.elapsed();
            render(
                Some(&prev_sample),
                &mut sample,
                collection_duration,
                &mut tt,
                &mut json,
                &mut text_buf,
            );
            bpf.reap_freed(&cur);
            times.push(t0.elapsed());
            prev_sample = sample;
            std::mem::swap(&mut cur, &mut prev);
        }
        times.sort_unstable();
        let sum: Duration = times.iter().sum();
        let p50 = times[times.len() / 2];
        let p95 = times[times.len() * 95 / 100];
        let p99 = times[times.len() * 99 / 100];
        eprintln!(
            "refresh pipeline (map read through JSON construction; stdout excluded)\nn={bench_n}  avg={:.2}ms  p50={:.2}ms  p95={:.2}ms  p99={:.2}ms  min={:.2}ms  max={:.2}ms",
            sum.as_secs_f64() * 1000.0 / times.len() as f64,
            p50.as_secs_f64() * 1000.0,
            p95.as_secs_f64() * 1000.0,
            p99.as_secs_f64() * 1000.0,
            times[0].as_secs_f64() * 1000.0,
            times.last().unwrap().as_secs_f64() * 1000.0
        );
        return;
    }

    // First sample (no deltas)
    let first_ts = Instant::now();
    bpf.read_stats(&mut prev);
    let mut s = sampler.take_sample(0.0, &prev, &cur, first_ts);
    let first_duration = first_ts.elapsed();
    render(
        None,
        &mut s,
        first_duration,
        &mut tt,
        &mut json,
        &mut text_buf,
    );
    bpf.reap_freed(&prev);
    write_json(&json);
    let mut prev_sample = s;

    loop {
        sleep_or_signal(INTERVAL_MS.load(Ordering::Relaxed));
        let t0 = Instant::now();
        let es = t0.duration_since(prev_sample.ts).as_secs_f64();
        bpf.read_stats(&mut cur);
        let mut s = sampler.take_sample(es, &cur, &prev, t0);
        let dur = t0.elapsed();
        render(
            Some(&prev_sample),
            &mut s,
            dur,
            &mut tt,
            &mut json,
            &mut text_buf,
        );
        bpf.reap_freed(&cur);
        write_json(&json);
        prev_sample = s;
        std::mem::swap(&mut cur, &mut prev);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_sparse_online_cpu_lists() {
        assert_eq!(parse_cpu_list("0-2,4,8-9\n"), Some(vec![0, 1, 2, 4, 8, 9]));
        assert_eq!(parse_cpu_list("3,1-2,2"), Some(vec![1, 2, 3]));
        assert_eq!(parse_cpu_list("4-2"), None);
        assert_eq!(parse_cpu_list(""), None);
    }

    #[test]
    fn parses_memavailable_in_bytes() {
        let meminfo =
            b"MemTotal:       32768 kB\nMemFree:         1024 kB\nMemAvailable:   24576 kB\n";
        assert_eq!(
            parse_meminfo_bytes(meminfo),
            (Some(32 * 1024 * 1024), Some(24 * 1024 * 1024))
        );
    }

    #[test]
    fn newest_thread_snapshot_wins_for_process_rss() {
        let mut aggregate = ProcAgg::new();
        aggregate.update_rss(900, 20);
        aggregate.update_rss(1_200, 10);
        assert_eq!(aggregate.rss_bytes, 900);
        aggregate.update_rss(700, 30);
        assert_eq!(aggregate.rss_bytes, 700);
    }

    #[test]
    fn historical_io_is_a_baseline_but_new_task_io_counts() {
        let historical = BpfPidStats {
            io_rb: 8_000,
            io_wb: 4_000,
            snapshot_ns: 10,
            io_baseline: 1,
            ..BpfPidStats::default()
        };
        assert_eq!(io_delta(&historical, None), (0, 0));

        let new_task = BpfPidStats {
            io_rb: 800,
            io_wb: 400,
            ..BpfPidStats::default()
        };
        assert_eq!(io_delta(&new_task, None), (800, 400));

        let later = BpfPidStats {
            io_rb: 8_500,
            io_wb: 4_250,
            snapshot_ns: 20,
            io_baseline: 1,
            ..BpfPidStats::default()
        };
        assert_eq!(io_delta(&later, Some(&historical)), (500, 250));

        let seeded_before_its_first_switch = BpfPidStats {
            io_baseline: 1,
            ..BpfPidStats::default()
        };
        assert_eq!(
            io_delta(&historical, Some(&seeded_before_its_first_switch)),
            (0, 0)
        );
    }
}
