{
  description = "Waybar syshealth streaming daemon (eBPF)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";

    rust-overlay.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = {
    self,
    nixpkgs,
    rust-overlay,
  }: let
    systems = ["x86_64-linux" "aarch64-linux"];
    forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f system);
    pkgsFor = system:
      import nixpkgs {
        inherit system;
        overlays = [(import rust-overlay)];
      };
  in {
    packages = forAllSystems (system: let
      pkgs = pkgsFor system;
      rstat = pkgs.rustPlatform.buildRustPackage {
        pname = "rstat";
        version = "0.1.0";
        src = ./.;
        cargoHash = "sha256-1O6RRWztQXukeM6WAc2KEbNRRhsAVxqr5MhtcTelFeo=";
        RSTAT_BPFTOOL = "${pkgs.bpftools}/bin/bpftool";
        RSTAT_CLANG = "${pkgs.llvmPackages.clang-unwrapped}/bin/clang";
        RSTAT_LIBBPF_INCLUDE = "${pkgs.libbpf}/include";
      };
    in {
      default = rstat;
      rstat = rstat;
    });

    devShells = forAllSystems (system: let
      pkgs = pkgsFor system;
      rustToolchain = pkgs.rust-bin.stable."1.96.0".default.override {
        extensions = ["clippy" "rust-analyzer" "rust-src" "rustfmt"];
      };
    in {
      default = pkgs.mkShell {
        packages = with pkgs; [
          rustToolchain
          bpftools
          clang
          libbpf
          mold
          pkg-config
        ];
        RSTAT_BPFTOOL = "${pkgs.bpftools}/bin/bpftool";
        RSTAT_CLANG = "${pkgs.llvmPackages.clang-unwrapped}/bin/clang";
        RSTAT_LIBBPF_INCLUDE = "${pkgs.libbpf}/include";
        RUSTFLAGS = "-C link-arg=-fuse-ld=mold";
      };
    });
  };
}
