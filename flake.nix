{
  description = "Waybar syshealth streaming daemon (eBPF)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = {
    self,
    nixpkgs,
  }: let
    systems = ["x86_64-linux" "aarch64-linux"];
    forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f system);
  in {
    packages = forAllSystems (system: let
      pkgs = nixpkgs.legacyPackages.${system};
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
  };
}
