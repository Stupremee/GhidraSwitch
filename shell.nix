{ pkgs ? import <nixpkgs> { } }:
pkgs.mkShell {
  name = "java-shell";
  nativeBuildInputs = with pkgs.unstable; [ jdk ];

  GHIDRA_INSTALL_DIR =
    "/nix/store/19k8zvkk3830lwiwk1l1g3k6wximvx6j-ghidra-9.2/lib/ghidra/";
}
