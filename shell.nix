{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  nativeBuildInputs = with pkgs; [
    gcc
    pkg-config
    clang
    rustc
    cargo
  ];

  buildInputs = with pkgs; [
    dbus
    openssl
    sqlite
    llvmPackages.libclang
    xz
  ];

  LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
}
