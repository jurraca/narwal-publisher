{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  nativeBuildInputs = with pkgs; [
    gcc
    pkg-config
    clang
  ];

  buildInputs = with pkgs; [
    dbus
    openssl
    sqlite
    llvmPackages.libclang
  ];

  LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
}
