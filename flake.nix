{
  description = "narwal-cli: publish a Nix binary cache via Blossom + Nostr";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
  };

  outputs = { self, nixpkgs }: let
    supportedSystems = [ "x86_64-linux" "aarch64-linux" ];
    forAllSystems = nixpkgs.lib.genAttrs supportedSystems;
  in {
    packages = forAllSystems (system: let
      pkgs = nixpkgs.legacyPackages.${system};
    in {
      default = pkgs.rustPlatform.buildRustPackage {
        pname = "narwal-cli";
        version = "0.1.0";
        src = ./.;
        cargoLock.lockFile = ./Cargo.lock;

        # xz2/zstd link system liblzma + libzstd.
        nativeBuildInputs = with pkgs; [ pkg-config ];
        buildInputs = with pkgs; [ xz zstd ];

        meta = with pkgs.lib; {
          description = "Publish a Nix binary cache via Blossom + Nostr";
          license = licenses.mit;
          mainProgram = "narwal-cli";
        };
      };
    });
  };
}
