{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    crane.url = "github:ipetkov/crane";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };
  outputs =
    {
      nixpkgs,
      crane,
      flake-utils,
      rust-overlay,
      ...
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ (import rust-overlay) ];
        };
        craneLib = (crane.mkLib pkgs).overrideToolchain (p: p.rust-bin.stable.latest.default);

        commonArgs = {
          src = craneLib.cleanCargoSource ./.;
          strictDeps = true;
        };

        crate = craneLib.buildPackage (
          commonArgs
          // {
            cargoArtifacts = craneLib.buildDepsOnly commonArgs;
            nativeBuildInputs = [ pkgs.makeWrapper ];
            propagatedBuildInputs = [ pkgs.arp-scan ];
            postInstall = ''
              wrapProgram $out/bin/lanotify \
                --prefix PATH : ${pkgs.lib.makeBinPath [ pkgs.arp-scan ]}
            '';
          }
        );
      in
      {
        checks = {
          inherit crate;
        };
        packages.default = crate;
        apps.default = flake-utils.lib.mkApp {
          drv = crate;
        };
        devShells.default = craneLib.devShell {
          packages = with pkgs; [
            arp-scan
            cargo-edit
          ];
        };

      }
    );
}
