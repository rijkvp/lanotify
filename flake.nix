{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    crane.url = "github:ipetkov/crane";
    flake-utils.url = "github:numtide/flake-utils";
  };
  outputs =
    {
      nixpkgs,
      crane,
      flake-utils,
      ...
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        craneLib = crane.mkLib pkgs;

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
      }
    );
}
