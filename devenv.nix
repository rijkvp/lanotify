{ pkgs, ... }:

{
  languages.rust = {
    enable = true;
    channel = "stable";
  };

  packages = with pkgs; [
    cargo-edit
    arp-scan
  ];
}
