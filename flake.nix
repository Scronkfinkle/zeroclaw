{
  description = "Quiet Crab Flake";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";
  };

  outputs = { self, nixpkgs }:
  let
    pkgs = import nixpkgs { system = "x86_64-linux"; };

    stdInputs = [
        # Rust
        pkgs.cargo
        pkgs.rustc
        pkgs.pkg-config
        pkgs.glib

        # Vulkan loader so wgpu can dlopen libvulkan.so.1 at runtime
        pkgs.vulkan-loader
    ];
    devInputs = [
        pkgs.rustfmt
        pkgs.clippy
        pkgs.rust-analyzer
    ];
  in
  {
    packages."x86_64-linux" = {
      # Full build with all features (default)
      default = pkgs.rustPlatform.buildRustPackage {
        pname = "zeroclaw";
        version = "0.0.1";
        src = ./.;
        buildType = "release";
        cargoHash = "sha256-Yeo3yOPgiyZu4wEqsnigwUASRQrQMDV/UlrzzYPNL/g=";

        buildInputs = stdInputs;

        nativeBuildInputs = stdInputs;

      };
    };
    devShells."x86_64-linux".default = pkgs.mkShell {
       buildInputs = stdInputs ++ devInputs;

       # Rust stdlib for language servers
       RUST_SRC_PATH = "${pkgs.rust.packages.stable.rustPlatform.rustLibSrc}";
       };
  };

}
