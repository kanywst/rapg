{
  description = "Local-first secret manager for the AI-agent era: keeps API keys out of .env files and out of your agent transcripts";

  # Only nixpkgs. No flake-utils, so the input closure stays at one flake and
  # `nix flake update` has exactly one thing to think about.
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      # Keep this in step with the git tag when a release is cut.
      version = "0.3.1";

      # No x86_64-darwin: nixpkgs dropped it in 26.11, and merely listing it
      # here makes `nix flake show --all-systems` abort on the eval error.
      # Intel-Mac users take the release tarball or the brew tap.
      systems = [ "x86_64-linux" "aarch64-linux" "aarch64-darwin" ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in
    {
      overlays.default = final: prev: {
        rapg = final.callPackage ({ buildGoModule, lib }:
          buildGoModule {
            pname = "rapg";
            inherit version;
            src = self;

            # Changes whenever go.mod or go.sum does. To refresh: put
            # lib.fakeHash here, run `nix build .#rapg`, copy the "got:" value.
            vendorHash = "sha256-Q3o2q3T9rDrmepw9eS4wlrfhj61Aau/VQ8KpX8xOc14=";

            subPackages = [ "cmd/rapg" ];

            # gorm.io/driver/sqlite pulls in mattn/go-sqlite3, which is cgo.
            # Left at the buildGoModule default (enabled) deliberately, since
            # turning it off builds a binary that cannot open its own vault.
            ldflags = [ "-s" "-w" ];

            meta = {
              description = "Local-first secret manager for the AI-agent era";
              homepage = "https://github.com/kanywst/rapg";
              license = lib.licenses.mit;
              mainProgram = "rapg";
              platforms = lib.platforms.unix;
            };
          }) { };
      };

      packages = forAllSystems (pkgs: rec {
        rapg = (self.overlays.default pkgs pkgs).rapg;
        default = rapg;
      });

      apps = forAllSystems (pkgs: rec {
        rapg = {
          type = "app";
          program = "${self.packages.${pkgs.stdenv.hostPlatform.system}.rapg}/bin/rapg";
        };
        default = rapg;
      });

      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          packages = [ pkgs.go pkgs.gopls pkgs.golangci-lint ];
        };
      });
    };
}
