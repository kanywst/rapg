{
  description = "Local-first secret manager for the AI-agent era: keeps API keys out of .env files and out of your agent transcripts";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      # Keep this in step with the git tag when a release is cut.
      version = "0.3.2";

      # No x86_64-darwin: nixpkgs dropped it in 26.11, and listing it makes
      # `nix flake show --all-systems` abort on the eval error.
      systems = [ "x86_64-linux" "aarch64-linux" "aarch64-darwin" ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in
    {
      overlays.default = final: prev: {
        rapg = final.callPackage ({ buildGoModule, installShellFiles, lib, stdenv }:
          buildGoModule {
            pname = "rapg";
            inherit version;
            src = self;

            # Moves with go.mod. To refresh: set lib.fakeHash, `nix build
            # .#rapg`, copy the "got:" value.
            vendorHash = "sha256-Q3o2q3T9rDrmepw9eS4wlrfhj61Aau/VQ8KpX8xOc14=";

            subPackages = [ "cmd/rapg" ];

            # CGO stays at the buildGoModule default: a CGO-less binary cannot
            # open the SQLite vault.
            ldflags = [
              "-s"
              "-w"
              "-X=github.com/kanywst/rapg/internal/version.Version=${version}"
            ];

            nativeBuildInputs = [ installShellFiles ];

            # Doubles as a regression test: the build sandbox sets HOME to an
            # unwritable path, so this fails if `rapg completion` ever goes
            # back to opening the vault.
            postInstall = lib.optionalString (stdenv.buildPlatform.canExecute stdenv.hostPlatform) ''
              installShellCompletion --cmd rapg \
                --bash <($out/bin/rapg completion bash) \
                --fish <($out/bin/rapg completion fish) \
                --zsh <($out/bin/rapg completion zsh)
            '';

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
