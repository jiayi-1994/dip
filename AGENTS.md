# AGENTS.md

## Cursor Cloud specific instructions

**Product**: DIP (Docker Image Pull) — a single-binary Go CLI that pulls Docker images from registries and saves them as `.tar` files, without requiring Docker.

**Tech stack**: Go 1.23.8, zero external dependencies (stdlib only), single source file `main.go`.

### Build & Run

- **Build**: `go build -o dip .`
- **Lint**: `go vet ./...`
- **Run**: `./dip -i <image>:<tag>` (e.g. `./dip -i alpine:latest`)
- **Version check**: `./dip --version`
- See `README.md` for full CLI flags and usage examples.

### Notes

- Run `go test ./...` for mirror configuration and registry selection regression tests. Also validate by building and running the tool against a real registry.
- The tool requires network access to Docker registries at runtime and connects directly by default. Custom mirrors are opt-in via `-m` or `DOCKER_PULL_MIRRORS`; use `-m=` to force direct access, including in Windows PowerShell.
- Output `.tar` files and the cache directory (`~/.docker-pull/cache`) are generated at runtime — clean them up as needed. The `.gitignore` already excludes `*.tar` and the `dip` binary.
- No `go.sum` file exists because there are zero external dependencies.
