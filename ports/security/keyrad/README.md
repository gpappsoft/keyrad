# FreeBSD port: security/keyrad

Builds the `keyrad` daemon into a FreeBSD package so it can be installed as a
dependency of the OPNsense `os-keyrad` plugin (which declares
`PLUGIN_DEPENDS= keyrad`).

## Why vendored

OPNsense / poudriere build jails have **no network access during the build
phase**. The Go module dependencies are therefore vendored into `vendor/` in
the repository root, and the port builds with `-mod=vendor` (verified to build
fully offline). No `GH_TUPLE` bookkeeping is required.

## Release / build flow

1. Regenerate and commit the vendor tree whenever `go.mod` changes:

   ```sh
   go mod vendor
   git add vendor go.mod go.sum
   git commit -m "vendor dependencies for FreeBSD port"
   ```

2. Tag a release whose tarball therefore includes `vendor/`, and set
   `DISTVERSION` in `Makefile` to that tag.

3. Generate the checksums (downloads the GitHub source tarball):

   ```sh
   cd ports/security/keyrad
   make makesum
   ```

   This creates/updates `distinfo`. It is intentionally not committed here
   because it must match the exact released tarball.

4. Build and test:

   ```sh
   make build         # compiles offline against vendor/
   make stage check-plist
   make package
   ```

## Integrating into an OPNsense ports overlay

Copy this directory to `security/keyrad/` inside your OPNsense ports tree
(the same tree that builds the plugins), or add it to your private ports
overlay. The `os-keyrad` plugin pulls it in automatically via `PLUGIN_DEPENDS`.
