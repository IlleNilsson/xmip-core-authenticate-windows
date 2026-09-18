# xmip-core-authenticate-windows

Authenticate by Windows: proves a credential through the host's SSPI, refusing where no SSPI is reachable from this build. A technology of [xmip-core-authenticate](https://github.com/IlleNilsson/xmip-core-authenticate).

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
