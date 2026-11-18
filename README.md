# ky

The [KyPanel](https://kypanel.com) command line. It manages a server through the API with an API token, from any machine.

```sh
ky login --server https://server.example.com:7711 --token YOUR_TOKEN
ky accounts list
ky accounts create acme acme.com --package Basic --wait
ky call listAccounts q=acme
```

`ky help` lists every command. `ky call` reaches any API operation by its operationId.

## Install

```sh
curl -fsSL https://updates.kypanel.com/cli/install.sh | sh
```

Builds for Linux, macOS and Windows are in `https://updates.kypanel.com/cli/VERSION/`, with signed checksums.
With Go 1.22 or later:

```sh
go install github.com/KyPanel/cli/cmd/ky@latest
```

Documentation: https://docs.kypanel.com/developers/cli/

## Develop

```sh
go test ./...
go build -o ky ./cmd/ky
```

`openapi/openapi.json` is the API description of the current KyPanel release.

License: MIT
