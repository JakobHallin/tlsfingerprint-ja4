# JA4 TLS fingerprint server

## Run

```sh
./scripts/generate-cert.sh
go run .
```

In another terminal:

```sh
curl -k https://localhost:8443/
```

## Test

```sh
go test ./...
```
