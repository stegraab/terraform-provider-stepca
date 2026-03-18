# Terraform Provider for Step CA

Terraform provider for managing Step CA provisioners.

## Provider Source

Use the provider source:

- `stegraab/stepca`

## Status

This provider is under active development and currently exposes one resource:

- `stepca_provisioner`

## Requirements

- Terraform `>= 1.6.0`
- Go `>= 1.24` (for building from source)

## Build

```bash
go build -o terraform-provider-stepca
```

## Run Tests

```bash
go test ./...
```

## Documentation

Provider and resource documentation:

- [Provider docs](./docs/index.md)
- [stepca_provisioner resource docs](./docs/resources/provisioner.md)

## Release

Releases are published via GitHub Actions manual workflow:

- `.github/workflows/release.yml`

Artifacts are built and signed using GoReleaser configuration:

- `.goreleaser.yml`
