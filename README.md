# ManticoreScanner

Scan npm dependencies for malicious code using the Manticore behavioral analysis backend.

## Table of contents

- [Requirements](#requirements)
- [GitHub Action](#github-action)
  - [Quick start](#quick-start)
  - [Scan action](#scan-action)
  - [Setup action](#setup-action)
- [CLI](#cli)
  - [Install](#install)
  - [`manticore scan`](#manticore-scan)
  - [`manticore exec`](#manticore-exec)
- [Environment variables](#environment-variables)
- [Docker](#docker)
  - [Verifying the image signature](#verifying-the-image-signature)
- [Verifying release artifacts](#verifying-release-artifacts)
- [License](#license)

## Requirements

- A Manticore API key. Sign up at [tazarsec.dev](https://tazarsec.dev) to obtain one, then store it as an Actions secret (e.g. `MANTICORE_API_KEY`).
- A GitHub-hosted or self-hosted runner on Linux, macOS, or Windows (amd64 or arm64).
- An npm project with a `package.json` and/or `package-lock.json` checked into the repository.

## GitHub Action

Two composite actions are published from this repository:

| Action | Purpose |
|---|---|
| `TazarSec/ManticoreScanner@v1` | One-shot scan against your committed lockfile. Reports findings, optionally posts a PR comment, and can fail the job on suspicious packages. |
| `TazarSec/ManticoreScanner/setup@v1` | Installs the `manticore` CLI on the runner PATH so you can invoke `manticore scan` or `manticore exec` from your own pipeline steps. |

Both actions download the matching release binary for the runner platform, verify its SHA-256 checksum against the published `checksums.txt`, and add the binary to `PATH` at the resolved release tag.

**Pin by full commit SHA — recommended.** Git tags are mutable, so `@v1` or `@v1.2.3` can silently change underneath your workflow. A 40-character commit SHA is the only tamper-evident pin and is the format GitHub recommends for third-party actions:

```yaml
- uses: TazarSec/ManticoreScanner@<full-commit-sha> # v1.2.3
```

The action accepts SHA pins and resolves them back to the matching release tag to download the corresponding binary, so the SHA must point to a commit that is itself a tagged release (an arbitrary commit on `main` will be rejected). Dependabot and Renovate both understand the `@<sha> # vX.Y.Z` convention and will bump both the SHA and the trailing comment when a new release is cut.

The floating `@v1` and lightweight `@v1.2.3` tag pins are also supported for convenience, but SHA pinning is the recommended option when hardening your supply chain.

### Quick start

Drop this into `.github/workflows/manticore.yml` to scan every push and pull request — no other configuration required:

```yaml
on: [push, pull_request]

jobs:
  manticore:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd #6.0.2
      - uses: TazarSec/ManticoreScanner@v1
        with:
          api-key: ${{ secrets.MANTICORE_API_KEY }}
```

The action auto-detects your `package-lock.json` (or `package.json`), fails the job on any non-zero suspicion score, and prints a results table to the job log. See the [scan action](#scan-action) section below to enable PR comments, raise the fail threshold, emit SARIF, and more.

### Scan action

Runs `manticore scan` against your lockfile and reports the results. Use this when you want a turnkey "open a PR, get findings on the PR" workflow.

```yaml
permissions:
  contents: read
  pull-requests: write

jobs:
  manticore:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd #6.0.2
      - uses: TazarSec/ManticoreScanner@v1
        with:
          api-key: ${{ secrets.MANTICORE_API_KEY }}
          fail-on: 50
          vcs-comment: true
```

> **PRs from forks:** the default `GITHUB_TOKEN` is read-only on `pull_request` events triggered by forked repositories, so `vcs-comment: true` will fail to post (the scan itself still runs and reports findings in the job output). If you need PR comments on fork PRs, switch the workflow trigger to `pull_request_target` — but only after you've audited the security implications, since that trigger runs with the base repository's secrets.

#### Inputs

| Input | Description | Default |
|---|---|---|
| `api-key` | Manticore API key. **Required.** | — |
| `api-url` | API base URL. | `https://tazarsec.dev` |
| `file` | Path to `package.json` / `package-lock.json`. | auto-detected in `working-directory` |
| `format` | Output format: `table`, `json`, `sarif`. | `table` |
| `output` | Write results to this path instead of stdout. | stdout |
| `fail-on` | Fail the job if any suspicion score is at or above this threshold. Pass a higher number to gate only on stronger signals. | `1` (any non-zero score fails) |
| `ignore-list` | Path to a file listing packages to skip — see [Ignore specific packages](#ignore-specific-packages). | none |
| `http-timeout` | Per-request HTTP timeout in seconds. | `120` |
| `timeout` | Polling timeout in seconds — how long to wait for backend results before erroring or continuing per `on-error`. | `300` |
| `on-error` | Behavior on backend errors or polling deadline exceeded with pending items: `fail` (exit non-zero) or `continue` (exit 0). | `fail` |
| `production` | Set to `true` to skip devDependencies. | `false` |
| `vcs-comment` | Set to `true` to post a PR comment with findings. | `false` |
| `include-transitive` | Set to `true` to submit transitive deps — see [Transitive dependencies](#transitive-dependencies). | `false` |
| `insecure` | Allow plaintext `http://` API URLs. TLS is required when `false`. | `false` |
| `working-directory` | Directory to run the scan from. | `.` |
| `version` | Pin a specific release tag (e.g. `v1.2.3`). | the ref the action was invoked with (e.g. `v1`) |

### Setup action

Installs the CLI on `PATH` and stops there. Use this when you want to drive `manticore` directly — to gate `npm install` at execution time, run scans on dynamically-resolved lockfiles, emit SARIF for code scanning, or chain it with other steps.

#### Gate installs with `manticore exec`

`manticore exec` wraps a package manager install command. It first resolves the dependency tree to a lockfile **without executing install scripts**, scans every package, and only invokes the real install if the scan passes. This blocks malicious payloads on the runner before they get a chance to run.

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    env:
      MANTICORE_API_KEY: ${{ secrets.MANTICORE_API_KEY }}
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd #6.0.2
      - uses: TazarSec/ManticoreScanner/setup@v1
      - run: manticore exec --fail-on 50 -- npm ci
      - run: npm run build
```

Supported package managers: `npm`. Supported subcommands: `install`, `ci`, and `install <pkg>`.

#### Run a scan as a workflow step

```yaml
jobs:
  scan:
    runs-on: ubuntu-latest
    env:
      MANTICORE_API_KEY: ${{ secrets.MANTICORE_API_KEY }}
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd #6.0.2
      - uses: TazarSec/ManticoreScanner/setup@v1

      - run: manticore scan --format sarif --output manticore.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: manticore.sarif
```

Configure runtime behavior via flags or `MANTICORE_*` environment variables — see [CLI](#cli) below.

#### Inputs

| Input | Description | Default |
|---|---|---|
| `version` | Pin a specific release tag (e.g. `v1.2.3`). | the ref the action was invoked with (e.g. `v1`) |

## CLI

### Install

```bash
go install github.com/TazarSec/ManticoreScanner/cmd/manticore@latest
```

Or build from source:

```bash
git clone https://github.com/TazarSec/ManticoreScanner.git
cd ManticoreScanner
go build -o manticore ./cmd/manticore
```

Pre-built release binaries (`manticore-<os>-<arch>`) and a Docker image are also published — see [Verifying release artifacts](#verifying-release-artifacts) and [Docker](#docker).

### `manticore scan`

Parses an npm lockfile (or `package.json`) and submits dependencies to the backend for behavioral analysis.

#### Basic scan

Auto-detect `package-lock.json` or `package.json` in the current directory:

```bash
manticore scan --api-key YOUR_API_KEY
```

#### Scan a specific file

```bash
manticore scan --api-key YOUR_API_KEY --file path/to/package-lock.json
```

#### Output formats

```bash
# Human-readable table (default)
manticore scan --api-key YOUR_API_KEY --format table

# JSON
manticore scan --api-key YOUR_API_KEY --format json

# SARIF (for GitHub Code Scanning)
manticore scan --api-key YOUR_API_KEY --format sarif --output results.sarif
```

#### Fail on suspicious packages

By default the scan exits non-zero if any package has a suspicion score of `1` or higher (i.e., any non-zero finding). Pass `--fail-on N` to raise the threshold and only fail on stronger signals:

```bash
manticore scan --api-key YOUR_API_KEY --fail-on 50
```

The default threshold can also be overridden via the `MANTICORE_FAILURE_THRESHOLD` environment variable.

#### Skip devDependencies

```bash
manticore scan --api-key YOUR_API_KEY --production
```

#### Transitive dependencies

By default the scanner submits only **direct** dependencies (the entries in your `package.json` `dependencies` / `devDependencies`). The backend's behavioral analysis already executes transitive code when it installs each direct package, so most "live payload" supply-chain attacks are caught indirectly.

If you want every package in the resolved tree submitted by name — useful for static signals like known-bad lists, typosquat heuristics, and per-package attribution in reports — opt in:

```bash
manticore scan --api-key YOUR_API_KEY --include-transitive
```

Trade-off: this can multiply your scan volume by 10–100× on a typical Node project. Leave it off unless you specifically need static-signal coverage on transitives.

#### Ignore specific packages

Pass a file with one entry per line. Each entry must pin a specific release — either `name@version` or a lockfile integrity hash (e.g. `sha512-...`). Bare package names are rejected so an ignore never silently covers a future malicious version. Blank lines and lines starting with `#` are ignored. Matching packages are skipped before submission, so they don't count against your scan quota.

Hash matching reads the `integrity` field from `package-lock.json`; entries in `package.json` have no hash and can only be ignored by `name@version`.

```bash
manticore scan --api-key YOUR_API_KEY --ignore-list .manticoreignore
```

```text
# .manticoreignore
lodash@4.17.21
@scope/internal-pkg@1.2.3
sha512-oRjE9PZkgGr/QJtKqz5IngnFFiLk5xQxQ4y+9k4dZB5RZ2yMJZ8R3pYV+Q0WQ1l7xq4j6+UqQc9Yj3o/4G0sUQ==
```

By default no ignore list is used.

#### Post results to a GitHub PR

When running in GitHub Actions, post a comment with suspicious packages to the PR:

```bash
manticore scan --api-key YOUR_API_KEY --vcs-comment
```

### `manticore exec`

Wraps a package manager install command. Resolves the dependency tree to a lockfile without running install scripts, scans every package, and only proceeds with the real install if the scan passes.

```bash
manticore exec -- npm ci
manticore exec -- npm install
manticore exec -- npm install lodash
manticore exec --fail-on 50 -- npm install
manticore exec --ignore-list .manticoreignore -- npm ci
manticore exec --on-error continue -- npm ci
```

Supported package managers: `npm`.

`exec` shares the same `--fail-on` default as [`scan`](#fail-on-suspicious-packages) (`1` — any non-zero suspicion score blocks the install) and respects `MANTICORE_FAILURE_THRESHOLD` the same way. Pass `--fail-on N` (or set the env var) to gate only on stronger signals, e.g. `--fail-on 50` to block on moderate findings or `--fail-on 70` to block only on strong ones. Use `--ignore-list` to waive specific pinned packages (same format as [`scan`](#ignore-specific-packages)). Use `--on-error continue` to proceed with the install if the backend is unreachable or the polling deadline is exceeded with packages still pending — this trades the security gate for availability.

## Environment variables

Every variable below is optional and overridden by the equivalent CLI flag when both are set.

| Variable | Description | Default |
|---|---|---|
| `MANTICORE_API_KEY` | API key (alternative to `--api-key`). | — |
| `MANTICORE_API_URL` | API base URL. | `https://tazarsec.dev` |
| `MANTICORE_TIMEOUT` | Polling timeout in seconds. | `300` |
| `MANTICORE_HTTP_TIMEOUT` | Per-request HTTP timeout in seconds. | `120` |
| `MANTICORE_ON_ERROR` | Behavior on backend errors or polling deadline exceeded with pending items: `fail` or `continue`. | `fail` |
| `MANTICORE_FORMAT` | Output format: `table`, `json`, `sarif`. | `table` |
| `MANTICORE_FAILURE_THRESHOLD` | Default `--fail-on` threshold when not passed explicitly. | `1` (any non-zero score fails) |
| `MANTICORE_IGNORE_LIST` | Path to an ignore-list file (alternative to `--ignore-list`). | none |
| `MANTICORE_INCLUDE_TRANSITIVE` | Set to `true` to submit transitive deps. | `false` (direct deps only) |
| `MANTICORE_INSECURE` | Set to `true` to allow plaintext `http://` API URLs. | `false` (HTTPS required) |

## Docker

Multi-arch images (`linux/amd64`, `linux/arm64`) are published to GHCR on every release. Tags: `vX.Y.Z` (immutable), `vX` (latest release in the major line), and `latest`.

```bash
docker run --rm \
  -v $(pwd):/workspace \
  -w /workspace \
  ghcr.io/tazarsec/manticorescanner:latest \
  scan --api-key YOUR_API_KEY
```

### Verifying the image signature

Release images are signed by digest with cosign keyless (Sigstore + GitHub OIDC) and have a SLSA build-provenance attestation pushed to the registry.

```bash
IMAGE=ghcr.io/tazarsec/manticorescanner:v1.2.3

# Cosign keyless signature
cosign verify "${IMAGE}" \
  --certificate-identity-regexp '^https://github.com/TazarSec/ManticoreScanner/\.github/workflows/release\.yml@refs/tags/v.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

# SLSA build provenance
gh attestation verify "oci://${IMAGE}" --repo TazarSec/ManticoreScanner
```

For reproducible pulls pin by digest instead of tag:

```bash
docker pull ghcr.io/tazarsec/manticorescanner@sha256:<digest>
```

## Verifying release artifacts

Every release publishes `checksums.txt` with a keyless signature plus a SLSA build provenance attestation per binary:

1. **Keyless signature** (`checksums.txt.sig` / `checksums.txt.pem`) produced automatically by the release workflow using [cosign](https://github.com/sigstore/cosign) + Sigstore Fulcio + GitHub OIDC, transparency-logged in Rekor.
2. **Build provenance attestations** for every `manticore-*` binary via GitHub's [attest-build-provenance](https://github.com/actions/attest-build-provenance).

Verify with either — or both — of them:

```bash
# 1. Keyless (Sigstore/OIDC)
cosign verify-blob \
  --certificate checksums.txt.pem \
  --signature checksums.txt.sig \
  --certificate-identity-regexp '^https://github.com/TazarSec/ManticoreScanner/\.github/workflows/release\.yml@refs/tags/v.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt

# 2. SLSA build provenance
gh attestation verify manticore-linux-amd64 --repo TazarSec/ManticoreScanner

# Then validate the binary itself against the verified manifest
sha256sum --check --ignore-missing checksums.txt
```

## License

Licensed under the [Apache License, Version 2.0](LICENSE) (SPDX: `Apache-2.0`). See [NOTICE](NOTICE) for attribution.