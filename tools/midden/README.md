# midden CLI

A compiled single-binary nmap wrapper that uploads scans to Midden. No runtime, no
dependencies beyond nmap itself (install it with `brew install nmap` / your package
manager; uploads of already-captured files work without it).

```
midden <nmap args...>            plain nmap passthrough
midden -U <nmap args...>         scan, then upload the result
midden upload scan.xml ...       upload an existing -oX/-oN file
midden login --url https://midden.corp.example
midden whoami | logout | version
```

## First run

```bash
midden login --url https://midden.staging.obara.dev
```

The CLI fetches a one-time challenge from the server and opens your browser at the Midden
web app. Sign in there (local account or SSO — whatever the browser session does anyway),
press **Allow**, and the CLI picks up a fresh, revocable API key cached under
`~/.config/midden/credentials.json`. Nothing to paste.

## Scanning

```bash
midden -sT -T4 --top-ports 1000 10.0.0.0/24          # just nmap
midden -U --name "edge sweep" --phase discovery 10.0.0.0/24
midden upload scan.xml --case case_YodbHg6aG_If --wait
```

`-U` forces an `-oX` capture, then uploads to `POST /api/cases/<id>/scans` with your bearer
key. The case comes from `--case`, `MIDDEN_CASE_ID`, or an interactive numbered picker.
`--wait` blocks until the server reports `ready`/`failed`.

Env: `MIDDEN_URL`, `MIDDEN_API_KEY`, `MIDDEN_CASE_ID`, `MIDDEN_NMAP` (alternate nmap path).
Exit codes: `1` config/pick failure, `3` transport, `4` uploaded but parse failed,
otherwise nmap's own code passes through — scriptable end to end.

## Building

```bash
tools/midden/build.sh [version]   # dist/midden-{darwin,linux}-{arm64,amd64}
go test ./...                     # unit tests (in this directory)
```

CI attaches the four binaries to every GitHub release. Windows binaries on request.
