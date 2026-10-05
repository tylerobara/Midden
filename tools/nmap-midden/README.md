# midden-nmap

Run [nmap](https://nmap.org) and upload the result to a Midden case, or upload an existing
`-oX`/`-oN` file. One dependency-free Node 20+ script — no build, no install.

```bash
export MIDDEN_URL=https://midden.staging.obara.dev
export MIDDEN_API_KEY=mk_...          # create under API keys in the web UI
export MIDDEN_CASE_ID=case_YodbHg6aG_If

# Scan and upload (your nmap args pass through; XML capture is forced):
node midden-nmap.mjs -sT -T4 --top-ports 1000 10.0.0.0/24

# Don't know your case id? Leave MIDDEN_CASE_ID unset and run from a terminal —
# the tool lists the cases you can access and asks:
#   cases:
#   > 1) CASE-7 — perimeter recon
#   > 2) CASE-9 — lateral movement
#   type the case number you want to upload results to:

# Upload a file you already have, labelled, and block until Midden finishes parsing:
node midden-nmap.mjs -f scan.xml --name "edge sweep" --phase discovery --wait
```

Flags `--url/--key/--case` override the env vars; `--keep` also drops the XML copy in the
current directory. Exit codes: `1` config, `2` nmap failed, `3` upload/poll failed,
`4` scan uploaded but failed to parse — so CI and wrapper scripts can branch on the stage
that broke. Auth is the user-scoped API key (`Authorization: Bearer`); upload goes to
`POST /api/cases/<id>/scans`, parsing is polled via `GET` until `ready`/`failed`.

Typical hunt loop matches the scan builder: discovery pass with `--phase discovery`, then a
service scan of the alive targets with `--phase service`; both attach to the same case and
land on the terrain map.

Tests: `pnpm vitest run --project tools`.
