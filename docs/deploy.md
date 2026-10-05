# Deploying Midden

Midden ships as one container with everything inside: the API, the web client, the SQLite
database and the file store. There is nothing else to install and nothing to connect it to.

## What you need

- Docker with buildx, or a machine with Node 24 if you would rather run it directly.
- One writable directory for `/data`. That directory _is_ the installation: copy it and you
  have copied every case, scan and attachment.
- A laptop or a Raspberry Pi 4/5. Both are supported targets; images are published for
  `linux/amd64` and `linux/arm64`.

## Quick start

```bash
docker run -d --name midden \
  -p 8080:8080 \
  -v "$PWD/midden-data:/data" \
  -e MIDDEN_SECRET="$(openssl rand -base64 32)" \
  -e MIDDEN_ADMIN_USER=admin \
  -e MIDDEN_ADMIN_PASSWORD='choose something long' \
  ghcr.io/jacstrong/midden:latest
```

Open `http://localhost:8080`, sign in as the admin, and change the password when prompted. If
you leave `MIDDEN_ADMIN_PASSWORD` unset, Midden generates a one-time password and writes it to
the container log on first boot:

```bash
docker logs midden | grep 'one-time password'
```

Then add your team under **Users** and create the first case.

Or with compose, from a checkout:

```bash
docker compose -f docker/docker-compose.yml up -d
```

## Running on a Raspberry Pi

The image is multi-arch, so the same command works. Two notes:

- The entrypoint caps the V8 heap at 1 GB on arm64. Override with `MIDDEN_NODE_HEAP_MB` if the
  Pi has plenty of memory and you ingest very large scans.
- Password hashing is deliberately expensive. On a Pi 4, drop it so sign-in stays brisk:
  `-e MIDDEN_ARGON2_MEMORY_KIB=32768`.

Put `/data` on an SSD rather than the SD card if you can. Midden batches writes and uses WAL
mode, but a /16 scan still writes a few hundred megabytes.

## Configuration

Everything is an environment variable. All of them are optional except where noted.

| Variable                                      | Default   | What it does                                                                                                                   |
| --------------------------------------------- | --------- | ------------------------------------------------------------------------------------------------------------------------------ |
| `MIDDEN_PORT`                                 | `8080`    | Listening port                                                                                                                 |
| `MIDDEN_HOST`                                 | `0.0.0.0` | Listening address                                                                                                              |
| `MIDDEN_DATA`                                 | `/data`   | Database, blobs and temp files                                                                                                 |
| `MIDDEN_SECRET`                               | none      | Signing secret for session cookies. Set it in production.                                                                      |
| `MIDDEN_PUBLIC_ORIGIN`                        | none      | Public URL, e.g. `https://midden.corp.example`. Used for WebSocket origin checks and the OIDC redirect. Set it behind a proxy. |
| `MIDDEN_TRUST_PROXY`                          | `false`   | Trust `X-Forwarded-*`. Turn on behind a reverse proxy.                                                                         |
| `MIDDEN_OPEN_CASES`                           | `true`    | Every analyst can edit every case. Turn off to make new cases members-only.                                                    |
| `MIDDEN_ADMIN_USER` / `MIDDEN_ADMIN_PASSWORD` | none      | Seeds the first admin. Only used when there are no users.                                                                      |
| `MIDDEN_ARGON2_MEMORY_KIB`                    | `65536`   | Password hashing cost. Lower on small boards.                                                                                  |
| `MIDDEN_MAX_UPLOAD_MB`                        | `25`      | Largest single scan or attachment                                                                                              |
| `MIDDEN_CASE_QUOTA_MB`                        | `2048`    | Total attachment bytes per case                                                                                                |
| `MIDDEN_LOGIN_RATE_LIMIT`                     | `30`      | Login attempts per minute per IP                                                                                               |
| `MIDDEN_TLS_CERT` / `MIDDEN_TLS_KEY`          | none      | Serve HTTPS directly, for a hunt LAN with no proxy in front                                                                    |
| `MIDDEN_LOG_LEVEL`                            | `info`    | pino level                                                                                                                     |

## HTTPS

Behind a reverse proxy, terminate TLS there and set:

```
MIDDEN_PUBLIC_ORIGIN=https://midden.corp.example
MIDDEN_TRUST_PROXY=true
```

The proxy must forward WebSocket upgrades on `/api/ws`. For nginx:

```nginx
location / {
    proxy_pass http://127.0.0.1:8080;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
}
```

With no proxy available, point Midden at a certificate and key and it serves HTTPS itself:

```bash
-e MIDDEN_TLS_CERT=/data/tls/fullchain.pem -e MIDDEN_TLS_KEY=/data/tls/privkey.pem
```

## Single sign-on

Local accounts are the default and always work. To offer OpenID Connect alongside them, set all
three of these and restart:

```
MIDDEN_OIDC_ISSUER=https://idp.corp.example/realms/ir
MIDDEN_OIDC_CLIENT_ID=midden
MIDDEN_OIDC_CLIENT_SECRET=...
```

Register `https://<your public origin>/api/auth/oidc/callback` as the redirect URI. A
"Sign in with SSO" button then appears on the login screen.

Optional:

- `MIDDEN_OIDC_SCOPES` (default `openid profile email`)
- `MIDDEN_OIDC_ADMIN_CLAIM` and `MIDDEN_OIDC_ADMIN_VALUE`, e.g. `groups` and `midden-admins`.
  When set, admin rights follow the provider on every sign-in, both granted and revoked.

Users are matched on the issuer's subject, so renaming someone upstream does not create a
duplicate. A first-time SSO user with the same username as an existing local account is linked
to it rather than duplicated.

## API keys

Logged-in users create API keys under **API keys** in the header (or `POST /api/auth/tokens`).
A key acts as you, is shown once, is stored only as a SHA-256 hash, and works until revoked.
Scripts authenticate with a bearer header instead of the session cookie:

```bash
curl -X POST https://midden.corp.example/api/cases/case_YodbHg6aG_If/scans \
  -H "Authorization: Bearer mk_..." \
  -F "file=@scan.xml" -F "name=perimeter sweep" -F "phase=recon"
```

No `X-Midden-Client` or cookie is needed with a bearer key (that header stays as the CSRF
guard for cookie requests). Useful for the nmap plugin: point it at the case's
`/api/cases/<id>/scans` endpoint and it can upload `-oX`/`-oN` output unattended.

## Backup and restore

`/data` is the whole installation, but copying it while the server is running can catch the
database mid-write. Take a consistent copy instead:

```bash
docker exec midden node /app/dist/main.js backup /data/midden-backup.db
docker cp midden:/data/midden-backup.db ./midden-backup.db
```

Admins can also download one from the API: `GET /api/admin/backup`.

To restore, stop the container, put the backup in place as `/data/midden.db`, and start again.
Attachments and raw scans live in `/data/blobs`, so copy that directory too if you want the
files as well as the case data.

## Maintenance

All commands take the same `MIDDEN_DATA`:

```bash
# replay the operation log into fresh projection tables (safe, idempotent)
docker exec midden node /app/dist/main.js rebuild all

# accounts, when nobody can get in
docker exec midden node /app/dist/main.js create-user ann 'a long passphrase' analyst
docker exec midden node /app/dist/main.js reset-password admin 'a new long passphrase'
```

`rebuild` is the repair tool: every case is stored as an append-only operation log, and the
tables the UI reads are a projection of it. If a projection is ever wrong, replaying fixes it
without losing history.

## Health and monitoring

`GET /api/health` returns version, Node and SQLite versions, whether argon2 is available, and
free space on the data volume. The container healthcheck already polls it. Logs are JSON
(pino) on stdout.

## Sizing

Twenty concurrent analysts on one case is the design point. On a laptop, twenty clients each
sending five operations a second settle at a p95 acknowledgement of about 30 ms. A /16 scan
with service detection is roughly 65,000 hosts and half a million ports; it ingests in a worker
thread so live editing is unaffected while it loads.

## Running without Docker

```bash
pnpm install && pnpm build
MIDDEN_DATA=./data MIDDEN_PUBLIC_DIR=packages/web/dist \
  node --no-warnings=ExperimentalWarning packages/server/dist/main.js
```

## No server at all

Every release also ships `midden-standalone.html`: the same interface in one file, with no
server, no storage and no network calls. Open it from disk, work on a case, save a `.json`,
and reopen it later. It reads nmap scans too, parsing them in the page. Use it when you are
working alone or cannot run a container; use the server when more than one person needs the
same case at the same time. Case files move freely between the two.
