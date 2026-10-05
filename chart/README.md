# midden

Helm chart for [Midden](https://github.com/tylerobara/Midden): one container with the API,
web client, SQLite database and file store. The whole installation lives in the `/data`
volume, so it runs as a single pod on a `ReadWriteOnce` volume.

## Install

```bash
helm registry login ghcr.io -u <github-user> --password-stdin   # if the package is private
helm install midden oci://ghcr.io/tylerobara/charts/midden \
  --set secret.adminPassword='choose something long' \
  --set config.MIDDEN_SECRET="$(openssl rand -base64 32)"
```

If you leave `secret.signingKey` and `secret.adminPassword` empty, the chart generates a
signing key once (it survives upgrades) and Midden logs a one-time admin password on first
boot: `kubectl logs deploy/<release>-midden | grep 'one-time password'`.

## OpenID Connect

Yes — OIDC is just environment variables, so the chart configures it natively. The server
turns SSO on when issuer, client ID and client secret are all present; a "Sign in with SSO"
button appears next to local accounts.

```bash
helm install midden oci://ghcr.io/tylerobara/charts/midden \
  --set oidc.enabled=true \
  --set oidc.issuer=https://idp.corp.example/realms/ir \
  --set oidc.clientId=midden \
  --set oidc.clientSecret='<secret>' \
  --set config.MIDDEN_PUBLIC_ORIGIN=https://midden.corp.example \
  --set config.MIDDEN_TRUST_PROXY=true
```

- Register `https://<public origin>/api/auth/oidc/callback` as the redirect URI at the provider.
- Keep the secret out of values with an existing Secret:
  `oidc.existingSecret=my-sso oidc.clientSecretKey=client-secret`.
- Provider-managed admins: `oidc.adminClaim=groups oidc.adminValue=midden-admins`.
- Everything else (`scopes`, `allowInsecure`, quotas, TLS, log level) is in `values.yaml`,
  with pass-through for anything unhandled via `extraEnv`.

## Gateway API

Instead of (or alongside) the Ingress, enable a Gateway API `HTTPRoute` — the cluster needs
the `gateway.networking.k8s.io` CRDs.

```bash
helm install midden oci://ghcr.io/tylerobara/charts/midden \
  --set gateway.enabled=true \
  --set 'gateway.parentRefs[0].name=main-gateway' \
  --set 'gateway.parentRefs[0].namespace=gateway-system' \
  --set 'gateway.hostnames[0]=midden.corp.example'
```

`parentRefs` is passed through verbatim (add `sectionName` to pin a listener); `matches`,
`filters` (e.g. `RequestHeaderModifier`) and `requestTimeout` cover the rest. The same
WebSocket-forwarding caveat as the Ingress applies to your gateway's routing.

## Notes

- `replicaCount` must stay `1`; the strategy is `Recreate` so the volume never has two writers.
- Behind an ingress, the controller must forward WebSocket upgrades on `/api/ws`.
- Non-root, read-only root filesystem, all capabilities dropped; only `/data` is writable.
