# Delegated-session migration notice

`delegated-session` is no longer a supported agent mode. The former UHID-based design was removed because stock Chromium could still present a native credential-selection modal, preventing reliable autonomous browser operation.

Use [`same-user`](same-user.md) for bounded access to the existing human credential backend. Same-user retains the daemon-backed MV3 browser path selected by ADR 0005 while replacing the old one-shot delegated credential view with:

- the real human storage, PIN service, key provider, signature counters, and operation lock;
- exact RP and optional credential-reference scope;
- a short-lived browser capability with a shared operation budget;
- replay rejection and policy re-evaluation for every distinct request;
- immediate authentication with a credential registered during the same session.

## Configuration migration

Replace:

```toml
mode = "delegated-session"
delegated_registration_storage = "human"
```

with:

```toml
mode = "same-user"
max_session_ttl = 600
max_operations = 16
credential_selection = "single"
```

Remove delegated-only storage/view fields. Keep exact RP rules, but replace the legacy evidence spelling `policy` with `agent` or use the aliases:

```toml
[[agents.profiles.opencode.rules]]
rp_id = "github.com"
register = "deny"
authenticate = "autonomous"
```

The parser accepts `policy` as a temporary alias for `agent`, but new configuration and audit output use `agent`.

See [same-user.md](same-user.md), [configuration.md](configuration.md), and [security.md](security.md).
