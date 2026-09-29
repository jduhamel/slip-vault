# slip-vault

A HashiCorp Vault and OpenBao package for SLIP.

## Summary

This [Slip](https://github.com/ohler55/slip) package wraps the official
[Vault Go API](https://pkg.go.dev/github.com/hashicorp/vault/api) client, which
also works against [OpenBao](https://openbao.org). It lets Slip programs read
and write secrets without hard-coding them and without echoing them in the
REPL. Like the other Slip plugins it uses Slip Flavors: `vault-connect`
returns a `vault-client` instance and every method also has a CLOS like
`vault-` function.

## Secrets are redacted

Secret values read from Vault are returned as `secret` objects, not strings.
A `secret` always prints as `#<secret>`, whether it is echoed by the REPL,
passed to `format`, `prin1`, or `describe`, converted to JSON, or included in an error
message. The plaintext is only available through `secret-value`.

```lisp
▶ (setq v (vault-connect :address "http://127.0.0.1:8200" :token "root"))
▶ (vault-kv-put v "secret" "app" '(("pw" . "hunter2")))
▶ (vault-kv-get v "secret" "app")
(("pw" . #<secret>))
▶ (secret-value (vault-kv-get-field v "secret" "app" "pw"))
"hunter2"
```

- `(make-secret "str")` wraps a string so user code can redact values too.
- `(secret-value s)` returns the plaintext string.
- `(secretp x)` returns `t` if `x` is a secret.
- `~s`, `prin1`, and `print` also show `#<secret>` rather than raising a
  `print-not-readable` error, so responses containing secrets can be printed.
- `(secret-equal a b)` compares the values of two secrets in constant time
  and returns `t` or `nil`. Both arguments must be secrets.
- `equal` is identity for secrets: two distinct secret objects are never
  `equal`, even with the same value. Use `secret-equal` to compare values.
  (`equalp` also compares values in constant time.)

Values sent to Vault (`:kv-put`, `:kv-patch`, `:write`, `:token`, `:approle`)
may be plain strings or secrets. Secrets are unwrapped before they are sent.

String values in Vault are wrapped as they are. Other JSON values, such as
numbers, booleans, arrays, and nested objects, are wrapped as their JSON
encoding, so `42` comes back as a secret whose value is `"42"`.

**Caveat:** redaction only prevents accidental display. Once a program calls
`secret-value` the plaintext is an ordinary string and can be printed, logged,
or sent anywhere. In particular:

- `(trace secret-value)`, or tracing any function that is passed the
  plaintext, prints the plaintext `secret-value` returns.
- A literal such as `(make-secret "hunter2")` typed into the REPL is saved in
  the REPL history in plain text, as is a `:token` string. Read literals from
  the environment or a file instead.
- The token and any literal secrets are also visible in the source forms of
  a program.

## API

`(vault-connect &key :address :token :namespace :timeout :ca-cert :client-cert
:client-key :tls-skip-verify :approle :auto-renew :renew-increment)` returns a
`vault-client`.

- `:address`, `:token`, and `:namespace` default to `VAULT_ADDR`,
  `VAULT_TOKEN`, and `VAULT_NAMESPACE`. The other `VAULT_*` variables are also
  honored. If any TLS keyword is given the TLS settings from the environment
  are replaced. An explicit `:address` also overrides `VAULT_AGENT_ADDR`, and
  an explicit `:token` or `:approle` overrides `VAULT_TOKEN`.
- `:approle` is a list of `(role-id secret-id [mount])`. Each may be a string
  or a secret. The mount defaults to `approle`. The login token replaces
  `:token`, and it is revoked when the client is closed.
- `:auto-renew` (default `t`) renews a renewable token in the background.
  `:renew-increment` is the ttl in seconds to request on each renewal. When an
  AppRole token reaches its max ttl a new login is made, so the role-id and
  secret-id are kept in memory for the life of the client. Any other token
  that can no longer be renewed makes later calls raise
  `vault token expired: ...`. Root tokens are not renewable and are not
  watched. `(vault-renewal-status c)` reports the state.
- The token is verified with a token self lookup, so a bad address or token
  raises an error from `vault-connect`.

| function | method | returns |
|---|---|---|
| `(vault-kv-get c mount path &key :version :timeout)` | `:kv-get` | alist of `(key . #<secret>)`, nil if missing |
| `(vault-kv-get-field c mount path field &key :version :timeout)` | `:kv-get-field` | `#<secret>` or nil |
| `(vault-kv-put c mount path data &key :cas :timeout)` | `:kv-put` | version metadata alist |
| `(vault-kv-patch c mount path data &key :timeout)` | `:kv-patch` | version metadata alist |
| `(vault-kv-delete c mount path &key :versions :timeout)` | `:kv-delete` | nil |
| `(vault-kv-list c mount path &key :timeout)` | `:kv-list` | list of key strings, nil if empty |
| `(vault-kv-metadata c mount path &key :timeout)` | `:kv-metadata` | metadata alist, nil if missing |
| `(vault-read c path &key :timeout)` | `:read` | response alist (see below), nil if missing |
| `(vault-write c path data &key :timeout)` | `:write` | response alist (see below) or nil |
| `(vault-token-lookup-self c &key :timeout)` | `:token-lookup-self` | token info alist, `"id"`, `"accessor"`, and `"cubbyhole_id"` are secrets |
| `(vault-token-renew-self c &key :increment :timeout)` | `:token-renew-self` | new ttl in seconds |
| `(vault-token c)` | `:token` | the token as a `#<secret>` |
| `(vault-renewal-status c)` | `:renewal-status` | plist `(:auto-renew :renewable :last-renewal :error)` |
| `(vault-close c)` | `:close` | nil; later calls raise `vault-client is closed` |

The KV methods use the KV version 2 engine. `data` is an alist of
`(key . value)` or a hash-table. Values may be nested lists, alists, and
hash-tables, and secrets at any depth are sent as their plaintext. Leading and
trailing `/` are trimmed from mounts and paths. `:timeout` is in seconds.
Alists returned are sorted by key.

`:read` and `:write` return the whole response:

```lisp
((:data . (("password" . #<secret>) ("username" . #<secret>)))
 (:lease-id . "database/creds/app/abc123")
 (:lease-duration . 3600)
 (:renewable . t)
 (:auth . ((:client-token . #<secret>) (:accessor . #<secret>)
           (:policies "default") (:lease-duration . 3600))))
```

`:auth` is only present when the response has auth information, for example
from a login.

## Building

The package is implemented as a Go plugin. All plugins require that the
version of the code pulling in the plugin and the plugin version match. The
plugin must be built against the actual Slip source code, not just a version
in go.mod, so `go.mod` replaces `github.com/ohler55/slip` with `../slip`. The
[slap](https://github.com/ohler55/slap) repo simplifies the process.

```
> make build   # builds vault.so
> make test    # lint and tests, needs the vault binary on the PATH
```

The tests start a `vault server -dev` subprocess. If `vault` is not on the
PATH the integration tests are skipped. To test against Vault in Docker
instead:

```
> make vault-up      # docker compose, hashicorp/vault:1.17 in dev mode
> make test-docker
> make vault-down
> make cover         # coverage total
```

## Explore

Once in the slap REPL, describe the package to list everything:

```lisp
▶ (describe *vault*)
```
