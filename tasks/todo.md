# slip-vault todo

Plan: /Users/joe/.claude/plans/prancy-jingling-sutherland.md

- [x] Scaffold: main.go, Makefile, go.mod, .gitignore, vault/Makefile, git init
- [x] Secret type, make-secret, secret-value, secretp, secret-equal
- [x] vault-connect and the vault-client flavor (KV v2, read/write, token methods, close)
- [x] Devil's-advocate fixes (redaction everywhere, AgentAddress, path trimming, lease info, atomic close)
- [x] Token auto-renewal (LifetimeWatcher, AppRole re-login, :renewal-status)
- [x] Test harness: -dev-no-store-token, temp HOME, Setpgid, group kill, pidfile reaping, VAULT_TEST_ADDR
- [x] docker-compose.yml and make vault-up / test-docker / vault-down / cover
- [x] make test clean: 156 tests pass, 95.5% coverage, -race clean, lint clean
- [x] make build produces vault.so
- [x] Wired into slap (go.mod replace, blank imports); slap and slapr build
- [x] REPL smoke test via slapr: runtime canary never printed
- [x] Verifier pass: PASS, with follow-ups applied (numeric type errors redacted, token revoked on a cancelled re-login or a failed lookup, revocation test)
- [ ] First commit and push to github.com/jduhamel/slip-vault (awaiting approval)
- [ ] slap startup crash: slip-graph's `command` flavor clashes with slip core pkg/gi (outside this repo)

## Known limits
- After one failed AppRole re-login the client stays errored until you reconnect. There's no retry.
- The renewal tests sleep with about 2s of margin against 4s/10s TTLs.
