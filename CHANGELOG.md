# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Added
- Initial `vault` package: `vault-connect` and the `vault-client` flavor with
  `:kv-get`, `:kv-get-field`, `:kv-put`, `:kv-patch`, `:kv-delete`,
  `:kv-list`, `:kv-metadata`, `:read`, `:write`, `:token-lookup-self`,
  `:token-renew-self`, `:token`, and `:close`, each with a `vault-` FLOS function.
- Redacting `secret` type with `make-secret`, `secret-value`, `secretp`, and
  the constant-time `secret-equal`.
- Background token renewal with the `:auto-renew` and `:renew-increment`
  connect options, AppRole re-login at max ttl, and `:renewal-status`.
- `:read` and `:write` return the lease and auth information with the data.
- `docker-compose.yml` and `vault-up`, `vault-down`, `test-docker`, and
  `cover` make targets.
