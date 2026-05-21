# afauth CLI

> The reference command-line interface for the [AFAuth Protocol](https://github.com/AFAuthHQ/spec) — **Agent-First Auth**, the open protocol that makes AI agents first-class citizens of every service.

Human attention is finite. Agent attention is exploding. AFAuth is how that new attention reaches services — and how your agent reaches every service. `afauth` is the reference agent runtime: a single static binary that generates an identity, signs requests, signs your agent up to any AFAuth-supporting service on its own, and hands off ownership to a human only if you want it to.

## Status

**v0.1.0-alpha.** All commands functional. Cross-language conformance
gate (`testdata/spec-vectors/`) green against `AFAuthHQ/spec @ 908892a`.

## Install

```bash
# Homebrew (coming soon)
brew install afauth/tap/afauth

# Direct download
curl -fsSL https://afauth.org/install.sh | sh

# From source
go install github.com/afauthhq/cli/cmd/afauth@latest
```

## Usage

```bash
# Identity
afauth init                              # generate keypair → ~/.afauth/key.json
afauth whoami                            # print did:key:…

# Discovery and generic signed requests
afauth discover https://api.example.com
afauth call https://api.example.com/afauth/v1/accounts/me
afauth call --method POST --data '{"x":1}' https://api.example.com/x

# Account lifecycle
afauth signup https://api.example.com
afauth signup --explicit --terms-version 2026-05-01 https://api.example.com
afauth invite alice@example.com --service https://api.example.com
afauth invite --type oidc --issuer https://accounts.google.com --sub 12345 \
              --service https://api.example.com

# Inspect local state
afauth accounts list
afauth accounts show --refresh https://api.example.com

# Key management
afauth keys rotate --service https://api.example.com
afauth keys export --out backup.json
afauth keys import backup.json

# Conformance probe
afauth probe https://api.example.com
afauth probe --json https://api.example.com | jq .
```

`~/.afauth/key.json` is the active keypair (mode 0600).
`~/.afauth/accounts.json` is a local ledger of services this agent has
used; the service remains authoritative. `$AFAUTH_HOME` overrides both
locations.

## Develop

```bash
make build      # build the binary
make test       # run unit tests
make lint       # run linters (requires golangci-lint)
```

## License

[MIT](LICENSE)
