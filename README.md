# afauth CLI

> The reference command-line interface for the [AFAuth Protocol](https://github.com/AFAuthHQ/spec) — **Agent-First Auth**, the open protocol that makes AI agents first-class citizens of every service.

Human attention is finite. Agent attention is exploding. AFAuth is how that new attention reaches services — and how your agent reaches every service. `afauth` is the reference agent runtime: a single static binary that generates an identity, signs requests, signs your agent up to any AFAuth-supporting service on its own, and hands off ownership to a human only if you want it to.

## Status

**v0.3.1** (stable). All commands functional, now including the
AFAP-0006 `afauth trust` subcommand. Cross-language conformance gate
(`testdata/spec-vectors/`) green against `AFAuthHQ/spec @ 908892a`.
Released binaries (macOS / Linux / Windows × amd64 / arm64) on the
[releases page](https://github.com/AFAuthHQ/cli/releases).

## Install

```bash
# Homebrew (macOS / Linuxbrew)
brew install afauthhq/tap/afauth

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

# Trust attestor (AFAP-0006) — bind to a human account, mint §10 JWTs
afauth trust link                                # browse to trust.afauth.org, confirm
afauth trust token did:web:tavily.com            # mint an audience-bound JWT
afauth signup --attest "$(afauth trust token did:web:tavily.com)" \
              https://tavily.com                 # use it against an attested_only service
afauth trust status                              # show the cached binding
afauth trust forget                              # delete the local binding
```

`~/.afauth/key.json` is the active keypair (mode 0600).
`~/.afauth/accounts.json` is a local ledger of services this agent has
used; the service remains authoritative. `~/.afauth/trust.json` (mode
0600) holds the trust-attestor binding token if you ran
`afauth trust link`. `$AFAUTH_HOME` overrides all three locations.

## Develop

```bash
make build      # build the binary
make test       # run unit tests
make lint       # run linters (requires golangci-lint)
```

## License

[MIT](LICENSE)
