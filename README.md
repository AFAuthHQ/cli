# afauth CLI

> The reference command-line interface for the [AFAuth Protocol](https://github.com/AFAuthHQ/spec) — **Agent-First Auth**, the open protocol that makes AI agents first-class citizens of every service.

Human attention is finite. Agent attention is exploding. AFAuth is how that new attention reaches services — and how your agent reaches every service. `afauth` is the reference agent runtime: a single static binary that generates an identity, links once to a human at [trust.afauth.org](https://trust.afauth.org) so spam-resistant services accept it, signs your agent up to any AFAuth-supporting service on its own, and hands off ownership to a human later if you want it to.

## Status

**v0.6.1** (stable). Security hardening: the signed-request, discovery,
and trust-attestor clients now refuse cross-origin redirects — a 30x can
no longer harvest a live `AFAuth-Attestation` JWT or `Signature` header —
and auto-attest binds the attestation audience to the discovery origin, so
a `did:web` service DID MUST be anchored at the host that served its
discovery document before a token is minted (confused-deputy guard). All
commands functional, including keyless trust mint (§3.1), `afauth status`
(identity + attestor linkage), and §10.7 attested-session refresh in
`afauth call --attest`. Cross-language conformance gate
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

### Quick start

```bash
afauth init                                 # 1. generate keypair → ~/.afauth/key.json
afauth trust link                           # 2. bind to a human at trust.afauth.org (one-time)
afauth signup https://api.example.com       # 3. sign up — auto-mints an attestation when the
                                            #    service declares attested_only (most do)
afauth call https://api.example.com/afauth/v1/accounts/me   # 4. signed requests thereafter
```

Step 2 is required for `attested_only` services; skip it and `afauth signup` exits with a prompt to run `afauth trust link` first.

### All commands

```bash
# Identity
afauth init                              # generate keypair → ~/.afauth/key.json
afauth whoami                            # print did:key:… (bare, for scripts)
afauth status                            # identity + attestor linkage + accounts (human)
afauth status --json                     # same, machine-readable

# Discovery and generic signed requests
afauth discover https://api.example.com
afauth call https://api.example.com/afauth/v1/accounts/me
afauth call --method POST --data '{"x":1}' https://api.example.com/x
# attested_only services: `call` auto-mints + retries once on a §10.7
# attestation_required challenge; --attest <jwt> attaches one up front

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
afauth trust link --base https://acme-trust.com  # link a DIFFERENT / self-hosted attestor
afauth signup https://tavily.com                 # auto-mints attestation when the service
                                                 # declares attested_only, picking the
                                                 # attestor the service accepts; exits with
                                                 # an `afauth trust link` prompt if none —
                                                 # or, if you're linked to an attestor the
                                                 # service doesn't accept, names which ones
                                                 # it does so you can re-link.
afauth signup --attestor acme-trust https://…    # force a specific linked attestor
afauth trust token did:web:tavily.com            # mint an audience-bound JWT manually
afauth trust token --attestor acme-trust did:web:…  # …from a specific attestor
afauth trust status                              # show the cached binding(s)
afauth trust forget [--attestor <iss|url>]       # delete one (or all) local bindings
```

`~/.afauth/key.json` is the active keypair (mode 0600).
`~/.afauth/accounts.json` is a local ledger of services this agent has
used; the service remains authoritative. `~/.afauth/trust.json` (mode
0600) holds your trust-attestor binding(s) — an agent can link to more
than one attestor, and `signup`/`call` pick the one a service accepts
(its `billing.accepted_attestors`), or `--attestor` chooses explicitly.
`$AFAUTH_HOME` overrides all three locations.

## Develop

```bash
make build      # build the binary
make test       # run unit tests
make lint       # run linters (requires golangci-lint)
```

## License

[MIT](LICENSE)
