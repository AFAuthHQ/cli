# afauth CLI

> The reference command-line interface for the [AFAuth Protocol](https://github.com/afauth/spec).

`afauth` lets agents generate a keypair, sign HTTP requests, sign up to AFAuth-enabled services, and hand off accounts to humans — from a single static binary.

## Status

**v0.0.1 — Pre-alpha.** Not yet functional. Command scaffolding only.

## Install

```bash
# Homebrew (coming soon)
brew install afauth/tap/afauth

# Direct download (coming soon)
curl -fsSL https://afauth.org/install.sh | sh

# From source
go install github.com/afauth/cli/cmd/afauth@latest
```

## Usage

```bash
# Identity
afauth init                              # generate keypair → ~/.afauth/key.json
afauth whoami                            # print did:key:…

# Use any AFAuth-enabled service
afauth call https://api.example.com/things
afauth signup https://api.example.com

# Hand off to a human
afauth invite alice@example.com --service api.example.com

# Run as an MCP server (for Claude Desktop, Cursor, etc.)
afauth mcp

# Inspect
afauth accounts list
afauth keys rotate
```

## Develop

```bash
make build      # build the binary
make test       # run unit tests
make lint       # run linters (requires golangci-lint)
```

## License

[MIT](LICENSE)
