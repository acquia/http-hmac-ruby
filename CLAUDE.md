# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Install dependencies
bundle install

# Run all tests and RuboCop
bundle exec rake

# Run tests only
bundle exec rake test

# Run a single test file
bundle exec ruby test/httphmac_test.rb

# Run a specific test method
bundle exec ruby test/httphmac_test.rb -n test_prepare_request_get

# Run RuboCop linter
bundle exec rake rubocop
```

## Architecture

This is a Ruby gem (`acquia-http-hmac`) implementing [Acquia's HTTP HMAC Spec 2.0](https://github.com/acquia/http-hmac-spec/tree/2.0). It has two layers:

**Core signing library** (`lib/acquia_http_hmac.rb`): The `Acquia::HTTPHmac::Auth` class handles all cryptographic operations. It signs requests with `prepare_request_headers`, verifies incoming requests with `request_authenticated?`, and verifies signed responses with `response_authenticated?`. The HMAC-SHA256 base string is assembled in a specific order by `prepare_base_string`: HTTP method, host (lowercased), path, query string, auth parameters (`id=...&nonce=...&realm=...&version=...`), any custom headers (sorted, lowercased), timestamp, and optionally content-type + body SHA256 for requests with bodies. Secrets are stored and accepted as base64-encoded strings.

**Rack middleware** (`lib/acquia-http-hmac/rack_authenticate.rb`): `Acquia::HTTPHmac::RackAuthenticate` wraps a Rack app and enforces HMAC authentication on every request. After verifying a request, it signs the response by adding `X-Server-Authorization-HMAC-SHA256` (signed over `"#{nonce}\n#{timestamp}\n#{body}"`). It passes the authenticated client's id and data downstream via `env['ACQUIA-HTTP-HMAC-ID']` and `env['ACQUIA-HTTP-HMAC-DATA']`.

**Password storage interface**: The middleware takes a `password_storage` object that must implement `valid?(id)`, `password(id, timestamp)`, and `data(id)`. Three implementations are provided:
- `SimplePasswordStorage` — in-memory hash
- `FilePasswordStorage` — YAML file (used in tests via `fixtures/passwords.yml`)
- `SQLite3PasswordStorage` (`lib/acquia-http-hmac/sqlite3_password_storage.rb`) — date-based rotating credentials from SQLite

**Nonce checking interface**: The middleware also takes a `nonce_checker` implementing `valid?(id, nonce)`. `NoopNonceChecker` only validates UUID format; `MemoryNonceChecker` additionally prevents replay attacks by tracking seen nonces in a class variable.

## Tests

Tests use Minitest. `test/helpers/rack_app_test_base.rb` is a shared module (`TestRackAppBase`) included by both `rack_simple_app_test.rb` and `rack_sqlite3_app_test.rb` — it defines the full suite of Rack integration tests and a helper `app` method that assembles the middleware stack with `Example::App` (the Grape app in `example/app.rb`). The fixture-driven test in `test/acquia_spec_test.rb` validates against `fixtures/acquia_spec.json`, the canonical cross-language compliance fixtures from the HMAC spec repo.

## Key behavior notes

- Custom headers included in signing must be listed in `headers:` arg (keys only); their values are stripped of leading/trailing whitespace before signing, so header values with surrounding spaces still match.
- Clock skew tolerance defaults to 900 seconds (15 minutes); tests can override via `allowed_skew`.
- The `excluded_paths` middleware option accepts path prefixes and bypasses auth for matching paths (used for `/healthcheck`).
