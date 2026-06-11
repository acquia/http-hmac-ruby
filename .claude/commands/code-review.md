---
name: code-review
description: Review changed Ruby files for RuboCop violations, test failures, and HMAC/security issues specific to this gem
argument-hint: [optional file path to scope the review, e.g. lib/acquia_http_hmac.rb]
allowed-tools:
  - Bash
  - Read
  - Grep
---

Review the current changes in this repository for correctness, style, and security issues. Follow the steps below in order and produce a structured report at the end.

## Step 1 — Collect the diff

```bash
git diff HEAD
```

If `$ARGUMENTS` is provided and names a file, run:
```bash
git diff HEAD -- $ARGUMENTS
```

If `git diff HEAD` is empty (all changes are staged), run:
```bash
git diff --cached
```

Also collect the list of changed Ruby files:
```bash
git diff HEAD --name-only --diff-filter=ACM | grep '\.rb$'
```

## Step 2 — RuboCop

Run RuboCop on the changed Ruby files only (use the list from Step 1). The project's `.rubocop.yml` defines the thresholds — do not flag anything within those limits.

```bash
bundle exec rubocop $(git diff HEAD --name-only --diff-filter=ACM | grep '\.rb$' | tr '\n' ' ')
```

Note any violations with `file:line` and whether they are auto-correctable (`[A]`).

If there are no changed Ruby files, skip this step.

## Step 3 — Test suite

```bash
bundle exec rake test 2>&1
```

Report any failures or errors verbatim. If all tests pass, note that.

Also check whether any method that was modified in the diff has a corresponding `test_<method_name>` in `test/`. List any changed public methods that lack test coverage.

## Step 4 — HMAC domain and security review

Analyze the diff statically for the following issues. Only report items that appear in the diff.

**Base string ordering (`lib/acquia_http_hmac.rb` — `prepare_base_string`)**
Any change to field order breaks cross-language compatibility. The required order is:
1. `http_method`
2. `host` (must be downcased)
3. `path_info`
4. `query_string`
5. Auth params string: `id=...&nonce=...&realm=...&version=...`
6. Custom headers — each as `name_lowercased:value_stripped`, sorted by lowercased key
7. `timestamp`
8. If body present: `content_type_lowercased` then `body_hash`

Flag any reordering, removal, or conditional wrapping of these fields.

**Timing-safe comparison**
`signature(base_string) == args[:signature]` (and similar) compares HMAC output with `==`. This is a known timing oracle. Flag any NEW `==` comparisons against a computed HMAC or secret value. Recommend `OpenSSL.fixed_length_secure_compare` for production hardening (note: the existing comparisons in `request_authenticated?` and `response_authenticated?` are pre-existing — only flag new ones added in the diff).

**Secret handling**
`@secret` is set from `Base64.decode64(base64_secret)` in `Auth#initialize`. Flag if:
- `@secret` is returned, logged, or appears in an exception message
- A new constructor bypasses the Base64 decode

**Nonce validation**
The UUID regex `/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}/` in `request_authenticated?` must not be weakened. Flag any change that relaxes the pattern or replaces it with a simpler length check.

**Rack contract (`lib/acquia-http-hmac/rack_authenticate.rb`)**
- `call(env)` must always return `[Integer, Hash, #each]`
- After `request.body.read`, `request.body.rewind` must be called if the body IO responds to it — this allows downstream middleware to read the body again
- Any early return path (401, 403) must return a valid three-element array

**Class variable thread safety**
`SimplePasswordStorage` and `MemoryNonceChecker` use `@@creds` and `@@seen` respectively. These are shared across all instances and threads. Flag any change to these classes that introduces a write without a mutex, or that adds new `@@` variables.

**Password storage interface**
Any new class claiming to implement password storage must provide all three methods: `valid?(id)`, `password(id, timestamp)`, `data(id)`. Flag missing methods.

**Nonce checker interface**
Any new nonce checker must implement `valid?(id, nonce)`. Flag missing methods.

## Step 5 — Report

Output findings in this format:

```
## RuboCop
PASS  (or list violations as `file:line  CopName  [A]  message`)

## Tests
PASS  (or paste failure output)

## Coverage gaps
- `MethodName` in `file.rb` — no test_method_name found in test/

## HMAC / Security findings
HIGH   | description | file:line
MEDIUM | description | file:line
LOW    | description | file:line
```

If a section has no findings, write `PASS` or `None`. Keep descriptions to one line each.
