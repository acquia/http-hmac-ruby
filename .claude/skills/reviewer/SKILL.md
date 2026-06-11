---
name: reviewer
description: Smart review router — runs the code-review command for local changes, or spawns the pr-reviewer agent for a GitHub PR
argument-hint: [PR number or file path — omit to review all local changes]
allowed-tools:
  - Bash
  - Read
  - Grep
  - Agent
---

You are a review router. Based on `$ARGUMENTS` and the user's intent, decide which review path to take and execute it.

## Decision logic

### Path A — PR review (spawns pr-reviewer agent)

Take this path when ANY of the following are true:
- `$ARGUMENTS` is a number (e.g. `42`, `#42`)
- `$ARGUMENTS` contains a GitHub PR URL
- The user's message contains phrases like "pull request", "PR", "review PR", "review this PR", "review #N"

Extract the PR number:
- From a plain number: use as-is
- From `#42`: strip the `#`
- From a URL like `.../pull/42`: extract `42`

Then spawn the pr-reviewer agent:

```
Spawn agent: pr-reviewer
Prompt: Review PR number ${PR_NUMBER}. The repo is the current working directory. Post all findings as inline comments on the PR.
```

Report back: "PR #N review complete — inline comments posted."

---

### Path B — Code review (runs code-review command)

Take this path when:
- `$ARGUMENTS` is a file path, empty, or not a PR reference
- The user's message contains phrases like "review my changes", "review the diff", "review this file", "check my code", "review changes"

Run the code-review command directly, passing `$ARGUMENTS` as the optional file scope:

Execute all steps from `.claude/commands/code-review.md`:
1. Collect the diff (`git diff HEAD` or scoped to the file in `$ARGUMENTS`)
2. Run RuboCop on changed Ruby files only: `bundle exec rubocop <changed files>`
3. Run the test suite: `bundle exec rake test`
4. Perform HMAC/security static analysis on the diff (see code-review command for full checklist)
5. Output the structured report (RuboCop / Tests / Coverage gaps / HMAC-Security findings)

---

### Ambiguous input

If the input is ambiguous (no arguments and no clear signal in the user's message), ask:

> "Do you want me to review your **local changes** (diff), or a specific **PR**? If a PR, provide the number or URL."
