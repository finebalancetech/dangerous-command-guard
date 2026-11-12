# Dangerous Command Guard

An [OpenCode](https://opencode.ai) plugin that blocks dangerous shell commands
before they run, explains why in the conversation, and stops the agent until
you intervene.

Built and tested against OpenCode **v2.2.x** (v2.2.7 on macOS, v2.2.5 on Linux).

## What it does

On a command that matches a dangerous pattern (regex list), the guard:

1. **Blocks it** — the command never runs without an explicit human decision.
2. **Explains** — injects a 🚫 *Dangerous Command Guard* message into the
   conversation with the matched category, pattern, the command, and three
   options (allow / skip / revise).
3. **Stops the session** — calls `session.interrupt({ resume: false })` so the
   agent does no further work until you intervene.

```text
🚫 DANGEROUS COMMAND BLOCKED
Category: git
Pattern: git push --force

A message has been added to the conversation. STOP all work and wait for user instructions.
```

## Install

Put the plugin in your OpenCode plugins directory:

```sh
# global plugins
~/.config/opencode/plugins/dangerous-command-guard/
```

Restart OpenCode (or `/reload`) to load it. It logs every command it checks to
`~/dangerous-command-audit.jsonl`.

## Patterns

Patterns live in `~/.config/opencode/dangerous-command-patterns`, one per
line. See [`patterns.example`](patterns.example) for the format and a starting
set. Lines starting with `#` are comments.

```text
# Regex with flags
/rm\s+-[rf]/i
# Plain text (matched as a regex, falls back to a literal match)
git push --force
```

## Behavior notes

- In OpenCode's default ("prompt") permission mode the guard also asks through
  the native permission prompt; either way a matched command is blocked.
- "Accept All" / auto-approve mode does **not** bypass the guard: it force-fails
  the command and stops the session (see the design notes below).
- To allow a specific command permanently, remove its pattern from the patterns
  file, or run it yourself.

## Design notes

See [`VERSION-HISTORY.md`](VERSION-HISTORY.md) for the full history: the v3
force-fail model, the v4 experiment with the permission `evaluate` hook (and why
it cannot beat a client-side "Accept All"), and the recommended v5 design
(chat-based decision + allowlist override).
