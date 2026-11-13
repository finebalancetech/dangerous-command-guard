# Dangerous Command Guard

An [OpenCode](https://opencode.ai) plugin that blocks dangerous shell commands
before they run, explains why in the conversation, and stops the agent until
you decide.

Built and tested against OpenCode **v2.2.x** (v2.2.7 on macOS, v2.2.5 on Linux).

## What it does

On a command that matches a dangerous pattern (regex list), the guard:

1. **Blocks it** — the command never runs unless you explicitly allow it.
2. **Explains** — injects a 🚫 *Dangerous Command Guard* message into the
   conversation with the matched category, pattern, and the command.
3. **Stops the session** — calls `session.interrupt({ resume: false })` so the
   agent does no further work until you decide.

```text
🚫 DANGEROUS COMMAND BLOCKED
Category: shell
Pattern: umount

A message has been added to the conversation. Reply `allow` to run this command
once, or STOP all work and wait for user instructions.
```

## Approving a blocked command

The decision happens **in the chat** — not the native permission prompt — so a
client-side "Accept All" / auto-approve mode cannot bypass it.

To run the blocked command exactly once, reply with a bare approval word:

```
allow        allow it     approve     approved    allowed
ok           okay         yes         yep         yeah
go ahead     run it       run it anyway   do it   fine
sure         let it run
```

The approval applies to the **most recent blocked command** in that session,
works only while the block is fresh (15 minutes), and is **consumed on first
use** — the same command is blocked again on the next attempt. Nothing is ever
allowed for the whole session. `guard allow <command>` also works as the
explicit form, and is one-shot too.

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

Note: patterns match against the command *text*, so a pattern like `/umount/i`
also trips on commands that merely contain the word (e.g. grepping the audit
log for "umount").

## Design notes

See [`VERSION-HISTORY.md`](VERSION-HISTORY.md) for the full history: the v3
force-fail model (which ignored approvals on purpose to defend against
Accept All), the v4 experiment with the permission `evaluate` hook (and why it
cannot beat a client-side "Accept All"), and the v5 chat-gate (why the decision
moved into the chat, and the one-shot approval model).
