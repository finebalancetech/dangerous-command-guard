# dangerous-command-guard — version history & design notes

Plugin dir: `~/.config/opencode/plugins/dangerous-command-guard/`
Backup of v3.1.0: `~/.config/opencode-backups/dangerous-command-guard-3.1.0/`
Audit log: `~/dangerous-command-audit.jsonl`
Patterns file: `~/.config/opencode/dangerous-command-patterns`

## Current state (v3.1.0 + "stop session on deny")

Behavior model — *force-fail*: a matched dangerous command never runs without an
explicit human decision. On a match the guard:

1. logs `pending_approval` to the audit log,
2. calls `ctx.permission.assert(...)` (native once / always / reject prompt in
   default "prompt" permission mode; silently auto-approved in accept-all mode),
3. always throws a `Dangerous command guard blocked` error — even if a rule or
   the client auto-approved the ask.

**Addition since the v3.1.0 backup:** on a deny the guard (1) injects a blocked
message into the conversation (`session.prompt` with `resume: false`, so the
message lands without resuming the agent loop — v2's `noReply` does not exist in
2.2.7 and was silently stripped, `resume: false` is its modern equivalent), and
(2) calls `ctx.session.interrupt({ sessionID, resume: false })` so the agent
stops doing any other work until the user intervenes. Both are applied on both
deny outcomes:

- the user rejected the permission ask (`denied` in the audit log), and
- the force-fail path (`denied_accept_all_or_user_denied`).

The injected message and the thrown error are copied from v2.0.0: the 🚫
**Dangerous Command Guard** explainer with category, matched pattern, the
blocked command, and the "Allow / Skip / Revise" options.

Known limitation (unchanged from v3.1.0): in accept-all mode the permission ask
is auto-approved by the client and the guard force-fails without showing any UI,
so the user cannot review-and-allow from the prompt.

## v4.0.0 (attempted, reverted)

Idea: replace the force-fail with "always stop & ask" by using
`ctx.permission.hook("evaluate")` to escalate any dangerous permission check to
`ask`, so the native once / reject prompt appears in every permission mode.
Plus: a custom `dangerous_command_guard` action for MCP tools, audit logging of
the escalation, and `session.interrupt` on denial.

What worked: in default ("prompt") permission mode the hook escalates matched
commands and the user gets the native prompt (verified in the audit log:
`escalated_to_ask` on `docker system prune -a`, which the user rejected).

What failed — the Accept All problem: "Accept All" in the client is the
`session.permissions = "autoaccept"` setting ("Whether permission requests ask
you or auto accept"). It is client-side: when on, the client auto-approves every
pending permission request without rendering UI. The evaluate hook only changes
the server-side `effect`; it cannot force the client to show UI, and no plugin
API exposes whether autoaccept is on.

Evidence from opencode 2.2.7 internals:

- settings schema: `session.permissions` → `["prompt","autoaccept"]`,
- permission docs: "Non-interactive clients must decide how to handle approval
  requests; configured `deny` rules always remain enforced",
- plugin API surface for permissions is only `hook / list / get / reply / assert`
  — no mode setter. The `set_permission_mode` RPC is client SDK, not exposed to
  plugins, and flipping a server-side mode would not make an autoaccept client
  render the prompt anyway.

Conclusion: under Accept All, `ask` is always swallowed by the client. The only
server-side effect always enforced is `deny`, and `session.interrupt` works
regardless of client mode. Therefore an "always ask" that beats accept-all is
not possible through the permission system — the decision must move outside it
(into the chat), which is the v5 design below.

## v5 (recommended, not implemented)

Goal: *always* stop and ask on a regex match, even with Accept All enabled, and
respect the user's decision (allow / deny / suggest an alternative).

- Keep the evaluate hook → `ask` (nice native prompt in "prompt" mode).
- On match: deny the command (throw with pattern + category + suggested
  alternative) and `session.interrupt({ sessionID, resume: false })` — works in
  every mode because interrupt is not a permission.
- The decision happens in the chat: the user replies to approve, deny, or
  suggest a safer command (e.g. `git push --force-with-lease`).
- Allowlist override so an explicit approval is honored: watch user messages via
  `ctx.session.hook("context")` (same mechanism the jev-router plugin uses; note
  the context event does not expose a session id, so attribute to the active
  session when unambiguous). A reply like `guard allow <command>` stores the
  command hash for the session and lets the next attempt run.

Trade-off: in "prompt" mode the native once / always / reject buttons are lost —
the decision moves to the chat. There is no way to keep the native buttons *and*
guarantee the stop under Accept All, because the mode is not detectable from the
plugin API.

## Testing

A throwaway harness (`guard-v4-test.mjs`, temp dir) simulates a fake `ctx`
(permission.hook/assert, tool.transform, session.interrupt) against the plugin
to verify: hook escalation, deny respect, native gate for `shell`, guard assert
for non-shell tools, deny → interrupt, safe pass-through. Re-run it after any
change to the plugin's setup path.
