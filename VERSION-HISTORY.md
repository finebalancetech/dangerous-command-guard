# dangerous-command-guard — version history & design notes

Plugin dir: `~/.config/opencode/plugins/dangerous-command-guard/`
Backup of v3.1.0: `~/.config/opencode-backups/dangerous-command-guard-3.1.0/`
Audit log: `~/dangerous-command-audit.jsonl`
Patterns file: `~/.config/opencode/dangerous-command-patterns`

## v5.0.0 (current) — chat-gate

Goal (from the user): a regex match *always* stops and asks, even with
"Accept All" enabled, and respects the user's decision
(allow / deny / suggest an alternative).

Behavior on a matched dangerous command:

1. logs `pending_approval`,
2. if the exact command was **approved in the chat** (`guard allow <command>`)
   it runs; otherwise
3. injects the 🚫 blocked-message explainer into the conversation
   (`session.prompt` with `resume: false` — the message lands without resuming
   the agent loop; 2.2.7's schema has no `noReply`, `resume: false` is its
   modern equivalent), and
4. calls `session.interrupt({ sessionID, resume: false })` so the agent stops
   doing any other work until the user intervenes, then throws the 🚫 error.

The decision is made **in the chat, not the permission prompt**, so a
client-side "Accept All" (`session.permissions = "autoaccept"`) cannot
auto-approve or bypass it. Approvals are **one-shot**: replying a bare approval
word ("allow", "yes", "go ahead", ...) approves *the most recent blocked
command exactly once* — no need to retype it — and `guard allow <command>`
works as the explicit form. The approval is consumed on first use, so nothing
is ever allowed for the whole session. The prompt hook
(`ctx.session.hook("prompt")`, which exposes the session id) parses the
approval, applies it to the last blocked command (only while it is fresh, 15
minutes), and rewrites the prompt so the agent does not treat the directive as
a task instruction. Quoted/blockquoted message text can never match.

Trade-off: the native once / always / reject permission buttons are gone for
matched commands — the decision is a chat reply. There is no way to keep the
native buttons *and* guarantee the stop under Accept All, because the mode is
not detectable from the plugin API.

## v3.1.0 + "stop session on deny" (superseded by v5)

Behavior model — *force-fail*: a matched dangerous command never runs. On a
match the guard logged `pending_approval`, called `ctx.permission.assert(...)`
(native prompt in "prompt" mode; auto-approved silently in accept-all mode), and
then **always** threw — even when a real human clicked "Allow once/always".
That was deliberate (protect against accept-all auto-approve) but it meant an
explicit approval was ignored, which the user reported as a bug. This is the
reason v5 moved the decision out of the permission system.

The 🚫 message text was ported from v2.0.0.

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
(into the chat), which is the v5 design above.

## Testing

Throwaway harnesses (temp dir) simulate a fake `ctx`
(session.hook/prompt/interrupt, tool.transform) against the plugin to verify:
block → notify + interrupt + throw, `guard allow` parsing + prompt rewrite,
approved command runs, session scoping, benign pass-through. Re-run after any
change to the plugin's setup path.
