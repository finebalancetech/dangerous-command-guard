import { readFile, appendFile } from 'fs/promises';
import { homedir } from 'os';
import { join } from 'path';

const CONFIG_DIR = join(homedir(), '.config/opencode');
// Both spellings are accepted: the current file has no leading dot, older
// versions of the plugin looked for a dotted name.
const PATTERNS_FILES = [
  join(CONFIG_DIR, 'dangerous-command-patterns'),
  join(CONFIG_DIR, '.dangerous-command-patterns'),
];
const AUDIT_LOG = join(homedir(), 'dangerous-command-audit.jsonl');

// Log every tool call, not just dangerous ones
const LOG_SAFE_COMMANDS = true;

/**
 * After a dangerous command is denied, stop the session so the agent does not
 * continue with any other work until the user intervenes. `resume: false`
 * keeps the agent stopped; the user resumes it explicitly. Best-effort: a
 * failure here must never break the guard flow.
 */
async function maybeStopSession(ctx, sessionID) {
  if (!sessionID) return;
  try {
    await ctx.session.interrupt({ sessionID, resume: false });
  } catch (e) {}
}

/**
 * Detailed message injected into the conversation when a command is blocked.
 * Copied from v2.0.0.
 */
function formatBlockedMessage(dangerous, toolID) {
  const { name, category, command } = dangerous;
  return [
    '🚫 **Dangerous Command Guard** *(plugin)*',
    '',
    `**Category:** ${category}`,
    `**Pattern matched:** ${name}`,
    `**Tool:** ${toolID}`,
    '',
    '```',
    command,
    '```',
    '',
    'This command has been blocked because it matches a dangerous pattern.',
    '',
    '**What would you like to do?**',
    '1. **Allow this specific command** — re-run it yourself, or edit the patterns file',
    '2. **Skip this task** — stop working on this approach entirely',
    '3. **Revise the approach** — use a safer method to achieve the same goal',
  ].join('\n');
}

/**
 * Best-effort injection of a message into the conversation (no model reply).
 * Uses session.prompt with resume:false — the message lands in the
 * conversation without scheduling agent-loop execution (2.2.7 schema has no
 * `noReply`; v2's was silently stripped). Failure here must never prevent the
 * block.
 */
async function notifySession(ctx, sessionID, text) {
  const attempts = [
    { label: 'flat-resume-false', args: { sessionID, text, resume: false } },
    { label: 'flat', args: { sessionID, text } },
    { label: 'path-id-resume-false', args: { path: { id: sessionID }, text, resume: false } },
  ];
  const errors = [];
  for (const { label, args } of attempts) {
    try {
      await ctx.session.prompt(args);
      await logToAudit({ status: 'notified', shape: label });
      return true;
    } catch (e) {
      errors.push(`${label}: ${String(e && e.message).replace(/\s+/g, ' ')}`);
    }
  }
  await logToAudit({ status: 'notify_error', error: errors.join(' | ') });
  return false;
}

const DEFAULT_PATTERNS = [
  // Shell / filesystem destruction
  { pattern: /rm\s+-[rf]/i, name: 'rm -rf (recursive delete)', category: 'shell' },
  { pattern: /rm\s+-rf\s*\/(?:home|root|etc|usr|var|opt)/i, name: 'rm -rf on system directory', category: 'shell' },
  { pattern: /dd\s+of=\/dev/i, name: 'dd disk wipe', category: 'shell' },
  { pattern: /mkfs(\.|\s)/i, name: 'mkfs (filesystem format)', category: 'shell' },
  { pattern: /chmod\s+-R\s*777/i, name: 'chmod -R 777 (dangerous permissions)', category: 'shell' },
  { pattern: />\s*\/dev\/[sh]d[a-z]/i, name: 'write to raw block device', category: 'shell' },
  { pattern: /:\(\)\s*\{\s*:\|:&\s*\}\s*;\s*:/, name: 'bash fork bomb', category: 'shell' },
  { pattern: /:\s*\|.*>&-/i, name: 'bash fork bomb', category: 'shell' },
  { pattern: /curl[^|]*\|\s*(sudo\s+)?(ba)?sh/i, name: 'curl piped into shell', category: 'shell' },

  // SQL destruction
  { pattern: /DROP\s+TABLE/i, name: 'DROP TABLE', category: 'sql' },
  { pattern: /DROP\s+DATABASE/i, name: 'DROP DATABASE', category: 'sql' },
  { pattern: /DROP\s+SCHEMA/i, name: 'DROP SCHEMA', category: 'sql' },
  { pattern: /TRUNCATE\s+TABLE/i, name: 'TRUNCATE TABLE', category: 'sql' },
  { pattern: /DELETE\s+FROM\s+\w+\s*(?:WHERE\s+1=1|;|\s*$)/i, name: 'DELETE FROM (dangerous)', category: 'sql' },
  { pattern: /DELETE\s+FROM\s+\w+\s*(?:"|'|\s*$)/i, name: 'DELETE FROM (no WHERE clause)', category: 'sql' },
  { pattern: /ALTER\s+TABLE\s+\w+\s+DROP/i, name: 'ALTER TABLE DROP', category: 'sql' },

  // Git destruction
  { pattern: /git\s+push\s+(--force|-f)(\s|$)/i, name: 'git push --force', category: 'git' },
  { pattern: /git\s+push\s+[^\s]*--force-with-lease/i, name: 'git push --force-with-lease', category: 'git' },
  { pattern: /git\s+branch\s+-D/i, name: 'git branch -D (force delete)', category: 'git' },
  { pattern: /git\s+reset\s+--hard/i, name: 'git reset --hard', category: 'git' },
  { pattern: /git\s+clean\s+-[a-z]*f/i, name: 'git clean -f (untracked file delete)', category: 'git' },

  // Docker destruction
  { pattern: /docker\s+rm\s+-[a-z]*f/i, name: 'docker rm -f', category: 'docker' },
  { pattern: /docker\s+rmi\s+-[a-z]*f/i, name: 'docker rmi -f', category: 'docker' },
  { pattern: /docker\s+volume\s+rm\s/i, name: 'docker volume rm', category: 'docker' },
  { pattern: /docker\s+system\s+prune\s+-a/i, name: 'docker system prune -a', category: 'docker' },
  { pattern: /docker\s+compose\s+down\s+(-v|--volumes)/i, name: 'docker compose down -v (volume delete)', category: 'docker' },
];

/**
 * Read dangerous patterns from the patterns file, falling back to the defaults.
 * Two line formats are supported:
 *   /regex/flags  -> compiled verbatim
 *   plain text    -> compiled as a regex, falling back to a literal match
 * Blank lines and lines starting with # are ignored.
 * @returns {Promise<{patterns: Array, source: string, error: string|null}>}
 */
async function getDangerousPatterns() {
  let content;
  let usedPath = null;
  let lastErr = null;
  for (const file of PATTERNS_FILES) {
    try {
      content = await readFile(file, 'utf-8');
      usedPath = file;
      break;
    } catch (e) {
      lastErr = e;
    }
  }
  if (content === undefined) {
    return {
      patterns: DEFAULT_PATTERNS,
      source: 'defaults (patterns file unreadable)',
      error: String(lastErr && lastErr.message),
    };
  }

  const lines = content
    .split('\n')
    .map(l => l.trim())
    .filter(l => l && !l.startsWith('#'));

  const patterns = [];
  const parseErrors = [];

  for (const line of lines) {
    try {
      let patternStr = line;
      let flags = 'i';
      const m = line.match(/^\/(.+)\/([gimuy]*)$/);
      if (m) {
        patternStr = m[1];
        flags = m[2] || 'i';
      }
      patterns.push({ pattern: new RegExp(patternStr, flags), name: `Custom pattern: ${line}`, category: 'custom' });
    } catch (e) {
      // Bad regex -> treat the line as a literal string instead
      try {
        const literal = line.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        patterns.push({ pattern: new RegExp(literal, 'i'), name: `Literal: ${line}`, category: 'custom' });
      } catch {
        parseErrors.push({ line, error: String(e && e.message) });
      }
    }
  }

  if (patterns.length === 0) {
    return { patterns: DEFAULT_PATTERNS, source: 'defaults (file had no usable patterns)', error: null };
  }
  return {
    patterns,
    source: `file (${usedPath})`,
    error: parseErrors.length ? JSON.stringify(parseErrors) : null,
  };
}

/**
 * Return the first dangerous pattern that matches the command, else null.
 * Resets lastIndex so a custom /g pattern cannot skip matches.
 */
function findDangerousPattern(command, patterns) {
  if (!command || typeof command !== 'string') return null;
  for (const { pattern, name, category } of patterns) {
    if (pattern.global || pattern.sticky) pattern.lastIndex = 0;
    if (pattern.test(command)) return { name, category, command };
  }
  return null;
}

/**
 * Standard audit fields for every entry.
 */
function makeAuditEntry(toolID, context, extra = {}) {
  return {
    sid: context?.sessionID ?? null,
    cid: context?.callID ?? context?.messageID ?? null,
    tool: toolID,
    ...extra,
  };
}

/**
 * Best-effort audit append. Failures here must never break the guard flow.
 */
async function logToAudit(entry) {
  try {
    await appendFile(AUDIT_LOG, JSON.stringify({ ts: new Date().toISOString(), ...entry }) + '\n', 'utf-8');
  } catch (e) {}
}

export default {
  id: 'dangerous-command-guard',
  async setup(ctx) {
    const wrapped = [];

    await ctx.tool.transform((editor) => {
      for (const tool of editor.list()) {
        const originalExecute = tool.execute;
        const toolID = tool.id;

        editor.update(toolID, (t) => {
          t.execute = async (input, context) => {
            const raw = input.command || input.args || input.cmd || input.script || '';
            const command = (Array.isArray(raw) ? raw.join(' ') : String(raw ?? '')).toString();

            const { patterns, source, error: patternErr } = await getDangerousPatterns();
            const match = findDangerousPattern(command, patterns);

            if (match) {
              const sessionID = context?.sessionID;

              // Log the match
              await logToAudit(makeAuditEntry(toolID, context, {
                cmd: command,
                matchedPattern: match.name,
                category: match.category,
                status: 'pending_approval',
                patternSource: source,
                patternFileError: patternErr,
              }));

              if (!sessionID) {
                await logToAudit(makeAuditEntry(toolID, context, { status: 'blocked_no_session', pattern: match.name, category: match.category }));
                throw new Error(`Dangerous command blocked: ${match.name} (category: ${match.category}). No session context available to request permission.`);
              }

              // 1. explain in the conversation, 2. stop the agent flow, 3. fail the tool.
              await notifySession(ctx, sessionID, formatBlockedMessage(match, toolID));

              // Ask through OpenCode's native permission service instead of failing outright.
              // - deny  -> throws BlockedError (tool fails closed)
              // - ask   -> awaits the user's once / always / reject reply
              // - allow -> resolves, and we fall through to the real execution
              const invocationSource = context?.messageID && context?.id ? { type: 'tool', messageID: context.messageID, id: context.id } : undefined;
              try {
                await ctx.permission.assert({
                  sessionID,
                  action: toolID,
                  resources: [command],
                  metadata: { pattern: match.name, category: match.category, tool: toolID, cmd: command },
                  ...(invocationSource ? { source: invocationSource } : {}),
                });
              } catch (err) {
                // User rejected the permission ask. Stop the session so the agent
                // does not keep working until the user intervenes, then rethrow.
                await logToAudit(makeAuditEntry(toolID, context, {
                  status: 'denied', pattern: match.name, category: match.category, cmd: command,
                  reason: String(err?.message ?? err),
                }));
                await maybeStopSession(ctx, sessionID);
                throw err;
              }
              // Dangerous commands must not run unless explicitly permitted by a human.
              // Accept-all / unattended auto-approves permission asks, so enforce the
              // deny here to keep the guard effective even in accept-all mode. Stop
              // the session so the agent does not continue with other work.
              await logToAudit(makeAuditEntry(toolID, context, { status: 'denied_accept_all_or_user_denied', pattern: match.name, category: match.category, cmd: command }));
              await maybeStopSession(ctx, sessionID);
              throw new Error(
                `🚫 DANGEROUS COMMAND BLOCKED\n` +
                `Category: ${match.category}\n` +
                `Pattern: ${match.name}\n\n` +
                `A message has been added to the conversation. STOP all work and wait for user instructions.`,
              );
            }

            // Safe command (or a tool with no command text / an allowed dangerous command)
            if (LOG_SAFE_COMMANDS) {
              if (command) {
                await logToAudit(makeAuditEntry(toolID, context, { cmd: command, blocked: false }));
              } else {
                await logToAudit(makeAuditEntry(toolID, context, { blocked: false, args: input }));
              }
            }

            const result = await originalExecute(input, context);

            await logToAudit(makeAuditEntry(toolID, context, {
              blocked: false,
              status: 'success',
              output_size: result?.output ? result.output.length : 0,
            }));

            return result;
          };
        });

        wrapped.push(toolID);
      }
    });

    await logToAudit({
      status: 'loaded',
      wrappedTools: wrapped,
      logSafeCommands: LOG_SAFE_COMMANDS,
    });
  },
};
