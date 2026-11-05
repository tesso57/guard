# guard

An extension for the [pi coding agent](https://github.com/badlogic/pi-mono). guard judges every tool call **before it runs** and decides whether to allow it, ask you to confirm it, or block it.
It uses the [OpenAI Decisions API](https://platform.openai.com/docs/guides/decisions) (`gpt-6-luna`) for the judgement, and it remembers the decisions you make as rules.

> guard is not a sandbox. It is a layer that stops obviously dangerous actions while cutting down on approval prompts. When you work with untrusted code, run pi inside a container or VM as well.

## Install

```bash
pi install git:github.com/tesso57/guard
```

Set `GUARD_OPENAI_API_KEY`, then start pi:

```bash
export GUARD_OPENAI_API_KEY=sk-...
```

This key is used only by guard, independently of pi's `OPENAI_API_KEY`. guard does not fall back to `OPENAI_API_KEY`.

Without a key, guard runs in **rules-only mode**: the deterministic checks and your remembered rules still apply, and every call that would need a model judgement asks you first (or is blocked in modes without a UI).

## How a call is judged

| Order | Check | Result |
|---|---|---|
| 1 | Hard deny: recursive deletion of `/`, `~` or system directories, `curl … \| sh`, writes to `authorized_keys`, and **any change to guard's rules, pi's state and session logs, or the project resources pi loads (`.pi/`, `.agents/`)** | Block. No rule or dialog can override it |
| 2 | Deny and ask rules, in any scope | Block / confirm |
| 3 | Allow rules. For bash, every subcommand must match and the command must have no dynamic parts such as `$()` or variable expansion | Allow, after a light check for exfiltration, actions outside your request, and text aimed at the judge |
| 4 | Sensitive paths (`~/.ssh`, `.env`, key files, `/proc/*/environ`, …, after resolving symlinks and globs), printing the environment, and content searches across `~` | Confirm |
| 5 | Safe list, which only covers reads **inside the project** (or public system directories such as `/usr`): read-only bash commands (judged by command **and options**, so `git log --output=…` or `sort -o` are not read-only; read-only `git` only in trusted repositories whose `.git/config` runs no commands, and never after `cd`), `mkdir`/`touch` of ordinary project paths, and edits to ordinary files inside the project | Allow, without calling the API |
| 6 | Decisions API | Allow / confirm / block |

By default, the built-in read tools (`read`, `grep`, `find`, `ls`) skip the model only for paths inside the project or public system directories such as `/usr`; elsewhere they are judged like any other call. `read` must name an existing file to use this shortcut. Paths are resolved using pi's path conventions (`file://` URLs, `~`, unicode spaces). Project and home directory aliases such as macOS's `/var` → `/private/var` are recognized, symlinks are followed even when their target does not exist yet, and `..` is applied after symlinks as the kernel does. When pi runs in your home directory (or above), nothing counts as a plain project read or edit.

If the API call fails, the model refuses to answer, or the input had to be truncated, guard takes the safe side: it asks you to confirm, or blocks the call when there is no UI.

guard sends the Decisions API:

- your most recent messages, so the model knows what you asked for
- the agent's recent tool calls
- your past decisions
- the call being judged

It never sends the assistant's own text or tool outputs. This limits prompt injection. File contents guard attaches are passed as an untrusted tool output, never as your words. When bash runs a script that was written or edited earlier, guard attaches what the script will contain, including changes made by earlier calls in the same assistant message that have not run yet. Running a file changed earlier in the same message requires confirmation even if the model would otherwise allow it; changes from earlier messages force a full judgement but do not always require confirmation. When a test runner, build tool or interpreter (`npm`, `pytest`, `make`, `python`, `sh`, …) runs, guard collects the script it is given, known project files changed in this session, and up to 20 project files changed in the last day. Known session changes or changes guard cannot enumerate (such as a checkout) force a full judgement, even if an allow rule matches. Attachments are limited to 20 files and a 200,000-character budget; if collected attachments exceed those limits, guard asks for confirmation. Files larger than the per-field limit are truncated, which also requires confirmation.

As soon as an assistant message ends, guard starts assessing its tool calls in parallel, calling the model only where needed. pi judges every call of a message before it runs any of them, so when an earlier call in the same message may change files in ways guard cannot safely predict, later calls get no shortcuts: no safe list, no skipped model, no allow rule without a full judgement. Plain edits to ordinary project files and safe `mkdir`/`touch` calls do not disable these shortcuts, except when they change search ignore files. guard repeats every deterministic check at `tool_call` and reuses the model's verdict only if the input and attachments are unchanged.

Recursive content searches (`grep -r` in any spelling, `rg`, `git grep`, pi's `grep` tool) ask first when the searched tree contains `.env` files or keys, and are judged by the model when the tree is too large to check. Extracting archives where `.pi/` or `.agents/` could be created also asks first. Files that likely hold secrets are never sent to the judge; guard sends only their names.

Commands that change things are blocked whenever they name guard's state or a directory containing it, whatever wrapper comes first (`time -p`, `setarch`, `fakeroot`), however the shell gets there (`cd` through wildcards or `CDPATH`, `pushd`/`popd`, `OLDPWD`, `git -C`, `npm --prefix`, brace expansion), and including links (`ln`, `cp -l`) that would let a later plain write reach it. Command-like arguments of other tools (powershell, MCP shells) get the same check. A project's own `.pi/` is protected from writes, but does not block commands such as `git add .` or `prettier --write .`. Options with glued path values (`-f/etc/x`), the directory stack (`pushd`, `popd`), here-documents, pagers, and wildcards that match names starting with `-` (which the command would read as options) never count as safe; creating files with such names is never a plain edit. Wildcards are expanded like bash, through symlinked directories. File contents written with `write`/`edit` are data and are not scanned as commands; running them later is judged then.

Where guard cannot pin something down, it errs on the side of blocking: wildcards are matched against guard's state as patterns (so a skipped or truncated expansion cannot hide them), commands that change `HOME`, `CDPATH` or `OLDPWD` are blocked, and a changing command whose working directory guard cannot determine is blocked. Patches (`git apply`, `git am`, `patch`) are read to see which files they change; a patch guard cannot read asks first.

When an earlier call in the same message may swap whole directories (`git checkout`, `git pull`, extracting archives, `cp`, `rsync`, package installs), later calls that write ask you first, because neither guard nor the model can see what those directories will contain. Strings that look like secrets are redacted before anything is sent.

Risk is scored on five levels, from 0 to 4. guard looks at the probability of the high-risk levels as well as the weighted average, so a split such as "45% catastrophic, 55% harmless" is still caught.

## Approval dialog

```
Allow (this time only)
Allow (this session: npm install …)
Allow and remember… ▸     → this project / global
Deny
Deny and remember… ▸      → this project / global / this session
```

- When you remember a decision, guard shows an example that matches the rule and one that does not. For example, `npm test …` matches `npm test -- foo` but not `npm publish`.
- Only tools with subcommands (`git`, `npm`, `cargo`, `make`, …) get prefix rules. Other commands take paths or data as arguments, so `cp a b` is remembered exactly. Script runners keep the script name (`npm run lint` does not cover `npm run deploy`).
- Allow rules never match calls that point somewhere else (`npm --prefix /tmp/x test`, `git -C ../other status`) or that write outside the project or to files tools run later.
- A remembered deny keeps the command words and flags (`git push --force …`), so it also blocks other targets and spellings.
- Commands that are risky to allow by prefix, such as `rm`, `git push`, `curl` and package installs (`npm install foo`), are remembered only as exact matches, including their arguments.
- "Allow and remember" is not offered for:
  - high-risk calls
  - interpreters, such as `python x.py`
  - commands with dynamic parts
- Global allow rules are offered only for read-only calls in trusted projects, and they only apply in trusted projects, so a freshly cloned repository cannot reuse them.
- The dialog counts as a deny after 10 minutes without an answer.
- If you give a reason when you deny a call, the reason is passed to the agent.

## Scopes and precedence

| Scope | Stored in | Lifetime |
|---|---|---|
| Session | pi's session log | Until the session ends. Rewinding with `/tree` also drops approvals made after that point |
| Project | `~/.pi/agent/guard/projects/*.jsonl` | Allow rules: 30 days. Deny rules: no expiry |
| Global | `~/.pi/agent/guard/rules.jsonl` | Same as project |
| Repository | `.pi/guard.json`, read only for trusted projects | Deny and ask rules only, so a repository cannot grant itself permissions |

Precedence follows **strictness**, not scope: deny > ask > allow. A deny rule in any scope therefore wins over an allow rule in any other scope. Deny and ask rules also match other spellings of the same command: `git push --force` matches `git -C . push -f`, `timeout 60 git push -f`, `if …; then git push --force; fi` and `git push origin +main`.

Rule files are updated under a lock, so several pi processes can change rules at the same time without losing updates. A broken line in a rule file is reported and kept; it never disables the other rules.

```json
// .pi/guard.json
{ "deny": ["git push --force"], "ask": ["npm publish"] }
```

## Commands

| Command | What it does |
|---|---|
| `/guard` | Shows the current status |
| `/guard on` / `/guard off` | Turns guard on or off for this session |
| `/guard check <cmd>` | Scores a bash command without running it |
| `/guard rules` | Lists rules. Select one to delete it |
| `/guard rules rm <id>` | Deletes a rule |
| `/guard rules promote <id> project\|global` | Promotes a session rule to a wider scope |
| `/guard rules add <allow\|deny\|ask> <session\|project\|global> <command words… \| tool:<name> \| path:<path>>` | Adds a rule by hand |
| `/guard log [n]` | Shows the audit log (`~/.pi/agent/guard/audit.jsonl`) |
| `/guard reload` | Reloads settings and rules |

When a session rule has been used three times, guard suggests promoting it to the project scope.

After 3 automatic blocks in a row, or 20 automatic blocks in total, guard stops the agent and tells you. Your own denials in the approval dialog do not count toward these limits. The audit log is rotated at 5 MB.

## Configuration

Settings live in `~/.pi/agent/guard/config.json`. Every field is optional.

```json
{
  "model": "gpt-6-luna",
  "timeoutMs": 6000,
  "skipModelTools": ["read", "grep", "find", "ls"],
  "allowRuleTtlDays": 30,
  "dialogTimeoutMs": 600000,
  "verdictCacheMs": 600000,
  "thresholds": { "confirmScore": 1.5, "blockPHigh": 0.6, "blockPCatastrophic": 0.25, "confirmExfil": 0.3 }
}
```

Invalid values fall back to the default with a warning. The default thresholds are starting points. If guard asks too often or lets too much through, adjust them while checking real decisions with `/guard log`.

Environment variables override the config file:

| Variable | What it sets |
|---|---|
| `GUARD_OPENAI_API_KEY` | The API key used only by guard |
| `RISK_MODEL` | The model used for judgement |
| `RISK_TIMEOUT_MS` | The judgement timeout, in milliseconds |
| `RISK_CONFIRM_AT` | The score at which a call needs confirmation |
| `RISK_SKIP_TOOLS` | Tools that skip the model judgement |
| `OPENAI_BASE_URL` | The API endpoint, for example a gateway (not guard-specific) |
| `RISK_DISABLE=1` | Turns guard off completely |

Load guard last. If another extension rewrites a tool call's input after guard has judged it, guard detects the change and warns you.

## Development

Requires Node.js 22.19 or later, the same as pi. The current LTS, Node 26, is recommended (see `.node-version`).

```bash
npm ci
```

```bash
npm run check
```

`npm run check` runs, in order:

- type checking
- knip, to find unused code
- unit tests
- an end-to-end test that runs the real pi against a mock model and a mock Decisions API

GitHub Actions (`.github/workflows/ci.yml`) runs the same checks on the current LTS.

## License

[MIT](LICENSE) © 2026 tesso57
