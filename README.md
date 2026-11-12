# guard

An extension for the [pi coding agent](https://github.com/badlogic/pi-mono). Before a tool call runs, guard uses checks and remembered rules to decide whether to allow it, ask you to confirm it, or block it. Direct skill reads bypass guard, as described below.
When those checks need a model judgement, guard uses the [OpenAI Decisions API](https://platform.openai.com/docs/guides/decisions) (`gpt-6-luna`). It can remember your decisions as rules.

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
| 1 | Hard deny: recursive deletion of `/`, `~` or system directories, `curl … \| sh`, writes to `authorized_keys`, and **any change to guard's rules, pi's state and session logs, or the project resources pi loads (`.pi/`, `.agents/`)** | Block. No rule can override it; only you can, when the agent asks you and retries (see below) |
| 2 | Deny and ask rules, in any scope | Block / confirm |
| 3 | Allow rules. For bash, every subcommand must match and the command must have no dynamic parts such as `$()` or variable expansion | Allow, after a light check for exfiltration, actions outside your request, and text aimed at the judge |
| 4 | Sensitive paths (`~/.ssh`, `.env`, key files, `/proc/*/environ`, …, after resolving symlinks and globs), printing the environment, and content searches across `~` | Confirm |
| 5 | Safe list, which only covers reads **inside the project** (or public locations such as `/usr` and Pi code directories under `~/.pi/agent`): read-only bash commands (judged by command **and options**, so `git log --output=…` or `sort -o` are not read-only; read-only `git` only in trusted repositories with safe repository and user Git configuration, and never after `cd`), `mkdir`/`touch` of ordinary project paths, and edits to ordinary files inside the project | Allow, without calling the API |
| 6 | Decisions API | Allow / confirm / block |

The model is told that you have delegated the work and do not want to approve routine steps. Editing or deleting project files, running the project's tests, builds and scripts (including ones the agent just wrote, judged by their contents), `git commit`, and installing declared dependencies are normally allowed. It asks you only for likely harm: damage outside the project, data loss version control cannot undo, sending data elsewhere, code from untrusted sources, weakened security or persistence, and actions on shared or remote systems you did not ask for (push, publish, deploy).

By default, the built-in read tools (`read`, `grep`, `find`, `ls`) skip the model only for paths inside the project or public locations (system directories such as `/usr`, code pi loads under `~/.pi/agent/{install,git,npm,extensions,skills,prompts,themes}`); elsewhere they are judged like any other call. `read` must name an existing file to use this shortcut. Paths are resolved using pi's path conventions (`file://` URLs, `~`, unicode spaces). Project and home directory aliases such as macOS's `/var` → `/private/var` are recognized, symlinks are followed even when their target does not exist yet, and `..` is applied after symlinks as the kernel does. When pi runs in your home directory (or above), nothing counts as a plain project read or edit.

Direct skill reads bypass guard entirely, including deny rules and audit logging: the `read`, `ls`, `grep`, and `find` tools, and simple read-only `cat`, `head`, `tail`, `sed`, `grep`, and `rg` commands, including pipelines made from these commands, targeting only existing files or directories within standard `.agents/skills`, project `.pi/skills`, or the Pi agent's `skills` directory. The built-in `grep` and `find` bypass applies only when their search executables can be verified as described below. Each shell `rg` must name its search paths explicitly or read from a verified skill pipeline; shell `grep` with `GREP_OPTIONS` or a pattern file does not qualify. Hard-linked files whose other names cannot be verified, and directory content searches that cannot be inspected completely, go through guard normally. The exact skill files registered with Pi also qualify, including files supplied by packages or custom paths; if their resolved path changes after registration, they go through guard normally. Commands with other targets, writes, shell expansion, unsafe options, or symlinks that leave those directories go through guard normally. Pi's own automatic skill discovery does not use tool calls and is not intercepted by guard.

For compatibility with Pi versions that may honor ripgrep configuration, the built-in `grep` bypass also requires `RIPGREP_CONFIG_PATH` to be unset or empty.

Checks that grant a project or public-directory shortcut require matching path casing, so a differently cased path may need judgement even on a case-insensitive filesystem. Protective checks still treat case variants as equivalent.

Listing skill file names with `rg --files` does not require inspecting their contents or resolving every hard link. A content search still requires that inspection, including when it follows a file listing in a pipeline.

`tail` in follow mode goes through normal judgement: it can keep reading after the file name is retargeted. This includes follow mode on skill files.

Pi's built-in `grep` and `find` run `rg` and `fd` (or `fdfind`) respectively, and can download them if absent. A candidate may fail to start, so guard inspects later `PATH` entries and the `fdfind` fallback too. If any candidate is in the project, a temporary directory, or Pi's managed bin directory, is found through a relative `PATH` entry, has unverified hard links, or cannot be verified, guard asks for confirmation even when the model allows the search. On Windows these built-in searches also require confirmation because their executable lookup is not verified. Guard rechecks executable identity while a judgement or confirmation is pending.

For Pi 1.5.0, guard recognizes `PI_OFFLINE=1` (also `true` or `yes`, case-insensitive): when the search executable is absent, Pi reports it as unavailable without downloading it. Other Pi versions retain the confirmation because their offline download behavior has not been verified.

For script candidates, guard checks the interpreter path and its identity without running it; missing, relative, untrusted, `env`-resolved, nested script, or unrecognized interpreter formats require confirmation. Guard also checks that native executable headers are plausible for the current OS. On Linux it inspects bounded ELF program headers and verifies the dynamic loader is an unmodifiable system loader. On macOS it inspects Mach-O load commands and verifies `/usr/lib/dyld`; embedded dyld environment settings require confirmation. Other native startup failures, including missing shared libraries or platform-specific loader problems, may still cause Pi to attempt a download; these checks do not establish that every candidate can start.

For Linux ELF candidates, guard also examines embedded library search paths, direct dependency paths, and matching files in those search directories and their `glibc-hwcaps` subdirectories. Relative, unexpandable, project, temporary, or Pi-managed paths require confirmation; `$ORIGIN` is checked against both the executable's named and resolved locations. ELF auditing and filtering entries also require confirmation. The check does not recursively inspect shared libraries, legacy architecture-specific subdirectories, or the system loader cache.

Dynamic-loader environment settings that can inject code or redirect libraries, such as `LD_PRELOAD`, `LD_LIBRARY_PATH`, `DYLD_INSERT_LIBRARIES`, and `DYLD_LIBRARY_PATH`, require confirmation for shell and built-in search calls. Inherited environment values are not included in the warning; settings written explicitly in a command are handled like other command input. `read` and `ls` do not launch a new executable and are unaffected.

Git's compiled-in system configuration path varies between installations. To avoid executing Git before the safety check or guessing that path, guard skips the read-only Git shortcut unless `GIT_CONFIG_NOSYSTEM` is true or `GIT_CONFIG_SYSTEM` explicitly identifies a configuration file that guard can inspect. Other checks and remembered rules still apply.
The Git hooks directory is inspected up to 1,000 entries; a larger or unreadable directory disables the shortcut because guard cannot establish that it is safe.

If shell startup settings (`BASH_ENV` or `ENV`), inherited shell options (`SHELLOPTS` or `BASHOPTS`) or imported Bash functions are present, bash calls require confirmation because they can run additional code or change parsing. Supplying these settings inside a command, enabling shell tracing, creating Bash namerefs, or using `enable` to change builtins also requires confirmation because execution settings can change indirectly and `PS4` expansions can execute code. These environment values are not included in the warning.
On Unix, guard also checks the first executable found on `PATH`, including Pi's prepended agent `bin` directory. A command resolved inside the project or its enclosing Git repository, Pi's agent directory or a temporary directory requires confirmation instead of inheriting the command name's safe shortcut. If the search exceeds 512 filesystem probes or cannot be resolved reliably, guard asks first. If a PATH-resolved executable's filesystem identity or metadata, or shell lookup or startup environment variables, change while model judgement or confirmation is in progress, guard blocks the call; cached judgements also account for these settings. Changing `PATH`, clearing the environment with `env -i`, splitting an environment command with `env -S`, or changing Bash's command hash inside a call also requires confirmation. Explicit paths still receive a full judgement. Custom shells, configured shell command prefixes and spawn hooks may change what runs, so these checks do not replace sandboxing.
On Windows, guard asks before external bash commands because Git Bash's executable lookup cannot be verified with the Unix path check. This Windows behavior is covered by platform-simulated tests; the real-Pi executable-shadow test runs on Unix.

An executable with multiple hard links also requires confirmation, since another name may point into the project or another untrusted location. Root-owned system executables that are not writable by the current process are exempt from this check.

If the API call fails, the model refuses to answer, or the input had to be truncated, guard takes the safe side: it asks you to confirm, or blocks the call when there is no UI. The same applies when secret redaction hides part of the request or its judgement context, because the model cannot inspect the hidden content. YAML merge keys, multiline explicit keys, or a redacted alias whose anchor may still expose its value cause the containing text to be withheld in full, even when it also contains unrelated information.
HTTP errors report their status and a fixed hint, not the response body, which may contain echoed request data.
Transport and response-stream errors also use fixed messages so exception details cannot expose request data.
Successful responses are limited to 1 MiB and 4,096 chunks; oversized, excessively fragmented, invalid UTF-8 or invalid JSON responses also require confirmation.
Missing, malformed or duplicate required answers require confirmation. If duplicate answers include a valid exfiltration or risk signal above a block threshold, guard blocks instead.

guard sends the Decisions API:

- your most recent messages (3 by default, `contextUserMessages`), so the model knows what you asked for; the newest is marked as your current instruction, and an explicit go-ahead there for the pending action counts as within your request
- the agent's recent tool calls
- your past decisions
- the call being judged

It never sends the assistant's own text or tool outputs. This limits prompt injection. File contents guard attaches are passed as an untrusted tool output, never as your words. When bash runs a script that was written or edited earlier, guard attaches its contents. For a file another call in the same message proposes to change, guard attaches the proposed contents where predictable and labels them as such; concurrent execution means they are not guaranteed to be the contents that run. Running such a file requires confirmation even if the model would otherwise allow it; changes from earlier messages force a full judgement but do not always require confirmation. When a test runner, build tool or interpreter (`npm`, `pytest`, `make`, `python`, `sh`, …) runs, guard collects the script it is given, known project files changed in this session, and up to 20 project files changed in the last day. Known session changes or changes guard cannot enumerate (such as a checkout) force a full judgement, even if an allow rule matches. Preparation retains at most 20 attachments and inspects at most 256 session or concurrent change candidates; it may also read up to 20 peer edits to predict their contents. The request has a separate 200,000-character budget; if preparation or the request exceeds these limits, guard asks for confirmation. Files larger than the per-field limit are truncated, which also requires confirmation. Named or session-modified files that cannot be read or are at least 1 MB require confirmation rather than being silently omitted. Truncated user messages or tool history also require confirmation.

If a concurrent edit cannot be predicted exactly, such as one requiring fuzzy matching or conflicting edits, guard marks the resulting file contents as unknown instead of attaching a guessed result. Running it still requires confirmation. A concurrent shell write also requires confirmation for other calls that access filesystem paths. Special files such as named pipes are not read while preparing judgement; executing one requires confirmation.
Files that are not valid UTF-8 are also treated as unreadable rather than being sent with replacement characters.

Files with multiple hard links are not attached to the judge, because another name may point to a secret outside the project. Writes, execution, and running a changed file with multiple hard links require confirmation. Read-only shell commands can read them without confirmation only when a complete bounded project scan finds every link inside the project and none has a sensitive name. If any link cannot be located, confirmation remains required.
When a bounded scan identifies a hard link as the same file as protected state, writing through it is blocked. If identity cannot be established within the scan limit, the general hard-link confirmation still applies.

As soon as an assistant message ends, guard starts assessing up to its first eight tool calls in parallel, calling the model only where needed. Remaining calls are assessed when pi reaches them. Speculative requests are cancelled when a new message or session makes them obsolete. pi delivers the calls of a message for checking before it runs any of them, so when another call in the same message may change files in ways guard cannot safely predict, calls that depend on the file tree get no shortcuts: no safe list, no skipped model, no allow rule without a full judgement. The direct skill-read bypass described above still applies. Plain edits to ordinary project files and safe `mkdir`/`touch` calls do not disable these shortcuts, except when they change search ignore files. guard repeats its deterministic checks at `tool_call` and reuses the model's verdict only if the input, attachments and resolved path state are unchanged. If the judgement context or access policy changes while the model is responding or a confirmation is open, guard blocks the call.

After the checks, pi can execute calls from the same message concurrently. A confirmation does not make an earlier write finish before a later command runs; request separate agent turns when one operation depends on another's result.

Edit prediction has a bounded search budget. If a large batch exceeds it, guard treats the resulting file contents as unknown and requires confirmation before running the affected file.

A message containing more than 128 tool calls exceeds guard's batch inspection limit. Calls in such a message, or in a message with duplicate or invalid tool call IDs, are blocked rather than assessed with incomplete sibling context; split the work across messages or retry with unique IDs.

After changes guard cannot enumerate, script runners are judged again on each call instead of reusing a cached verdict. Configuring `bash` in `skipModelTools` does not skip the full judgement when the call may run changed files.

Recursive content searches (`grep -r` in any spelling, `rg`, `git grep`, pi's `grep` tool) ask first when the searched tree contains `.env` files or keys. For `rg`, simple inclusion globs such as `-g '*.ts'` exclude nonmatching files from that check; explicitly named files are still checked. Other glob forms remain conservative. When guard can establish that `rg` excludes hidden files, hidden directories are not traversed; `-u` or `--no-ignore` alone still excludes hidden files, while `-uu`, file type options such as `-tsh`, re-inclusion rules and explicit hidden paths remain subject to inspection. `--no-ignore-vcs` and `--no-ignore-dot` are accounted for separately, so disabled ignore sources do not cause unnecessary confirmation. `rg --files` and `rg --type-list` list filenames or types without searching file contents, so they do not trigger this tree-wide content check. If the tree cannot be checked completely, guard runs a model judgement and still asks first unless the model blocks the call. Extracting archives where `.pi/` or `.agents/` could be created also asks first. Files that likely hold secrets are never sent to the judge; guard sends only their names.

For recognized `grep` and `rg` options, guard distinguishes search patterns from file operands. Unknown options and shell expansions retain the conservative path checks.

Past tool-call arguments are also withheld when guard detects that the call refers to a sensitive or protected file or a hard-linked file. This prevents recognized previous writes or shell commands from reintroducing file contents through the history sent to the judge.
If a previous call's arguments cannot be inspected, guard withholds them and requires confirmation for a call that needs model judgement; neither a remembered allow rule in rules-only mode nor a configured model skip bypasses this.
Related past rules that contain sensitive or protected paths are also withheld from the judge. Because that removes potentially relevant decision history, the resulting model judgement requires confirmation unless it blocks the call.
For calls requiring model judgement, at most five related past decisions are sent, with deny and ask rules first. If more decisions exist, their omission also requires confirmation unless the model blocks the call. Directly matching deny and ask rules are checked against all rules before this limit is applied.

When `RIPGREP_CONFIG_PATH` is set, including by an assignment in the command, a bash `rg` search asks first because its configuration may add executable preprocessors or expand the search. Standalone version and help requests do not search files or run the preprocessor. Pass `--no-config` as an option to disable that configuration for a call. If this setting changes while an `rg` or other command that may invoke it is being judged or confirmed, guard blocks the call and requires a fresh decision; an unrelated read-only command or an `rg --no-config` search is unaffected.

When `GREP_OPTIONS` is set, including by an assignment in the command, grep-family searches ask first. Some grep implementations honor this variable and can enable recursive searches even when the command does not show a recursive flag.

Commands that change things are blocked whenever they name guard's state or a directory containing it, whatever wrapper comes first (`time -p`, `setarch`, `fakeroot`), however the shell gets there (`cd` through wildcards or `CDPATH`, `pushd`/`popd`, `OLDPWD`, `git -C`, `npm --prefix`, brace expansion), and including links (`ln`, `cp -l`) that would let a later plain write reach it. Command-like arguments of other tools (powershell, MCP shells) get the same check. A project's own `.pi/` is protected from writes, but does not block commands such as `git add .` or `prettier --write .`. Options with glued path values (`-f/etc/x`), the directory stack (`pushd`, `popd`), here-documents, pagers, and wildcards that match names starting with `-` (which the command would read as options) never count as safe; creating files with such names is never a plain edit. Wildcards are expanded like bash, through symlinked directories. File contents written with `write`/`edit` are data and are not scanned as commands; running them later is judged then.

For other tools, any string of 16 Ki characters or more exceeds the deterministic command and path inspection limit and requires confirmation, even when that tool is configured to skip the model.

For calls guard inspects, tool arguments must remain unambiguous JSON data and within the comparison complexity limit. Cyclic, non-JSON, negative-zero or overly complex inputs are blocked; if the input becomes uninspectable while judgement or confirmation is pending, the call is also blocked.

Where guard cannot pin something down, it errs on the side of blocking: wildcards are matched against guard's state as patterns (so a skipped or truncated expansion cannot hide them), commands that change `HOME`, `CDPATH` or `OLDPWD` are blocked, and a changing command whose working directory guard cannot determine is blocked. Patches (`git apply`, `git am`, `patch`) are read to see which files they change; a patch guard cannot read asks first.
Patterns too complex to evaluate within the wildcard limits are treated as potentially reaching protected paths.

When another call in the same message may change the file tree (including Git operations that can run hooks, extracting archives, `cp`, `rsync`, and package installs), calls that write or access filesystem paths ask you first regardless of their order in the message, because neither guard nor the model can see what those directories will contain. PowerShell and custom tools are treated as potentially changing the file tree too, since their effects cannot be enumerated reliably. Strings that look like secrets are redacted before anything is sent.

Risk is scored on five levels, from 0 to 4. guard looks at the probability of the high-risk levels as well as the weighted average, so a split such as "45% catastrophic, 55% harmless" is still caught.

## When guard blocks a call

The agent is told why, and that it must not work around the check. If it really needs that exact call, it should explain why and ask you; if you agree, it runs the same call again and guard shows you a dialog (allow this time only / deny) instead of blocking. This applies to hard denies and to calls the model judged too dangerous, once per block; nothing is remembered. Calls blocked by your own deny rules stay blocked (remove the rule with `/guard rules`), and without a UI every block stays a block.

Retry eligibility is discarded when settings are reloaded, guard is toggled, the session tree changes, or the project or trust state changes. Changed rules or trusted-folder grants also require a fresh block before a retry can be offered.

Guard keeps at most 500 blocked-call retry entries. If an older entry is evicted, that call is blocked again before a new retry can be offered.

## Approval dialog

```
Allow (this time only)
Allow (this session: npm install …)
Allow and remember (this project: …)   (or "… ▸ → this project / global" for read-only calls in trusted projects)
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
  - calls that may run files changed concurrently in the same message
- Global allow rules are offered only for read-only calls in trusted projects, and they only apply in trusted projects, so a freshly cloned repository cannot reuse them.
- Global allow rules are checked against the actual call as well as the stored pattern. A writing flag, unsafe Git configuration, or an older global rule for a non-read-only operation prevents the rule from granting permission. Manual global allow rules must also be read-only.
- Each selection or input prompt times out after 10 minutes by default. A timed-out selection counts as a deny; a timed-out optional denial reason is left blank.
- If you give a reason when you deny a call, the reason is passed to the agent.

## Scopes and precedence

| Scope | Stored in | Lifetime |
|---|---|---|
| Session | pi's session log | Until the session ends. Rewinding with `/tree` also drops approvals made after that point |
| Project | `~/.pi/agent/guard/projects/*.jsonl` | Allow rules: 30 days. Deny rules: no expiry |
| Global | `~/.pi/agent/guard/rules.jsonl` | Same as project |
| Repository | `.pi/guard.json`, read only for trusted projects | Deny and ask rules only, so a repository cannot grant itself permissions |

Precedence follows **strictness**, not scope: deny > ask > allow. A deny rule in any scope therefore wins over an allow rule in any other scope. Deny and ask rules also match other spellings of the same command: `git push --force` matches `git -C . push -f`, `timeout 60 git push -f`, `if …; then git push --force; fi` and `git push origin +main`.

Rule files are updated under a lock, so several pi processes can change rules at the same time without losing updates. A broken line is reported and kept. Known deny rules still block; other calls require confirmation until the broken line is repaired, since it might have contained another deny rule.

Invalid session rule events are treated the same way. Rewinding to a branch without the invalid event restores normal evaluation; a later removal event for an identifiable invalid rule also clears it.

A lock is not removed merely because it is old: a process may still be using it. If a crash leaves a `.lock` directory behind, stop other guard processes and remove the lock named in the error before retrying.

If a global or project rule file cannot be read, guard asks before calls instead of treating the file as empty; it retries on subsequent calls. An unreadable or invalid trusted repository `.pi/guard.json` also requires confirmation until it is repaired and `/guard reload` is run.

Guard reads settings, Git configuration and ignore files only when they are regular files under 1 MB; persisted global and project rule files have an 8 MB limit. Oversized or special files are treated as unreadable instead of being read indefinitely. Patch files over 2 MB or special files require confirmation.
Directory comparisons that exceed 2,000 inspected entries or cannot be inspected completely also require confirmation.
Wildcard reads require confirmation when expansion cannot be inspected completely.

```json
// .pi/guard.json
{ "deny": ["git push --force"], "ask": ["npm publish"] }
```

Each repository rule must be one static command. Quoted arguments are supported; redirects, wildcards, substitutions and compound commands are rejected so they cannot silently become ineffective rules.

## Tools and folders from other extensions

An extension can tell guard that one of its own tools is safe to run without a judgement, for example a notes extension's `notes_write`, whose arguments are text rather than commands:

```ts
pi.registerTool({ name: "notes_write", /* ... */ });

pi.on("session_start", () => {
  pi.events.emit("guard:trust-tool", { tool: "notes_write", by: "notes" });
});
```

Emitting in `session_start` works whatever order the extensions load in; without guard installed, nobody listens and nothing happens. Vouched-for tools run without any check and are recorded in the audit log (source `extension`); `/guard rules` lists them. Built-in tools (`bash`, `write`, `edit`, `read`, …) cannot be vouched for, a name only counts once a tool with that name is registered, and tools of project-local extensions (`.pi/extensions`) count only in trusted projects. Only vouch for tools whose effects you are happy to allow unconditionally.

The event bus does not authenticate which extension sent a trust event. Any loaded extension can vouch for an eligible tool or folder, including one owned by another extension; the `by` value is a display label, not proof of ownership.

An extension can also vouch for a folder it owns, such as an artifacts extension's output folder:

```ts
pi.on("session_start", () => {
  pi.events.emit("guard:trust-dir", { path: "~/.pi/artifacts", by: "artifacts" }); // access: "read" for read-only
});
```

Inside a vouched-for folder, reads are free like reads inside the project, and plain `write`/`edit` calls (and `mkdir`/`touch`) run without a judgement. Everything else is judged as usual: running code there, files that tools run later (`package.json`, `Makefile`, …), secrets (`.env`, keys), hard links, and symlinks that leave the folder. Only folders inside the home directory (or the temp directory) are accepted; the home directory itself, the agent directory `~/.pi/agent`, and folders that hold credentials, tool configuration or programs (`~/.ssh`, `~/.aws`, `~/.config`, `~/.local`, `~/bin`, …) are refused. `/guard rules` lists vouched-for folders, including refused ones and why.

The optional `access` field accepts `"read"` or `"write"` and defaults to `"write"` when omitted. Events with other values are ignored. Grants for overlapping folders are additive: a read-only child grant does not revoke a parent folder's write grant. Re-registering the same folder replaces its previous grant, including when the new registration uses a symlink to that folder.

Folder grants belong to the current guard instance and are not inherited by another guard instance. Extensions should emit their trust events on `session_start`.

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
| `/guard log [n]` | Shows up to `n` valid audit records (1–1000) from the last 256 KiB of `~/.pi/agent/guard/audit.jsonl` |
| `/guard reload` | Reloads settings and rules |

`/guard on` changes the session setting; it cannot override `disabled: true` in the configuration or `RISK_DISABLE=1`. After changing the configuration file, run `/guard reload`. To remove an environment variable inherited by a running Pi process, restart Pi without it.

`tool:<name>` deny and ask rules cover any input for a non-bash tool. For allow rules, `edit`, `write` and `read` require a `path:<path> <tool>` pattern; `powershell` cannot use an any-input allow rule. Other any-input allows apply only when the input has no path or command-like content. For bash, specify one static command instead of `tool:bash`; quoted arguments are supported, but redirects, wildcards, substitutions and compound commands are rejected. Manual `tool:` and `path:` patterns cannot contain spaces; `tool:` accepts no additional arguments and `path:` accepts only an optional tool name.
Manual bash allows use the same scope as approvals: commands such as `cp`, `rm` and `git push` match the complete command and arguments, while supported subcommands such as `npm test` can match a prefix. Location or unrecognized options that cannot match an allow rule are rejected when it is added.

When a session rule has been used three times, guard suggests promoting it to the project scope.

After 3 automatic blocks in a row, or 20 automatic blocks in total, guard stops the agent and tells you. Your own denials and cancellations do not count toward these limits. The audit log is rotated at 5 MB.
The audit source `concurrent` means guard requested confirmation based on another call in the same message; it did not need a model judgement for that decision.
If the audit log cannot be written, guard warns once and continues making decisions; it reports when logging recovers. Warnings go to standard error when there is no UI. Decisions missed during the interruption are not reconstructed. `/guard` shows this process's latest write status: `unknown` before its first attempt, `failed` after a failure, or `ok` after a success. A pending recovery notice means the warning about missing decisions has not yet been delivered; another process's status may differ.
Audit writes and rotation use a lock shared by guard processes. If a crash leaves `audit.jsonl.lock` behind, stop the other guard processes and remove that directory to resume logging.
When guard detects that a call involves sensitive or protected files, its audit preview omits the arguments; the approval dialog still shows the operation to the user.

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
  "thresholds": { "confirmScore": 2.5, "blockPHigh": 0.7, "blockPCatastrophic": 0.25, "confirmExfil": 0.3 }
}
```

Invalid values fall back to the default with a warning. An invalid `baseUrl` instead makes model judgement unavailable until corrected, so a misconfigured gateway does not silently send the key to the default endpoint. The URL must be HTTP(S) without embedded credentials, a query or a fragment. Unknown fields are ignored and produce a warning; their names and values are omitted from it to avoid exposing secrets. The default thresholds are starting points. If guard asks too often or lets too much through, adjust them while checking real decisions with `/guard log`.

Guard does not follow HTTP redirects from the Decisions API, so judgement context stays at the configured endpoint. Configure the final endpoint directly if a gateway responds with a redirect.

Environment variables override the config file. An invalid numeric override or an empty `RISK_MODEL` is ignored with a warning, preserving the validated file value:

| Variable | What it sets |
|---|---|
| `GUARD_OPENAI_API_KEY` | The API key used only by guard |
| `RISK_MODEL` | The model used for judgement |
| `RISK_TIMEOUT_MS` | The total judgement timeout, including retries, in milliseconds |
| `RISK_CONFIRM_AT` | The score at which a call needs confirmation |
| `RISK_SKIP_TOOLS` | Tools that skip the model judgement |
| `OPENAI_BASE_URL` | The API endpoint, for example a gateway (not guard-specific) |
| `RISK_DISABLE=1` | Turns guard off completely |

Load guard last. If the input changes while guard is judging it or waiting for confirmation, guard records the change and blocks the call. If another extension changes the input after guard has finished judging, guard records and warns about the change when the tool result arrives, after the changed call may already have run. In print mode the warning goes to standard error.

## Development

Requires Node.js 22.19 or later, the same as pi. Development and CI use Node.js 26.13.0 (see `.nvmrc`). The extension is tested with `@earendil-works/pi-coding-agent` 1.5.0.

```bash
npm ci
```

```bash
npm run check
```

`npm run check` runs, in order:

- type checking
- knip, to find unused code
- unit tests, Pi resource-loader smoke tests for both the source and an offline-installed package, and real Pi sessions with a scripted fake model, using Node.js's built-in test runner
- an npm package contents check
- an end-to-end test that packs the extension, loads the packaged entry point in the real pi, and uses a mock model and mock Decisions API

The installed-package smoke test uses a temporary npm cache and links the locally installed Pi dependency. A separate smoke test uses `pi install` with a local path and checks that Pi loads the resulting project configuration; it does not exercise GitHub installation. The in-process Pi session test uses a scripted model and a mocked Decisions API without network access. The end-to-end test binds its mock server to loopback and does not call the live Decisions API. A ripgrep visibility test compares guard's decisions with the installed `rg`; it is skipped when `rg` is unavailable locally and required in the main CI job. These tests verify local integration, not the behavior or availability of the live service. On macOS, the end-to-end test requests idle-sleep prevention while it runs.

GitHub Actions (`.github/workflows/ci.yml`) runs the same checks with the version in `.nvmrc`, the minimum supported Node.js 22.19.0, and Node.js 24 LTS; it also runs the package checks on Windows. The partial Pi test helper in `tests/helpers/mock-pi.ts` follows the template and does not replace the real-Pi checks.

The mock's `emit` returns individual handler results and propagates handler exceptions so tests fail visibly. Pi's runner reports handler errors and has event-specific result and cancellation behavior; use a real Pi session when a test depends on those semantics.

## License

[MIT](LICENSE) © 2026 tesso57
