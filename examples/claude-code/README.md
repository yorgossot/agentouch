# Claude Code guardrails for agentouch

Optional. They stop Claude from changing agentouch's store, log and binary, this hook or Claude
Code's settings, and from running `sudo`, so changes to agentouch go through you. They guard
against mistakes and prompt injection; they are not a sandbox.

`./install.sh --claude-code` does steps 1 and 2 for you. By hand:

1. Copy the hook and make it executable (it needs nothing beyond macOS, and blocks any command it
   can't read):

   ```sh
   mkdir -p ~/.claude/hooks
   cp agentouch-guard.sh ~/.claude/hooks/ && chmod 755 ~/.claude/hooks/agentouch-guard.sh
   ```

2. Merge this into `~/.claude/settings.json`, keeping your existing entries. In Claude Code an
   `Edit(path)` rule covers every file-writing tool, including Write
   ([docs](https://code.claude.com/docs/en/permissions)). Denying edits to the settings files
   stops Claude from removing the hook; you then change them yourself.

   ```json
   {
     "permissions": {
       "deny": [
         "Edit(~/.config/agentouch/**)",
         "Edit(//usr/local/bin/agentouch)",
         "Edit(~/.claude/hooks/agentouch-guard.sh)",
         "Edit(~/.claude/settings.json)",
         "Edit(~/.claude/settings.local.json)"
       ]
     },
     "hooks": {
       "PreToolUse": [
         {
           "matcher": "Bash",
           "hooks": [{ "type": "command", "command": "~/.claude/hooks/agentouch-guard.sh", "timeout": 10 }]
         }
       ]
     }
   }
   ```

3. Check it: ask Claude to run `ls ~/.config/agentouch`. The hook should block it.
   `../../tests/guard.sh` tests the hook itself.

The hook matches command text, so it also blocks commands that only mention `sudo`,
`.config/agentouch`, the hook or the settings file, for example inside a heredoc; Claude can
write such files with its file tools instead. It blocks reading the settings file through the
shell too; Claude's Read tool still works. `sudo` inside an `ssh` command runs on the other
machine and is allowed, unless it sits in `$(…)`, backticks, `<(…)`, `>(…)` or an ssh
`ProxyCommand`, which run on this Mac and are denied. It can be evaded by obfuscation (`bash -c
"su""do …"`): it is there to catch mistakes and the obvious, not a determined attacker.
