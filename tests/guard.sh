#!/bin/bash
# Tests for examples/claude-code/agentouch-guard.sh: ./tests/guard.sh (needs jq)
cd "$(dirname "$0")/.."
failures=0
expect() {
  local want=$1 cmd=$2 got
  got=$(jq -n --arg c "$cmd" '{tool_name: "Bash", tool_input: {command: $c}}' | examples/claude-code/agentouch-guard.sh |
    jq -r '.hookSpecificOutput.permissionDecision // "allow"')
  [ -z "$got" ] && got=allow
  if [ "$got" = "$want" ]; then echo "ok   $want: $cmd"; else echo "FAIL $want: $cmd (got $got)"; failures=$((failures + 1)); fi
}
expect allow 'ls'
expect allow 'agentouch list'
expect allow 'echo pseudo-random'
expect allow "ssh host 'sudo -n systemctl status x'"
expect deny  'cat ~/.config/agentouch/store.json'
expect deny  'cp x "$HOME/.config/agentouch/store.json"'
expect deny  'sudo install -m 755 agentouch /usr/local/bin/agentouch'
expect deny  'cd x && sudo cp agentouch /usr/local/bin/'
expect deny  'env sudo true'
expect deny  'command sudo true'
expect deny  '/usr/bin/sudo true'
expect deny  $'ls\nsudo true'
expect deny  'bash -c "sudo true"'
expect deny  "sh -c 'sudo true'"
expect deny  'sudo;true'
expect deny  "osascript -e 'do shell script \"x\" with administrator privileges'"
expect allow "ssh host 'sudo -n true'"
expect deny  "ssh host 'sudo -n true'; sudo true"
expect deny  'ssh host $(sudo true)'
expect deny  'ssh host `sudo true`'
expect deny  'echo ssh && sudo true'
expect deny  'myssh sudo true'
expect deny  'ssh h "echo $(sudo id)"'
expect deny  "ssh -o ProxyCommand='sudo nc %h %p' h true"
expect deny  'ssh h x > >(sudo tee f)'
expect deny  '$( ssh x) sudo y'
expect deny  'cat > ~/.claude/hooks/agentouch-guard.sh'
expect deny  'jq . ~/.claude/settings.json > /tmp/s && mv /tmp/s ~/.claude/settings.json'
got=$(printf 'not json' | examples/claude-code/agentouch-guard.sh | grep -c '"deny"')
if [ "$got" = 1 ]; then echo "ok   deny: unreadable input"; else echo "FAIL deny: unreadable input"; failures=$((failures + 1)); fi
[ "$failures" = 0 ] && echo "all passed" || { echo "$failures failed"; exit 1; }
