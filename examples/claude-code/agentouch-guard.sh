#!/bin/bash
# Claude Code PreToolUse hook (matcher: Bash). Blocks shell commands that touch agentouch's store and
# log, this hook or Claude Code's settings, or that ask for admin rights on this Mac (sudo, or
# osascript "with administrator privileges"): changes to agentouch's trust boundary go through the
# user, not the agent. A guardrail against mistakes and prompt injection, not a sandbox.
# Needs jq.
#
# It matches the command text, so it also blocks harmless commands that merely mention these
# (in a heredoc or comment, say); the agent can write such files with its file tools instead.
# sudo inside an ssh command runs on the other machine and is allowed, unless it sits in
# $( ), backticks, <( ), >( ) or an ssh ProxyCommand/LocalCommand, which run on this Mac.
pattern='\.config/agentouch|\.claude/(hooks/agentouch-guard|settings)|(^|[^[:alnum:]_-])sudo([[:space:];&|]|$)|administrator privileges'
local_exec='\$\(|`|<\(|>\(|ProxyCommand|LocalCommand'
raw=$(jq -r '.tool_input.command // ""')
remote_stripped=$(printf '%s\n' "$raw" | sed -E 's/(^|[;&|[:space:]])ssh [^;&|$`]*//g')
matches() { printf '%s\n' "$1" | grep -Eq "$2"; }
if matches "$remote_stripped" "$pattern" || { matches "$raw" "$pattern" && matches "$raw" "$local_exec"; }; then
  jq -n '{hookSpecificOutput: {hookEventName: "PreToolUse", permissionDecision: "deny",
    permissionDecisionReason: "agentouch guard: commands that touch ~/.config/agentouch, this hook or Claude Code settings, or ask for admin rights, are for the user to run"}}'
fi
exit 0
