#!/bin/bash
# Installs agentouch: checks this Mac, runs the tests, builds, installs the binary root-owned in
# /usr/local/bin (asks for your Mac password), and creates the Secure Enclave key.
#
#   ./install.sh                 install or update agentouch
#   ./install.sh --claude-code   also set up Claude Code: the example skill, the guard hook and
#                                its deny rules (existing files are never overwritten; settings.json
#                                is backed up and merged, not replaced)
set -euo pipefail
cd "$(dirname "$0")"
say() { printf '\n==> %s\n' "$*"; }
die() { printf '\nerror: %s\n' "$*" >&2; exit 1; }
ask() { local answer; read -r -p "$1 [y/N] " answer; [ "$answer" = y ] || [ "$answer" = Y ]; }

claude_code=false
case "${1:-}" in
    "") ;;
    --claude-code) claude_code=true ;;
    *) die "usage: ./install.sh [--claude-code]" ;;
esac
# You run this, not an agent: it installs a root-owned program and asks for your password.
[ -t 0 ] || die "run ./install.sh yourself, in a terminal"

if command -v git >/dev/null && git rev-parse --git-dir >/dev/null 2>&1; then
    say "Installing commit $(git log -1 --format='%h %s')"
    if [ -n "$(git status --porcelain)" ]; then
        git status --short
        ask "These files differ from that commit. Install them anyway (only if you made or read the changes)?" \
            || die "nothing was installed"
    fi
fi

say "Checking this Mac"
[ "$(uname -s)" = Darwin ] || die "agentouch needs macOS"
[ "$(sw_vers -productVersion | cut -d. -f1)" -ge 14 ] || die "agentouch needs macOS 14 or later"
command -v swiftc >/dev/null || die "the Swift compiler is missing: run xcode-select --install"
swift_version=$(swiftc --version 2>&1 | sed -n 's/.*Swift version \([0-9]*\.[0-9]*\).*/\1/p' | head -1)
printf '%s\n5.10\n' "$swift_version" | sort -V -C 2>/dev/null && [ "$swift_version" != 5.10 ] && die "Swift $swift_version is too old: agentouch needs 5.10 or later (Xcode 15.3+)"
echo "macOS $(sw_vers -productVersion), Swift $swift_version"
command -v bw >/dev/null && echo "Bitwarden CLI found (needed only for sign-ups and logins)" \
    || echo "Bitwarden CLI not found; fine unless you want sign-ups and logins (brew install bitwarden-cli)"

say "Running the tests (no Touch ID needed)"
if ! test_output=$(./tests/run.sh 2>&1); then
    printf '%s\n' "$test_output" | grep -E 'FAIL|error' | head -20 || true
    die "the tests failed; nothing was installed"
fi
printf '%s\n' "$test_output" | grep -E 'passed|skipping' || true

say "Building"
./build.sh
# doctor exits non-zero before installation (nothing set up yet), so only its Touch ID line counts.
doctor_output=$(./agentouch doctor 2>/dev/null || true)
grep -q 'Touch ID enrolled' <<< "$doctor_output" \
    || die "Touch ID isn't set up: enrol a fingerprint in System Settings → Touch ID & Password"

target=/usr/local/bin/agentouch
say "Installing $target, owned by root (asks for your Mac password)"
sudo mkdir -p /usr/local/bin
owner=$(stat -f %Su /usr/local/bin)
if [ "$owner" != root ]; then
    echo "/usr/local/bin belongs to $owner, so a root-owned agentouch in it could still be swapped out."
    if ask "Make /usr/local/bin root-owned? (Homebrew on Intel Macs will then need sudo to link there)"; then
        sudo chown root:wheel /usr/local/bin
        sudo chmod 755 /usr/local/bin
    else
        echo "Continuing; see the README's Install section for the trade-off."
    fi
fi
sudo install -o root -g wheel -m 755 agentouch "$target"
"$target" --version

if "$target" list >/dev/null 2>&1; then
    echo "Already set up; your secrets are untouched."
else
    say "Creating the Secure Enclave key"
    "$target" init
fi

if $claude_code; then
    say "Setting up Claude Code"
    skill=~/.claude/skills/agentouch/SKILL.md
    hook=~/.claude/hooks/agentouch-guard.sh
    settings=~/.claude/settings.json
    if [ -e "$skill" ]; then
        echo "kept your existing $skill"
    else
        mkdir -p "$(dirname "$skill")"
        cp examples/skill/SKILL.md "$skill"
        echo "installed the skill at $skill"
    fi
    if [ -e "$hook" ] && ! cmp -s "$hook" examples/claude-code/agentouch-guard.sh; then
        if grep -q 'jq -r' "$hook"; then
            echo "$hook is an older version that allows every command when jq is missing."
        else
            echo "$hook differs from the example:"
            diff "$hook" examples/claude-code/agentouch-guard.sh | head -20 || true
        fi
        if ask "Replace it with the example?"; then
            cp "$hook" "$hook.before-agentouch"
            cp examples/claude-code/agentouch-guard.sh "$hook"
            chmod 755 "$hook"
            echo "replaced it (backup: $hook.before-agentouch)"
        else
            echo "kept your existing $hook"
        fi
    else
        mkdir -p "$(dirname "$hook")"
        cp examples/claude-code/agentouch-guard.sh "$hook"
        chmod 755 "$hook"
        echo "installed the guard hook at $hook"
    fi
    if ! command -v jq >/dev/null; then
        echo "jq is missing, so settings.json wasn't changed; merge examples/claude-code/README.md by hand"
    else
        [ -e "$settings" ] || echo '{}' > "$settings"
        backup="$settings.before-agentouch-$(date +%Y%m%d-%H%M%S)"
        cp "$settings" "$backup"
        deny='["Edit(~/.config/agentouch/**)", "Edit(//usr/local/bin/agentouch)", "Edit(~/.claude/hooks/agentouch-guard.sh)"]'
        if ask "Also stop Claude from editing its own settings files (so it can't remove the hook; you then edit them yourself)?"; then
            deny='["Edit(~/.config/agentouch/**)", "Edit(//usr/local/bin/agentouch)", "Edit(~/.claude/hooks/agentouch-guard.sh)", "Edit(~/.claude/settings.json)", "Edit(~/.claude/settings.local.json)"]'
        fi
        jq --argjson deny "$deny" --arg cmd "~/.claude/hooks/agentouch-guard.sh" '
            .permissions.deny = ((.permissions.deny // []) + $deny | unique)
            | if ([.hooks.PreToolUse[]?.hooks[]?.command] | index($cmd)) != null then .
              else .hooks.PreToolUse = ((.hooks.PreToolUse // []) + [{matcher: "Bash", hooks: [{type: "command", command: $cmd, timeout: 10}]}])
              end' "$backup" > "$settings.new"
        cat "$settings.new" > "$settings"  # writes through a symlinked settings.json
        rm "$settings.new"
        echo "merged the deny rules and hook into $settings (backup: $backup)"
    fi
fi

say "Done"
cat <<'EOF'
Next:
  agentouch add gh-token --allow gh --env GH_TOKEN     store a token (Touch ID; paste it at the prompt)
  agentouch run gh-token -- gh auth status             use it (Touch ID shows the exact command)
For Bitwarden sign-ups and logins: bw login, then agentouch set-master (in your own terminal).
EOF
