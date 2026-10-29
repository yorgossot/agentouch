# agentouch

Let an AI coding agent use your secrets on a Mac without ever seeing them, one fingerprint at a
time.

```
$ agentouch run gh-token -- gh pr list
```

The Touch ID sheet reads roughly:

> **Touch ID** · use “gh-token” to run: /opt/homebrew/bin/gh pr list

The agent asks for a command. You see that exact command in the Touch ID prompt. Only after your
touch does `agentouch` decrypt the token and hand it to that one process: as an environment variable
or on stdin, never on the command line or in the agent's context. The token is redacted from
the command's output.

`agentouch` can also sign you up for websites: it generates a password, saves the login straight
into your Bitwarden vault, and puts the password on the clipboard for the form — one touch, and
the agent never sees the password.

Two Swift files, no daemon, no dependencies beyond macOS (and the Bitwarden CLI, if you
want sign-ups). **Unofficial; not affiliated with Bitwarden.**

## Threat model

Read this before relying on `agentouch`. It is a guardrail for a well-meaning agent, not a
sandbox for a hostile one.

**What it protects:** the values of your stored secrets, your Bitwarden master password, and
the passwords of accounts it creates.

**Who it defends against:** an AI agent that has shell access as your user and that
- **makes mistakes**: pastes a token into a log, runs the wrong command, uses your real email;
- **is steered by prompt injection**: a web page, email, issue, README or tool output tells it
  to send a token somewhere, print it, store a new one, or sign up somewhere.

The agent is assumed to follow its instructions and to use `agentouch` the documented way. It may be
fooled about *what* to ask for, but it is not trying to break `agentouch` itself.

**Assumptions:**
- You are the only user of the Mac, and its login and Touch ID are yours.
- You read the Touch ID prompt and **approve only what matches something you asked for**.
  This is the central control; everything else narrows what a single careless approval can do.
- The binary is installed root-owned in a root-owned directory (below), so replacing it needs
  your password, and the agent calls it by its absolute path, `/usr/local/bin/agentouch`.
- Programs in `/opt/homebrew/bin`, `/usr/local/bin`, `/usr/bin` and `/bin` are trustworthy.

**In scope, handled:**

| Threat | Defence |
|---|---|
| Secret appears in the agent's context, transcript or logs | Values are only ever handed to the approved process (env or stdin) and redacted from its output (raw, hex, URL-encoded, base64) |
| Agent runs a command you didn't intend | Fingerprint per use, showing the exact command; no password fallback, no reuse of an earlier touch |
| Injected instruction sends a token to an attacker | Host pinning for curl: https to pinned hosts only, no proxies, redirects, config files or output files; destination shown first in the prompt |
| Agent pipes a secret through a printing program | Common printing programs (shells, interpreters, `cat`, `env`, `tee`, `sed`, `jq`, `base64`…) are refused when you add a secret; programs are resolved by lower-case name from fixed directories only. This catches the obvious; **the allow-list you approve is the real boundary** (`git -c alias.x='!…'`, for one, is a shell in disguise, left to your reading of the prompt) |
| Homoglyphs or hidden characters in the prompt | Commands, sites and notes must be plain ASCII, one line, short enough to show in full (a typo-squat like `gooogle.com` is still plain ASCII: read the prompt) |
| Store edited to widen access (allow `cat`, drop a host pin) | Name, delivery, allowed programs and hosts are bound into each secret's ciphertext; any edit makes it fail to decrypt |
| Planted `node`, proxy or `DYLD_` variables hijack a tool | Child processes get a pinned `PATH` and a scrubbed environment |
| Agent swaps in its own secret, or deletes yours | Fingerprint for every add and removal; the prompt says when a secret is being replaced |
| Agent signs up with an ordinary address such as your Gmail | `login-new` takes only plain domains, and usernames that are plain or at an email-alias service |
| Master password handed to a program | Stored under a reserved name that `run` can never deliver |
| Vault reachable from a web page, or left unlocked after a crash | `bw serve` listens only on a private Unix socket, never a network port; it is locked and stopped on exit, and a watcher kills it if `agentouch` is killed |
| "Did the agent do something in my name?" | Every approval, decline and outcome is logged to `~/.config/agentouch/log` |

**Out of scope, not handled:**

- **Malicious code running as your user**, including a truly hostile agent. Any program you run
  can show its own Touch ID prompt with any text, and can use the store's Secure Enclave key
  after a touch. If you run untrusted code, `agentouch` won't save you.
- **You approving a prompt you didn't read.** A careless touch on a plausible-looking prompt
  gives that one command its secret.
- **What an approved command does with the secret.** `agentouch run gh-token -- gh api ...` runs
  with the token's full power, and a pinned host still receives whatever you approve sending it.
  Use narrowly scoped tokens.
- **Your whole vault, if you store the master password and approve a spoofed prompt.** Code
  running as you could show a sign-up-looking prompt and, after your touch, unseal the master
  password. Storing it is optional: it is only needed for `login-new`.
- **Encodings and side channels beyond the four above**, files the command writes, and secrets
  shorter than 6 bytes (not redacted, to avoid mangling ordinary output).
- **Other users or root on the same Mac, physical attacks, a compromised OS or Homebrew.**
- **Pasting into the wrong page.** The sign-up password goes to the clipboard; keeping it on
  the right site is the agent's instruction, not something `agentouch` enforces. It is a fresh
  password, so the loss is limited to that one new account.
- **Brief exposure to your own processes during a save.** For about two seconds the unlocked
  vault is reachable through `bw serve` on a Unix socket that only your user can open. No
  network port is opened, so web pages and other users can't reach it; code running as you
  could, which is already out of scope above.

## Install

Needs a Mac with Touch ID, macOS 14 or later, and Swift 5.10 or later (Xcode 15.3+, or
`xcode-select --install`).

```sh
git clone https://github.com/yorgossot/agentouch && cd agentouch
./tests/run.sh          # optional: the checks run without Touch ID
./build.sh
sudo mkdir -p /usr/local/bin
ls -ld /usr/local/bin   # must show root wheel, see below
sudo install -o root -g wheel -m 755 agentouch /usr/local/bin/agentouch
agentouch init                # creates the Secure Enclave key
```

Installing it root-owned means an agent can't quietly replace the binary: that would need
`sudo`, which asks you. That only holds if `/usr/local/bin` itself is root-owned. On Intel Macs
with Homebrew it usually belongs to you, and then a root-owned file in it can still be renamed
away. Fix it with `sudo chown root:wheel /usr/local/bin && sudo chmod 755 /usr/local/bin` (Intel
Homebrew will then need `sudo` to link there), or install somewhere root-owned and call that
path instead. Rebuild and reinstall yourself after reading the diff; `agentouch --version` shows the
commit it was built from, and so does every log line.

## Use

```sh
# Store a secret (Touch ID). Paste it at the hidden prompt, pipe it in, or copy it first:
agentouch add gh-token --allow gh --env GH_TOKEN
gh auth token | agentouch add gh-token --allow gh --env GH_TOKEN
agentouch add openai --allow curl --stdin --hosts api.openai.com --from-clipboard

# Use it (Touch ID, showing the exact command):
agentouch run gh-token -- gh pr list
agentouch run openai -- curl -sS -H @- https://api.openai.com/v1/models

agentouch list                # names, delivery, allowed programs and hosts; never values
agentouch rm gh-token         # Touch ID
agentouch password            # a new password onto the clipboard, never printed
```

`--hosts` pins a curl secret to those hosts: every URL must be https on one of them, and curl
may only use options that can't send the request anywhere else (`-s -S -f -i -H -d -X -m -A`
and their long forms, plus `--compressed --data-raw --data-binary --json --connect-timeout
--fail-with-body`, each written separately). `agentouch` adds `-q` so curl's
config files are ignored.

Programs are given by lower-case name. A few tools that start like an interpreter (`nodemon`,
`rubocop`) or have capitals (`Rscript`) can't be allowed; that's deliberate, failing closed.

A stdin secret is sent with a trailing newline, as most tools read a line. For curl, store the
whole header (`Authorization: Bearer …`) and pass `-H @-`.

## Sign-ups saved to Bitwarden

Needs the [Bitwarden CLI](https://bitwarden.com/help/cli/) (`brew install bitwarden-cli`),
logged in once with `bw login`.

```sh
agentouch set-master          # once, in your own terminal: Touch ID, then your master password
agentouch login-new --site example.com --username quiet.fox@icloud.com --task "newsletter"
```

`login-new` asks for one touch, then generates a 24-character password, unlocks the vault,
refuses if a login for that site and username already exists, saves the new login to the
folder "Agent sign-ups" with a note saying when and why, locks the vault, and puts the password
on the clipboard (marked concealed, cleared after 90 s). It never edits or deletes vault items
and prints nothing from the vault.

The username must be a plain username or an address at an email-alias service (`aliasDomains` in
`Sources/agentouch.swift`: iCloud Hide My Email, SimpleLogin, DuckDuckGo, Proton, addy.io,
Firefox Relay), so an agent can't use an ordinary address such as a Gmail. Some of these domains
also host real mailboxes (`icloud.com`, `duck.com`, `addy.io`); if yours is one, remove it from
the list and rebuild.

The master password is stored like any other secret but under a reserved name with no allowed
programs, so `agentouch run` can never hand it out. Vault access goes through a short-lived
`bw serve` listening on a Unix socket in a private (0700) temporary directory, so no network
port is ever opened. It is locked and stopped before `agentouch` returns, and a watcher process
stops it and removes the socket if `agentouch` is killed first. One process serves the whole
save, because each plain `bw` command idles about two seconds before exiting in Bitwarden CLI
2026.10 ([fixed upstream](https://github.com/bitwarden/clients/pull/23953)).

Right after a sync, `bw` can briefly list no items at all
([bitwarden/clients#23283](https://github.com/bitwarden/clients/issues/23283)), so
`login-new` looks again before believing an empty vault, rather than letting a duplicate
through. This relies on `bw serve`'s REST API, which may change between Bitwarden CLI releases;
over a socket it currently needs the header `Host: localhost:8087`
([bitwarden/clients#22867](https://github.com/bitwarden/clients/issues/22867)).

## With Claude Code

- [`examples/skill/SKILL.md`](examples/skill/SKILL.md) is a skill that teaches Claude to use
  `agentouch` and to sign up for sites (fill in your alias service).
- [`examples/claude-code/`](examples/claude-code/) has a `PreToolUse` hook and deny rules that
  stop Claude from touching `~/.config/agentouch` or running `sudo`. It's a guardrail against
  mistakes, not a sandbox.

The same approach works with any agent that runs shell commands.

## How it works

- `agentouch init` creates a P-256 key in the Secure Enclave whose use needs biometry (any enrolled
  finger). Its private part never leaves the chip.
- Each secret is encrypted with ChaCha20-Poly1305 under a key from ECDH between a one-off key
  and the Secure Enclave key (HKDF-SHA256). The secret's name, delivery, allowed programs and
  hosts are the associated data.
- `agentouch run` checks the request, builds the prompt, asks for Touch ID, and passes the
  authenticated context to the Secure Enclave, so one touch covers both.
- Programs are found only in `/opt/homebrew/bin`, `/usr/local/bin`, `/usr/bin` and `/bin`, and
  run with a pinned `PATH` and without proxy, `NODE_`, `DYLD_`, `GIT_`, `GH_`, `CURL_` and
  similar variables.

## License

MIT
