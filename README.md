# agentouch

Let an AI coding agent use your secrets on a Mac without ever seeing them, one fingerprint at a
time. **Unofficial; not affiliated with Bitwarden.**

## Quick start

Needs a Mac with Touch ID, macOS 14+, and the Xcode command-line tools (`xcode-select --install`).

```sh
git clone https://github.com/yorgossot/agentouch && cd agentouch
./install.sh                  # tests, builds, installs root-owned to /usr/local/bin (asks your password), creates the key
gh auth token | agentouch add gh-token --allow gh --env GH_TOKEN    # Touch ID
agentouch run gh-token -- gh pr list                                # Touch ID shows this exact command
./install.sh --claude-code    # optional: Claude Code skill + guard hook
```

Your agent calls `/usr/local/bin/agentouch run …`; you approve each use with a fingerprint.
`agentouch doctor` checks the setup. Bitwarden sign-ups and logins: [below](#bitwarden-optional).
Read the [threat model](#threat-model) before relying on it.

## What it does

The agent asks for a command. You see that exact command in the Touch ID prompt:

> **agentouch is trying to USE “gh-token”**
> **by running: /opt/homebrew/bin/gh pr list.**

Only after your touch does `agentouch` decrypt the token and hand it to that one process, as an
environment variable or on stdin: never on the command line or in the agent's context. The token
is redacted from the command's output. Every prompt starts with the action in capitals (`SEND
“api-key” to 🌐 api.example.com`, `LOG IN AS YOU on 🌐 example.com`, `BLOCK 3 LOGINS FROM
AGENTS`), with the details below.

With Bitwarden it can also sign you up for websites (a fresh password, saved straight into your
vault, onto the clipboard for the form) and log you in with a saved password, while the logins
you mark critical stay out of the agent's reach.

## Secrets

```sh
# Store a secret (Touch ID). Paste it at the hidden prompt, pipe it in, or copy it first:
agentouch add gh-token --allow gh --env GH_TOKEN
gh auth token | agentouch add gh-token --allow gh --env GH_TOKEN
agentouch add openai --allow curl --stdin --hosts api.openai.com --from-clipboard

agentouch run gh-token -- gh pr list          # Touch ID, showing the exact command
agentouch run openai -- curl -sS -H @- https://api.openai.com/v1/models
agentouch list                                # names, delivery, programs, hosts; never values
agentouch rm gh-token                         # Touch ID
```

- `--hosts` pins a curl secret to those hosts: every URL must be https on one of them, and curl
  may only use options that can't send the request anywhere else (`-s -S -f -i -H -d -X -m -A`
  and their long forms, plus `--compressed --data-raw --data-binary --json --connect-timeout
  --fail-with-body`, each written separately). `agentouch` adds `-q` so curl's config files are
  ignored.
- A stdin secret is sent with a trailing newline, as most tools read a line. For curl, store the
  whole header (`Authorization: Bearer …`) and pass `-H @-`.
- Programs are given by lower-case name and looked up in fixed directories. Shells, interpreters
  and other programs that could just print a secret can't be allowed (a few tools that start
  like an interpreter, such as `nodemon`, are caught too; that's deliberate, failing closed).

## Bitwarden (optional)

Needs the [Bitwarden CLI](https://bitwarden.com/help/cli/) (`brew install bitwarden-cli`), logged
in once with `bw login`. Then, in your own terminal:

```sh
agentouch set-master        # Touch ID, then your master password (stored sealed, used by the commands below)
agentouch protect           # Touch ID; choose, in a window, which logins agents may never get
```

**Keeping critical logins away from agents.** `protect` opens a window on your Mac listing your
logins. On the first run the ones that look critical are ticked (email, identity, password
managers, banks, brokers, crypto, government and tax: the lists in `Sources/critical.swift`,
plus logins whose notes hold something like a seed phrase); after that, your current list is.
What you leave ticked is blocked: `login` refuses it, and you log in to those sites yourself.
Unticking a blocked login unblocks it, after a second Touch ID that says how many. Nothing
changes in Bitwarden, the names stay in the window, and only counts are printed. The list is
sealed like a secret, so it can't be edited behind agentouch's back.

```sh
agentouch protect --block 1a2b3c4d          # Touch ID; block by item id
agentouch protect --reprompt                # the window, but marks Bitwarden's "master password re-prompt"
examples/suggest-critical.sh                # let Claude pre-tick the window (sends names to Anthropic; asks first)
```

`--reprompt` changes the items in Bitwarden, which also makes Bitwarden ask *you* for the master
password when you use them. It only ever turns re-prompt on, re-reads each item to check nothing
else changed, and skips items with a passkey or attachments, or shared through an organisation,
since editing those through the Bitwarden CLI could lose data. Export your vault first.

**Signing up.** `signup` asks for one touch, generates a 24-character password, refuses if a login
for that site and username already exists, saves the login to the folder "Agent sign-ups" with a
note saying when and why, and puts the password on the clipboard (marked concealed, cleared after
90 s). It never edits or deletes vault items.

```sh
agentouch signup --site example.com --username quiet.fox@icloud.com --task "newsletter"
```

The username must be plain or at an email-alias service (`aliasDomains` in
`Sources/agentouch.swift`: iCloud Hide My Email, SimpleLogin, DuckDuckGo, Proton, addy.io,
Firefox Relay), so an agent can't use an ordinary address such as a Gmail. Some of these domains
also host real mailboxes (`icloud.com`, `duck.com`, `addy.io`); if yours is one, remove it and
rebuild.

**Logging in.** `login` asks for one touch naming the site, finds the login saved for exactly
that host (or its `www.` form: name `accounts.google.com`, not `google.com`, if that's what the
login is saved under), prints its username and puts its password on the clipboard for 30 s.
Blocked logins, and logins marked re-prompt or with URI match "Never" in Bitwarden, are refused.
If the site has several logins, it lists their usernames and asks for `--username`.

```sh
agentouch login --site example.com      # Touch ID; prints the username
agentouch clear                         # once the password has been pasted
```

`agentouch password` puts a fresh password on the clipboard without saving it anywhere.

## With Claude Code

`./install.sh --claude-code` installs
- [`examples/skill/SKILL.md`](examples/skill/SKILL.md), a skill that teaches Claude to use
  `agentouch`, sign up and log in; and
- the guard hook and deny rules from [`examples/claude-code/`](examples/claude-code/), which stop
  Claude from touching `~/.config/agentouch`, the hook or its settings, or running `sudo`. A
  guardrail against mistakes, not a sandbox.

Existing files are never overwritten, and `~/.claude/settings.json` is backed up and merged. The
same approach works with any agent that runs shell commands.

## Threat model

Read this before relying on `agentouch`. It is a guardrail for a well-meaning agent, not a sandbox
for a hostile one.

**What it protects:** the values of your stored secrets, your Bitwarden master password, the
passwords of accounts it creates, and the passwords it fetches for logging in.

**Who it defends against:** an AI agent that has shell access as your user and that
- **makes mistakes**: pastes a token into a log, runs the wrong command, uses your real email;
- **is steered by prompt injection**: a web page, email, issue, README or tool output tells it
  to send a token somewhere, print it, store a new one, sign up somewhere, or log in somewhere.

The agent is assumed to follow its instructions and to use `agentouch` the documented way. It may
be fooled about *what* to ask for, but it is not trying to break `agentouch` itself.

**Assumptions:**
- You are the only user of the Mac, and its login and Touch ID are yours.
- You read the Touch ID prompt and **approve only what matches something you asked for**. This is
  the central control; everything else narrows what a single careless approval can do.
- The binary is installed root-owned in a root-owned directory, so replacing it needs your
  password, and the agent calls it by its absolute path, `/usr/local/bin/agentouch`.
- Programs in `/opt/homebrew/bin`, `/usr/local/bin`, `/usr/bin` and `/bin` are trustworthy. On
  Apple Silicon `/opt/homebrew/bin` belongs to you, so code running as you could replace a tool
  there; that's within the "not hostile" assumption, but worth knowing.
- Right after `set-master`, before giving an agent the skill, you block the logins you'd never
  want an agent to touch (`agentouch protect`).

**In scope, handled:**

| Threat | Defence |
|---|---|
| Secret appears in the agent's context, transcript or logs | Values are only ever handed to the approved process (env or stdin) and redacted from its output (raw, hex, URL-encoded, base64) |
| Agent runs a command you didn't intend | Fingerprint per use, showing the exact command; no password fallback, no reuse of an earlier touch |
| Injected instruction sends a token to an attacker | Host pinning for curl: https to pinned hosts only, no proxies, redirects, config files or output files; destination shown first in the prompt |
| Agent pipes a secret through a printing program | Common printing programs (shells, interpreters, `cat`, `env`, `tee`, `sed`, `jq`, `base64`…) are refused when you add a secret; programs are resolved by lower-case name from fixed directories only. This catches the obvious; **the allow-list you approve is the real boundary** (`git -c alias.x='!…'`, for one, is a shell in disguise, left to your reading of the prompt) |
| Homoglyphs or hidden characters in the prompt | Commands, sites and notes must be plain ASCII, one line, short enough to show in full (a typo-squat like `gooogle.com` is still plain ASCII: read the prompt) |
| Store edited to widen access (allow `cat`, drop a host pin, edit the blocked list) | Each secret's name, delivery, allowed programs and hosts are bound into its ciphertext, and the blocked list is sealed too; an edit makes it fail to decrypt, and `login` then refuses. Deleting the blocked list from `store.json` outright isn't detected; the Claude Code guard's deny rules are what stop an agent editing that file |
| Planted `node`, proxy or `DYLD_` variables hijack a tool | Child processes get a pinned `PATH` and a scrubbed environment |
| Agent swaps in its own secret, or deletes yours | Fingerprint for every add and removal; the prompt says when a secret is being replaced |
| Agent signs up with an ordinary address such as your Gmail | `signup` takes only plain domains, and usernames that are plain or at an email-alias service |
| Master password handed to a program | Stored under a reserved name that `run` can never deliver |
| Injected instruction asks for one of your saved passwords | `login` hands out one password per touch, only for the exact site named in the prompt (subdomains and look-alikes get nothing), never for blocked logins or ones marked re-prompt or URI match "Never", and only to the clipboard for 30 s |
| Vault reachable from a web page, or left unlocked after a crash | `bw serve` listens only on a private Unix socket, never a network port; it is locked and stopped on exit, and a watcher kills it if `agentouch` is killed |
| "Did the agent do something in my name?" | Every approval, decline and outcome is logged to `~/.config/agentouch/log` |

**Out of scope, not handled:**

- **Malicious code running as your user**, including a truly hostile agent. Any program you run
  can show its own Touch ID prompt with any text, and can use the store's Secure Enclave key after
  a touch. If you run untrusted code, `agentouch` won't save you.
- **You approving a prompt you didn't read.** A careless touch on a plausible-looking prompt gives
  that one command its secret.
- **What an approved command does with the secret.** `agentouch run gh-token -- gh api ...` runs
  with the token's full power, and a pinned host still receives whatever you approve sending it.
  Use narrowly scoped tokens.
- **Your whole vault, if you store the master password and approve a spoofed prompt.** Code
  running as you could show a sign-up-looking prompt and, after your touch, unseal the master
  password. Storing it is optional: it is only needed for `signup`, `login` and `protect`.
- **Encodings and side channels beyond the four above**, files the command writes, and secrets
  shorter than 6 bytes (not redacted, to avoid mangling ordinary output).
- **Other users or root on the same Mac, physical attacks, a compromised OS or Homebrew.**
- **Pasting into the wrong page.** Sign-up and login passwords go to the clipboard; keeping them on
  the right site is the agent's instruction, not something `agentouch` enforces. For a sign-up
  the password is fresh, so the loss is limited to that one new account; for `login` it is that
  site's existing password.
- **Reading a filled field back.** Once pasted, the password is in the page, where a
  browser-driving agent could read the field. The example skill tells the agent never to read
  password fields; `agentouch` can't enforce that.
- **Clipboard readers.** While a password is on the clipboard (30 s for `login`, 90 s for
  sign-ups, or until `agentouch clear`), any process running as you can read it, and Universal
  Clipboard may copy it to your other Apple devices. It is marked concealed, which well-behaved
  clipboard managers skip.
- **Brief exposure to your own processes during a save.** For about two seconds the unlocked vault
  is reachable through `bw serve` on a Unix socket that only your user can open. No network port
  is opened, so web pages and other users can't reach it; code running as you could, which is
  already out of scope above.
- **`examples/suggest-critical.sh` sends the names and sites of your logins to Anthropic's API**
  when you run it and say yes. Everything else stays on your Mac.

## Install details

`./install.sh` checks this Mac (macOS 14+, Swift 5.10+, Touch ID), shows the commit it's about to
install and asks before installing uncommitted changes, runs the tests, builds, and installs
`/usr/local/bin/agentouch` owned by root. Run it yourself, in a terminal: it refuses to run
without one, so an agent can't run it for you. To update, `git pull`, read the diff, and run it
again; `agentouch --version` shows the commit it was built from, and so does every log line.

Installing it root-owned means an agent can't quietly replace the binary: that would need `sudo`,
which asks you. That only holds if `/usr/local/bin` itself is root-owned; on Intel Macs with
Homebrew it usually belongs to you, and the installer offers to fix that (Intel Homebrew then
needs `sudo` to link there). For the same reason there's no Homebrew formula: Homebrew installs
into a directory you own, which would undo this.

The manual equivalent:

```sh
./tests/run.sh && ./build.sh
sudo mkdir -p /usr/local/bin && ls -ld /usr/local/bin    # must show root wheel
sudo install -o root -g wheel -m 755 agentouch /usr/local/bin/agentouch
agentouch init
```

## How it works

- `agentouch init` creates a P-256 key in the Secure Enclave whose use needs biometry (any enrolled
  finger). Its private part never leaves the chip.
- Each secret is encrypted with ChaCha20-Poly1305 under a key from ECDH between a one-off key and
  the Secure Enclave key (HKDF-SHA256). The secret's name, delivery, allowed programs and hosts are
  the associated data.
- `agentouch run` checks the request, builds the prompt, asks for Touch ID, and passes the
  authenticated context to the Secure Enclave, so one touch covers both.
- Programs run with a pinned `PATH` and without proxy, `NODE_`, `DYLD_`, `GIT_`, `GH_`, `CURL_`
  and similar variables.
- Bitwarden access goes through a short-lived `bw serve` on a Unix socket in a private (0700)
  temporary directory, locked and stopped before `agentouch` returns. One process serves each
  operation because plain `bw` commands idle about two seconds before exiting in Bitwarden CLI
  2026.10 ([fixed upstream](https://github.com/bitwarden/clients/pull/23953)). Right after a
  sync, `bw` can briefly list no items
  ([bitwarden/clients#23283](https://github.com/bitwarden/clients/issues/23283)), so an empty
  vault is checked again before it's believed. Over a socket `bw serve` currently needs the header
  `Host: localhost:8087` ([bitwarden/clients#22867](https://github.com/bitwarden/clients/issues/22867)).
  This relies on `bw serve`'s REST API, which may change between releases.
- The code is in `Sources/` (`main.swift` for the commands, `agentouch.swift` for the rest,
  `review.swift` for the window, `critical.swift` for the suggestion lists). `./tests/run.sh`
  runs the checks, which need no Touch ID.

## License

MIT
