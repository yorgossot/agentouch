---
name: agentouch
description: Use or store credentials behind the user's Touch ID via `agentouch`, and sign up for websites on their behalf (email alias + generated password saved straight into Bitwarden). Use when a task needs a login, API token or secret, when registering or creating an account somewhere, or when the user says "use my Bitwarden", "get the password for X" or "sign me up".
---

# Secrets and sign-ups via `agentouch`

<!-- Example skill for Claude Code. Copy to ~/.claude/skills/agentouch/SKILL.md and fill in step 1 of
     "Signing up" with your email-alias service, or delete that step. -->

`agentouch` holds secrets sealed to this Mac's Secure Enclave. Every use, add and removal asks the user for a fingerprint, and the Touch ID prompt shows the exact command or the name being stored. Always call it by its absolute path, `/usr/local/bin/agentouch`, so a look-alike earlier in PATH can't stand in for it (the examples below write `agentouch` for short). Before running anything that prompts, tell the user to expect it. If they decline (`not approved`), stop and ask; don't retry.

## Using a stored secret

- `agentouch list` shows names, delivery (`env VAR` or `stdin`), allowed programs and pinned hosts. It never shows values.
- `agentouch run NAME[,NAME] -- PROG ARGS...` runs the command. `agentouch` hands the secret to PROG and redacts it from the output.
  - Give PROG by name (looked up in /opt/homebrew/bin, /usr/local/bin, /usr/bin, /bin). Keep the command short (≤200 characters) and plain ASCII.
  - Secrets with pinned hosts (`→ host` in `agentouch list`) only go to those hosts over https. curl may then use only `-s -S -f -i --compressed -H -d --data-raw --data-binary --json -X -m -A`, written separately (`-f -sS`, not `-fsS`); `agentouch` adds `-q` itself. Anything else is refused before any prompt.
- There is no command that prints a secret. Don't look for one, and don't read or edit `~/.config/agentouch/`. If `[redacted NAME]` appears in output, don't try to recover it.

## Storing a secret

`agentouch add NAME --allow PROG[,PROG] (--env VAR | --stdin) [--hosts H[,H]] [--from-clipboard]` needs Touch ID every time. The prompt says if it replaces an existing secret.

- **From the user's clipboard:** they copy the secret, you run the add with `--from-clipboard`, they touch. `agentouch` clears the clipboard afterwards.
- **From another tool:** pipe it straight in, so the value never appears in your output: `gh auth token | agentouch add gh-token --allow gh --env GH_TOKEN`.
- Prefer `--stdin` when the tool can read the secret from stdin.
- For an API token used with curl, pin its host: `--allow curl --hosts api.example.com`, and store the whole header line (`Authorization: Bearer …`) so curl can read it with `-H @-`.

## Signing up somewhere for the user

1. **Email alias.** <!-- Describe your alias service here, e.g. SimpleLogin:
   `agentouch run simplelogin -- curl -sS -H @- --json '{"note":"<why>"}' "https://app.simplelogin.io/api/alias/random/new?hostname=<site>"`
   with the secret stored as the header line `Authentication: <API key>` and pinned to app.simplelogin.io.
   Note its rate limits; never batch-create aliases. -->
2. **Create and save the login.**
   - Run `agentouch login-new --site <domain> --username <alias> --task "<why, short>"`.
   - One Touch ID: `agentouch` generates a 24-character password and saves the login to Bitwarden (folder "Agent sign-ups"). The vault is locked again before it returns.
   - The password is then on the clipboard for 90 s and is never printed.
   - Do this *before* submitting the form, so a failed page never loses the password.
   - In the browser, click the password field and press ⌘V (and in the confirm field). Paste only into the password fields of the top-level page on the `--site` domain: never into an iframe, a popup or a page on another domain. Never type the password with a form-fill or type action, and don't read the clipboard: either would put it in the transcript.
   - If the 90 s run out, ask the user to copy it from Bitwarden. Don't run `login-new` again: it refuses a second login for the same site and username.
   - If it says no master password is stored, ask the user to run `agentouch set-master` once in their own terminal.
   - `--username` must be an email-alias address or a plain username. `--site` must be a plain domain.
   - For sites that only need a password, without saving it, `agentouch password` just puts one on the clipboard.
3. **Fill in and submit the form.** Stop and ask the user at CAPTCHAs, payment or card details, phone verification, terms beyond an ordinary signup, or anything that commits them to something.
4. **Report** the site, the alias, and whether the signup went through. Never the password. If it failed, say so: the Bitwarden item exists, and the user can delete it.

Not for critical accounts: banks, Apple ID, email recovery, government. Those get the user's real address and their own hand.

## Rules

- Never write a secret or a password to chat, files, memory, commits or artifacts.
- Never run `bw` against the user's vault, and never open the Bitwarden web vault.
