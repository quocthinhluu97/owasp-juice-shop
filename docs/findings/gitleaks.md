## What Gitleaks missed

Two files hold secrets but were not reported by the default rules:

| File | What it is |
|---|---|
| `app/ctf.key` | Key used to generate CTF flag codes (30 bytes) |
| `app/encryptionkeys/premium.key` | Key that unlocks Juice Shop's "premium" content (50 bytes) |

**Why they were missed.** Gitleaks detects a secret in one of two ways:
1. **Known format**: the value has a recognisable shape (e.g. `ghp_…`, `-----BEGIN RSA PRIVATE KEY-----`).
2. **Context**: the `generic-api-key` rule catches unknown formats when a name such as
   `key`, `token` or `secret` appears just before the value (`API_KEY=…`).

Both files contain only a bare value: no known format, no name in front of it. Neither way applies.
I reproduced this in a lab repo: a bare `ghp_…` token was found, a bare random string was not.

**What I did.** Added a custom rule to `.gitleaks.toml` that flags any file ending in `.key`,
based on the file name alone:

    [[rules]]
    id = "key-files"
    path = '''\.key$'''

Result: 6 → 8 findings; both files are now reported (at "line 0", because the rule matches
the file, not a line). `encryptionkeys/jwt.pub` is a public key and correctly not matched.
Both new findings are deliberate Juice Shop challenge material and will be waived in Phase 7,
like the other 6.

**Lesson.** Gitleaks finds secrets that *look like* secrets. A clean report means
"nothing matched the rules", not "there are no secrets". Custom rules can close known gaps,
but only gaps you already know about.
