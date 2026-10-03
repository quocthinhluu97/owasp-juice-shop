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

## Allowlists and why

Both live in `.gitleaks.toml`.

**1. Test files, by path, for two rules** (`^app/test/` and `^app/frontend/src/app/.+\.spec\.ts$`;
`jwt` and `generic-api-key` only). Juice Shop's tests hold forged JWTs and passwords for fake
users. Checked: none of them is a credential for anything real. Without this allowlist those
two rules produce 61 findings in test files, and no other rule fires there. Scoping it to
those two rules means a real private key or cloud token committed to a test is still reported.

**2. Ethereum addresses, by value.** The roadmap said "allowlist by path only". This one is an
exception, accepted for these reasons:

- **An address is not a secret.** It is a public on-chain identifier, like an account number
  printed on an invoice. Knowing it gives no access. `generic-api-key` flags it only because a
  name like `...Address = '0x...'` sits in front of a long hex string.
- **A path list would be worse.** Only one file is flagged today (`faucet.component.ts`), but
  addresses occur in about 20: `routes/web3Wallet.ts`, `data/static/codefixes/*`,
  `data/static/web3-snippets/*.sol` and several tests. Whether they get flagged depends on
  the variable name in front of them. A path entry hides *every* string in that file, and
  each newly flagged file would need another entry.
- **It is kept narrow.** It applies to one rule only (`generic-api-key`); it matches the
  extracted secret (`regexTarget = "secret"`), not the whole line; and `^0x[0-9a-fA-F]{40}$` is
  anchored to exactly 40 hex characters. An Ethereum **private key** is `0x` + 64 hex, so it
  is still reported.

**Remaining risk (accepted).** A real secret that happens to be exactly `0x` + 40 hex
characters would be hidden. That shape is what an address looks like, not what tokens or keys
from common providers look like.
