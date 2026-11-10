# agent-permission-audit

The local redaction tool and submission contract for NonceLogic's read-only
**agent permission audit** — a diff of what your agents are *allowed* to do
(standing permissions) against what they *actually did* last month.

Intake page (the offer, the handling terms, the form, and the API):
**https://audit-intake-noncelogic.vercel.app**
Sample report — the same audit run on NonceLogic's own setup:
https://audit-intake-noncelogic.vercel.app/sample

## The one rule

**Never send a secret value.** Not a live API key, not a token value, not a
password, not a private key. The audit reads permission *shapes* — service,
scope, role, policy — and action *metadata*. What a credential can do is
determined by its scope and role; neither document contains a secret value.

`redact.py` exists so that rule is easy to keep: it runs on **your** machine,
replaces secret values with typed placeholders that preserve the permission
shape, and emits the submission bundle. Nothing unredacted ever leaves your
side.

## Redaction in 3 steps

1. **Download** `redact.py` — a single, dependency-free Python 3 file. Read
   it first; it's short, and it contains no networking code.
2. **Run it on copies of your configs:**

   ```
   python3 redact.py path/to/configs -o bundle.json
   ```

   It replaces secret values with typed placeholders
   (`"api_key": "<redacted:present>"`), prints a summary of what it redacted
   **by category and count only**, and fails loudly if it meets a file it
   cannot parse — it never passes a file through unexamined. It writes
   nothing but the redacted bundle.
3. **Review the bundle, complete the stubs** (your agent inventory, last
   month's activity, your constraints, and each credential's scopes and
   action classes), then submit it via the form or the API at the intake
   page. Search the bundle for your key prefixes first — trust, but verify,
   including this tool.

## Verify the tool before you trust it

```
python3 redact.py --self-test
```

The self-test runs fixture configs (JSON, .env, YAML, TOML, plain text)
carrying fake secrets across every detection class — secret-named keys,
known token prefixes, private-key blocks, bearer tokens, high-entropy
values — and proves none of them survive into the emitted bundle, while
non-secret values (a region, a docs URL, a model name) are preserved, and
malformed JSON aborts loudly instead of passing through.

## What's in this repo

| File | What it is |
|---|---|
| `redact.py` | The local redaction tool (Python 3, standard library only, no network code). |
| `bundle-schema.json` | The submission bundle contract (JSON Schema, draft 2020-12). Credential objects structurally cannot hold a secret value: no extra fields are admitted, and each credential must affirm `value_included: false`. |

## Guarantees the tool makes

- No network access of any kind. This file contains no networking code.
- Original secret values are never written anywhere. The only output is the
  redacted bundle and a summary of counts.
- If a file cannot be parsed (malformed JSON, binary data), the tool fails
  loudly and writes no bundle, rather than passing the file through
  untouched.

## How the audit handles your material

Read-only. Your material is used for your audit and nothing else, never
shared or published, and is deleted within 7 days of your write-up being
delivered — you can withdraw and have everything deleted at any point,
including after delivery. The full handling terms are stated on the intake
page, before any submission path — that's when they matter.
