#!/usr/bin/env python3
"""
redact.py — local redaction tool for the agent permission audit intake.

Run this on YOUR OWN machine, against copies of your agent config files.
It reads the files, replaces every likely secret VALUE with a typed
placeholder that preserves the permission shape, and emits a submission
bundle (bundle-schema.json) with:

  - input C: your config documents, redacted;
  - input B: an index of the credentials it found (name, guessed service,
             storage location) — never their values;
  - inputs A / D / E: clearly marked stub sections for you to complete.

Guarantees:
  - No network access of any kind. This file contains no networking code.
  - Original secret values are never written anywhere. The only output is
    the redacted bundle and a summary of counts.
  - If a file cannot be parsed (malformed JSON, binary data), the tool
    FAILS LOUDLY and writes no bundle, rather than passing the file
    through untouched.

Usage:
  python3 redact.py CONFIG [CONFIG ...] [-o bundle.json]
  python3 redact.py --self-test

Exit codes: 0 ok · 1 self-test failure · 2 a file could not be processed
(aborted, nothing written) · 3 no readable input files.
"""

import argparse
import json
import math
import re
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

TOOL_NAME = "redact.py"
TOOL_VERSION = "1.0.0"

PLACEHOLDER = "<redacted:present>"
PLACEHOLDER_KEY = "<redacted:private-key>"

# ---------------------------------------------------------------------------
# Detection rules
# ---------------------------------------------------------------------------

# Key names that mark a VALUE as secret (PROBE-PACKAGE §6 patterns:
# *KEY / *TOKEN / *SECRET / *PASSWORD / *PRIVATE*, plus passwd).
SECRET_KEY_RE = re.compile(r"(key|token|secret|password|passwd|private)", re.IGNORECASE)

# Known secret formats, wherever they appear (value scans). Each entry:
# (pattern, category, service hint or None).
PREFIX_PATTERNS = [
    (re.compile(r"sk-(?:ant-|proj-)?[A-Za-z0-9_-]{10,}"), "known-prefix", None),
    (re.compile(r"ghp_[A-Za-z0-9]{20,}"), "known-prefix", "GitHub"),
    (re.compile(r"gho_[A-Za-z0-9]{20,}"), "known-prefix", "GitHub"),
    (re.compile(r"github_pat_[A-Za-z0-9_]{22,}"), "known-prefix", "GitHub"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "known-prefix", "AWS"),
    (re.compile(r"xox[baprs]-[A-Za-z0-9-]{8,}"), "known-prefix", "Slack"),
    (re.compile(r"AIza[0-9A-Za-z_-]{25,}"), "known-prefix", "Google"),
    (re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
     "known-prefix", None),  # JWT
]

PEM_BEGIN_RE = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
PEM_END_RE = re.compile(r"-----END [A-Z ]*PRIVATE KEY-----")

BEARER_RE = re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._\-+/=]{8,}")
URL_PASSWORD_RE = re.compile(r"([a-zA-Z][a-zA-Z0-9+.-]*://[^:\s/@]+:)([^@\s/]{3,})(@)")
TOKEN_CANDIDATE_RE = re.compile(r"[A-Za-z0-9+/=_-]{20,}")
UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
HEX_RE = re.compile(r"^[0-9a-fA-F]+$")

ENTROPY_THRESHOLD = 4.2  # bits per character
JSON_EXTS = {".json"}
TEXT_EXTS = {".yaml", ".yml", ".toml", ".env", ".ini", ".cfg", ".conf",
             ".txt", ".md", ".properties"}
KEY_MATERIAL_EXTS = {".pem", ".key"}

# Service guesses from key-name prefixes (input B convenience only).
SERVICE_HINTS = [
    (re.compile(r"^AWS_|^AMAZON_"), "AWS"),
    (re.compile(r"^GH_|^GITHUB_"), "GitHub"),
    (re.compile(r"^OPENAI_"), "OpenAI"),
    (re.compile(r"^ANTHROPIC_"), "Anthropic"),
    (re.compile(r"^STRIPE_"), "Stripe"),
    (re.compile(r"^CF_|^CLOUDFLARE_"), "Cloudflare"),
    (re.compile(r"^GOOGLE_|^GCP_|^GCLOUD_"), "Google Cloud"),
    (re.compile(r"^AZURE_"), "Azure"),
    (re.compile(r"^SLACK_"), "Slack"),
]


class RedactError(Exception):
    """A file could not be processed safely. Aborts the whole run."""


def new_counts():
    return {
        "private-key-block": 0,
        "secret-named-key": 0,
        "known-prefix": 0,
        "bearer-token": 0,
        "url-password": 0,
        "high-entropy": 0,
    }


def shannon_entropy(s):
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def looks_like_hash_or_id(token):
    """Long hex digests and UUIDs are identifiers/hashes, not secret values."""
    if UUID_RE.match(token):
        return True
    if HEX_RE.match(token) and len(token) in (32, 40, 64):
        return True
    return False


def char_classes(token):
    classes = 0
    if re.search(r"[a-z]", token):
        classes += 1
    if re.search(r"[A-Z]", token):
        classes += 1
    if re.search(r"[0-9]", token):
        classes += 1
    if re.search(r"[+/=_-]", token):
        classes += 1
    return classes


def redact_string_tokens(text, counts, found):
    """Token-level scans applied to any string value / line of text."""
    if not isinstance(text, str) or not text:
        return text

    if PEM_BEGIN_RE.search(text):
        # Whole PEM block inside a single string (common in JSON env blobs).
        text = PEM_BEGIN_RE.sub(PLACEHOLDER_KEY, text)
        counts["private-key-block"] += 1

    for pattern, category, service in PREFIX_PATTERNS:
        def _sub(m, category=category, service=service):
            counts[category] += 1
            if service:
                found.setdefault("__service_hint__", set()).add(service)
            return PLACEHOLDER
        text = pattern.sub(_sub, text)

    def _bearer(m):
        counts["bearer-token"] += 1
        return m.group(1) + PLACEHOLDER
    text = BEARER_RE.sub(_bearer, text)

    def _urlpw(m):
        counts["url-password"] += 1
        return m.group(1) + PLACEHOLDER + m.group(3)
    text = URL_PASSWORD_RE.sub(_urlpw, text)

    def _entropy(m):
        token = m.group(0)
        if token == PLACEHOLDER or looks_like_hash_or_id(token):
            return token
        if char_classes(token) >= 2 and shannon_entropy(token) >= ENTROPY_THRESHOLD:
            counts["high-entropy"] += 1
            return PLACEHOLDER
        return token
    text = TOKEN_CANDIDATE_RE.sub(_entropy, text)
    return text


def is_secret_key(name):
    return bool(SECRET_KEY_RE.search(str(name)))


def register_credential(found, key_name, filename):
    """Record a credential INDEX entry (name + guesses) — never the value."""
    name = str(key_name)
    entry = found.setdefault(name, {"files": set(), "name": name})
    entry["files"].add(filename)


def redact_json_obj(obj, counts, found, filename):
    if isinstance(obj, dict):
        out = {}
        for key, value in obj.items():
            if is_secret_key(key) and value not in (None, "", [], {}):
                counts["secret-named-key"] += 1
                register_credential(found, key, filename)
                out[key] = PLACEHOLDER
            else:
                out[key] = redact_json_obj(value, counts, found, filename)
        return out
    if isinstance(obj, list):
        return [redact_json_obj(v, counts, found, filename) for v in obj]
    if isinstance(obj, str):
        return redact_string_tokens(obj, counts, found)
    return obj


# key: value / key = value, incl. "export KEY=", YAML list "- KEY=value",
# quoted keys. Value part is captured for redaction.
KV_RE = re.compile(
    r"^(?P<indent>\s*(?:-\s*)?(?:export\s+)?[\"']?)"
    r"(?P<key>[A-Za-z0-9_.\-]+)"
    r"(?P<mid>[\"']?\s*[:=]\s*)"
    r"(?P<value>.*)$"
)


def redact_text_lines(text, counts, found, filename):
    lines = text.splitlines()
    out_lines = []
    in_pem = False
    pem_counted = False
    for line in lines:
        if in_pem:
            if PEM_END_RE.search(line):
                in_pem = False
            continue  # key material lines are dropped entirely
        if PEM_BEGIN_RE.search(line):
            in_pem = True
            pem_counted = True
            counts["private-key-block"] += 1
            indent = line[: len(line) - len(line.lstrip())]
            out_lines.append(indent + PLACEHOLDER_KEY)
            if PEM_END_RE.search(line):
                in_pem = False
            continue
        m = KV_RE.match(line)
        if m and is_secret_key(m.group("key")):
            raw_value = m.group("value").strip()
            # A trailing comment is not part of the value in .env-style files.
            if raw_value and not raw_value.startswith("#"):
                counts["secret-named-key"] += 1
                register_credential(found, m.group("key"), filename)
                quote = ""
                if raw_value[:1] in ("\"", "'"):
                    quote = raw_value[0]
                line = (m.group("indent") + m.group("key") + m.group("mid")
                        + quote + PLACEHOLDER + quote)
                out_lines.append(line)
                continue
        out_lines.append(redact_string_tokens(line, counts, found))
    if in_pem:
        raise RedactError(
            f"{filename}: unterminated PRIVATE KEY block — refusing to guess; "
            "fix the file and re-run.")
    return "\n".join(out_lines) + ("\n" if text.endswith("\n") else "")


def guess_service(key_name, found):
    for pattern, service in SERVICE_HINTS:
        if pattern.search(key_name.upper()):
            return service
    return "unknown"


def guess_credential_type(key_name, filename):
    upper = key_name.upper()
    if "SSH" in upper or filename.endswith((".pem", ".key")):
        return "ssh-key"
    if "OAUTH" in upper:
        return "oauth-token"
    if "ROLE" in upper or "ARN" in upper:
        return "iam-role"
    if "SERVICE_ACCOUNT" in upper or "SERVICEACCOUNT" in upper:
        return "service-account"
    return "api-key"


def guess_storage(filename):
    if filename.startswith(".env") or filename.endswith(".env"):
        return "env"
    if "workflow" in filename.lower() or ".github" in filename:
        return "ci-secret"
    return "config-file"


def doc_format(path):
    suffix = path.suffix.lower()
    if suffix == ".json":
        return "json"
    if suffix in (".yaml", ".yml"):
        return "yaml"
    if suffix == ".toml":
        return "toml"
    if suffix == ".env" or path.name.startswith(".env"):
        return "env"
    return "text"


def process_file(path, counts, found):
    """Return a config_documents entry for one file, or raise RedactError."""
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise RedactError(f"{path}: cannot read file ({exc.strerror or exc})")
    if b"\x00" in raw:
        raise RedactError(f"{path.name}: binary content detected — refusing to "
                          "process. Export a text config instead.")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise RedactError(f"{path.name}: not valid UTF-8 — refusing to process "
                          "rather than pass bytes through unexamined.")

    suffix = path.suffix.lower()
    filename = path.name
    if suffix in KEY_MATERIAL_EXTS:
        # A standalone key file: the entire content is key material.
        counts["private-key-block"] += 1
        register_credential(found, path.stem, filename)
        content = PLACEHOLDER_KEY + "\n"
    elif suffix in JSON_EXTS:
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError as exc:
            raise RedactError(
                f"{filename}: JSON parse failed ({exc.msg} at line {exc.lineno}) "
                "— refusing to pass an unparsed file through. Fix the file "
                "(comments/trailing commas are common causes) and re-run.")
        redacted = redact_json_obj(parsed, counts, found, filename)
        content = json.dumps(redacted, indent=2) + "\n"
    elif suffix in TEXT_EXTS or suffix == "" or filename.startswith(".env"):
        content = redact_text_lines(text, counts, found, filename)
    else:
        raise RedactError(
            f"{filename}: unsupported file type '{suffix}'. Supported: "
            ".json, .yaml, .yml, .toml, .env, .ini, .cfg, .conf, .txt, .md, "
            ".pem, .key. Convert or export the config to a supported text "
            "format and re-run.")
    return {"filename": filename, "format": doc_format(path), "content": content}

def collect_files(paths):
    files = []
    for raw_path in paths:
        p = Path(raw_path)
        if p.is_dir():
            for child in sorted(p.rglob("*")):
                if child.is_file() and ".git" not in child.parts:
                    files.append(child)
        elif p.is_file():
            files.append(p)
        else:
            raise RedactError(f"{raw_path}: no such file or directory")
    return files


def build_bundle(documents, found, agent_id, now_iso):
    credentials = []
    for name in sorted(found):
        if name == "__service_hint__":
            continue
        entry = found[name]
        first_file = sorted(entry["files"])[0] if entry["files"] else ""
        credentials.append({
            "credential_ref": name,
            "service": guess_service(name, found),
            "credential_type": guess_credential_type(name, first_file),
            "storage_location": guess_storage(first_file),
            "value_included": False,
        })
    agent = {
        "agent_id": agent_id,
        "name": "TODO: name this agent/harness (input A)",
        "purpose": "TODO: what this agent is for, in your words (input A)",
        "systems_touched": [],
        "active_last_month": True,
        "credentials": credentials,
        "configuration": {"config_documents": documents},
        "activity": {
            "sources": [],
            "coverage_note": (
                "TODO (input D): add last month's actual work — session/tool-call "
                "logs, deploy history, git history of agent-made commits, or cloud "
                "audit exports, summarised as actions_exercised where you can. "
                "Thin records are common and do not block the audit; they are "
                "named in the write-up."),
        },
        "constraints": [],
    }
    return {
        "schema_version": "1.0",
        "bundle_id": str(uuid.uuid4()),
        "generated_at": now_iso,
        "generator": {"name": TOOL_NAME, "version": TOOL_VERSION},
        "redaction_attestation": {
            "attested": True,
            "attested_at": now_iso,
            "method": "redact.py",
            "tool_name": TOOL_NAME,
            "tool_version": TOOL_VERSION,
        },
        "team": {
            "contact": {"email": "todo@example.com"},
        },
        "agents": [agent],
        "global_constraints": [],
        "coverage": {
            "inputs_included": ["C"],
            "missing_inputs": ["A", "B", "D", "E"],
            "notes": (
                "Generated by redact.py. Input C is complete (redacted config "
                "documents). Input B is PARTIAL: the credential index above was "
                "derived from secret-bearing key names — complete it before "
                "submitting (scope_summary and action_classes per credential, "
                "plus any credential that lives outside config files, e.g. in a "
                "vault or CI settings). Inputs A, D, E are stubs to complete. "
                "Also replace team.contact.email (todo@example.com) with the "
                "address the write-up should go to."),
        },
        "submitter_notes": (
            "Before submitting: complete the TODO stubs (inputs A, D, E), finish "
            "each credential's scope_summary and action_classes (input B), set "
            "team.contact.email, and confirm no secret value appears anywhere in "
            "this file — search it for your key prefixes. The submission endpoint "
            "runs its own secret sweep and will reject the bundle if one slipped "
            "through."),
    }


def run(paths, output, agent_id):
    counts = new_counts()
    found = {}
    files = collect_files(paths)
    if not files:
        print("ERROR: no input files found.", file=sys.stderr)
        return 3
    documents = []
    try:
        for f in files:
            documents.append(process_file(f, counts, found))
    except RedactError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        print("No bundle was written. Nothing was sent anywhere (this tool "
              "never transmits).", file=sys.stderr)
        return 2
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    bundle = build_bundle(documents, found, agent_id, now_iso)
    out_path = Path(output)
    out_path.write_text(json.dumps(bundle, indent=2) + "\n", encoding="utf-8")

    total = sum(counts.values())
    print(f"Scanned {len(documents)} file(s); redacted {total} item(s):",
          file=sys.stderr)
    for category in sorted(counts):
        if counts[category]:
            print(f"  {category}: {counts[category]}", file=sys.stderr)
    cred_count = len([k for k in found if k != '__service_hint__'])
    print(f"Credential index entries (input B, to complete): {cred_count}",
          file=sys.stderr)
    print(f"Bundle written to {out_path}. Review it, complete the TODO stubs "
          "(inputs A, B details, D, E), then submit.", file=sys.stderr)
    return 0


# ---------------------------------------------------------------------------
# Self-test: fixture configs WITH fake secrets go in; a bundle comes out;
# no fake secret value may survive anywhere in the output.
# ---------------------------------------------------------------------------

FAKE_SECRETS = {
    "json sk- key": "sk-proj-FAKE0TEST1SECRET2VALUE3XXXX",
    "json ghp_ token": "ghp_FAKE0TEST1TOKEN2VALUE3000000000aa",
    "env AWS secret": "FAKEawsSECRETkey/0123456789+abcdefgHIJ",
    "env password": "FAKE-hunter2-password-98765",
    "yaml high-entropy value": "Xk9Qm2Zv8Lp4Rt7Nw3Hs6Jd1Fc5Vb0Ga",
    "yaml pem body": "FAKEKEYMATERIALBASE64LINE000111222333444555",
    "toml password": "FAKE-toml-password-123456",
    "text sk-ant key (neutral context)": "sk-ant-FAKE0TEST1SECRET2VALUE3ZZZZ",
    "text bearer token": "FAKEbearerTOKEN0123456789abcdef",
}
SENTINELS = ["us-east-1", "https://example.com/docs", "gpt-5"]  # must survive


def _fixtures(tmp):
    (tmp / "agent-config.json").write_text(json.dumps({
        "openai": {"api_key": FAKE_SECRETS["json sk- key"], "model": "gpt-5"},
        "github": {"token": FAKE_SECRETS["json ghp_ token"]},
        "region": "us-east-1",
        "docs": "https://example.com/docs",
    }, indent=2), encoding="utf-8")
    (tmp / ".env").write_text(
        "AWS_SECRET_ACCESS_KEY=" + FAKE_SECRETS["env AWS secret"] + "\n"
        "DATABASE_PASSWORD=" + FAKE_SECRETS["env password"] + "\n"
        "MODEL_NAME=gpt-5\n", encoding="utf-8")
    (tmp / "config.yaml").write_text(
        "webhook_signing_material: " + FAKE_SECRETS["yaml high-entropy value"] + "\n"
        "tls:\n"
        "  private_key: |\n"
        "    -----BEGIN PRIVATE KEY-----\n"
        "    " + FAKE_SECRETS["yaml pem body"] + "\n"
        "    -----END PRIVATE KEY-----\n", encoding="utf-8")
    (tmp / "settings.toml").write_text(
        'password = "' + FAKE_SECRETS["toml password"] + '"\n'
        'region = "us-east-1"\n', encoding="utf-8")
    (tmp / "scratch.txt").write_text(
        "temp openai key: " + FAKE_SECRETS["text sk-ant key (neutral context)"] + "\n"
        "Authorization: Bearer " + FAKE_SECRETS["text bearer token"] + "\n",
        encoding="utf-8")
    (tmp / "broken.json").write_text('{"api_key": "x", }', encoding="utf-8")


def run_self_test():
    import tempfile
    checks = []

    def check(label, ok):
        checks.append((label, ok))
        print(f"  [{'PASS' if ok else 'FAIL'}] {label}")

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        _fixtures(tmp)
        good_files = [tmp / "agent-config.json", tmp / ".env",
                      tmp / "config.yaml", tmp / "settings.toml",
                      tmp / "scratch.txt"]
        counts = new_counts()
        found = {}
        documents = [process_file(f, counts, found) for f in good_files]
        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        bundle = build_bundle(documents, found, "self-test-agent", now_iso)
        bundle_text = json.dumps(bundle, indent=2)

        print("redact.py self-test")
        for label, secret in FAKE_SECRETS.items():
            check(f"fake secret redacted ({label})", secret not in bundle_text)
        for sentinel in SENTINELS:
            check(f"non-secret value preserved ({sentinel})",
                  sentinel in bundle_text)
        check("placeholders present", PLACEHOLDER in bundle_text)
        check("private-key placeholder present", PLACEHOLDER_KEY in bundle_text)
        try:
            parsed = json.loads(bundle_text)
            check("bundle parses as JSON", True)
        except json.JSONDecodeError:
            parsed = None
            check("bundle parses as JSON", False)
        if parsed:
            check("schema_version is 1.0", parsed.get("schema_version") == "1.0")
            check("redaction attested",
                  parsed["redaction_attestation"]["attested"] is True)
            creds = parsed["agents"][0]["credentials"]
            check("credential index non-empty (input B derived)", len(creds) >= 3)
            check("every credential value_included is false",
                  all(c["value_included"] is False for c in creds))
            check("redaction counts recorded in all categories used",
                  counts["secret-named-key"] >= 3 and counts["known-prefix"] >= 1
                  and counts["bearer-token"] >= 1
                  and counts["private-key-block"] >= 1
                  and counts["high-entropy"] >= 1)
        # Fail-loud behaviour: malformed JSON must abort, never pass through.
        try:
            process_file(tmp / "broken.json", new_counts(), {})
            check("malformed JSON aborts loudly", False)
        except RedactError:
            check("malformed JSON aborts loudly", True)

    failed = [label for label, ok in checks if not ok]
    if failed:
        print(f"SELF-TEST FAILED: {len(failed)} check(s) failed.")
        return 1
    print(f"SELF-TEST PASSED: all {len(checks)} checks passed.")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Redact secret values from agent config files and emit an "
                    "audit submission bundle (inputs B/C; A/D/E stubbed). "
                    "Runs fully locally; never transmits anything.")
    parser.add_argument("paths", nargs="*", help="config files or directories")
    parser.add_argument("-o", "--output", default="audit-bundle.json",
                        help="bundle output path (default: audit-bundle.json)")
    parser.add_argument("--agent-id", default="agent-1",
                        help="slug for the agent entry (default: agent-1)")
    parser.add_argument("--self-test", action="store_true",
                        help="run the built-in fixture test and exit")
    args = parser.parse_args(argv)
    if args.self_test:
        return run_self_test()
    if not args.paths:
        parser.error("give at least one config file or directory (or --self-test)")
    try:
        return run(args.paths, args.output, args.agent_id)
    except RedactError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
