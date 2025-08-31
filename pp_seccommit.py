#!/usr/bin/env python3
# PP-SecCommit: single-file Git hook for secret & entropy detection
# Hook modes supported:
#   - prepare-commit-msg: runs BEFORE the editor; aborts commit early if needed.
#   - commit-msg: runs AFTER the message; also supported (same script).
# Policy (per spec):
#   - Default (git commit without -m "allow"): ANY finding => HIGH => BLOCK.
#   - Override (git commit -m "allow"): ALL findings => WARN => DO NOT block.
# Scope:
#   - Scans STAGED text files only. Stateless. No extra dirs/files.

import argparse
import math
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import List, Dict, Tuple, Optional

TOOL_NAME = "PP-SecCommit"
MAX_BYTES = int(os.environ.get("PPSECCOMMIT_MAX_BYTES", 1_000_000))
ENTROPY_THRESHOLD = float(os.environ.get("PPSECCOMMIT_ENTROPY_THRESHOLD", 4.0))
MIN_ENTROPY_LEN = int(os.environ.get("PPSECCOMMIT_MIN_LEN", 20))

# High-confidence secret patterns
PATTERNS: List[Tuple[str, re.Pattern]] = [
    ("PRIVATE_KEY", re.compile(r"-----BEGIN (?:RSA|EC|DSA|OPENSSH|PGP) PRIVATE KEY-----")),
    ("AWS_ACCESS_KEY_ID", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("AWS_SECRET_KEY", re.compile(r"(?i)aws(.{0,20})?(secret|access)[-_ ]?key(.{0,20})?[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?")),
    ("GITHUB_PAT", re.compile(r"ghp_[A-Za-z0-9]{36}")),
    ("GITLAB_PAT", re.compile(r"glpat-[A-Za-z0-9\-_]{20,}")),
    ("GOOGLE_API_KEY", re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("SLACK_TOKEN", re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,48}")),
    ("GENERIC_SECRET", re.compile(r"(?i)(secret|api[_-]?key|token|password)\s*[:=]\s*['\"]?([A-Za-z0-9_\-/.+=]{16,})['\"]?")),
]

# Entropy candidates
ENTROPY_RES = [
    re.compile(r"[A-Za-z0-9+/=]{20,}"),   # base64-like
    re.compile(r"[0-9a-fA-F]{24,}"),      # hex-like
]

ADVICE: Dict[str, List[str]] = {
    "PRIVATE_KEY": [
        "Remove the private key from Git immediately.",
        "Rotate the key at its provider; never store private keys in Git.",
    ],
    "AWS_ACCESS_KEY_ID": [
        "Pair with the secret; rotate/deactivate in IAM.",
        "Store credentials in AWS Secrets Manager or CI variables.",
        "CLI: aws iam list-access-keys --user-name <user>",
    ],
    "AWS_SECRET_KEY": [
        "Deactivate & rotate the exposed access key.",
        "CLI: aws iam update-access-key --user-name <user> --access-key-id <id> --status Inactive",
        "CLI: aws iam delete-access-key --user-name <user> --access-key-id <id>",
    ],
    "GITHUB_PAT": [
        "Revoke the token in GitHub (Developer settings → Tokens).",
        "Recreate with least privilege and store as a CI secret.",
    ],
    "GITLAB_PAT": [
        "Revoke the token in GitLab (User settings → Access tokens).",
        "Recreate with least privilege; store as CI/CD variable.",
    ],
    "GOOGLE_API_KEY": [
        "Restrict by IP/referrer and rotate.",
        "CLI: gcloud services api-keys list / delete <KEY_ID>",
    ],
    "SLACK_TOKEN": [
        "Regenerate token in Slack App settings and redeploy services.",
    ],
    "GENERIC_SECRET": [
        "Rotate at provider; remove hard-coded secrets from source.",
        "Use env vars or a secrets manager.",
    ],
    "HIGH_ENTROPY": [
        "If real secret: rotate/revoke and remove it from history.",
        "If false positive: replace with a safer placeholder before committing.",
    ],
}

def run_git(args: List[str]) -> bytes:
    return subprocess.checkoutput(["git"] + args)

def run_git_safe(args: List[str]) -> Optional[bytes]:
    try:
        return subprocess.check_output(["git"] + args)
    except Exception:
        return None

def staged_paths() -> List[str]:
    out = run_git_safe(["diff", "--cached", "--name-only", "-z"]) or b""
    parts = out.split(b"\x00")
    return [p.decode() for p in parts if p]

def get_staged_blob(path: str) -> Optional[bytes]:
    try:
        return subprocess.check_output(["git", "show", f":{path}"])
    except subprocess.CalledProcessError:
        return None

def is_binary(buf: bytes) -> bool:
    if b"\x00" in buf:
        return True
    text_chars = bytearray({7,8,9,10,12,13,27} | set(range(0x20, 0x100)))
    nontext = sum(ch not in text_chars for ch in buf)
    return (nontext / max(1, len(buf))) > 0.30

def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: Dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    H = 0.0
    L = len(s)
    for c in freq.values():
        p = c / L
        H -= p * math.log2(p)
    return H

def mask_secret(fragment: str) -> str:
    frag = fragment.strip()
    if len(frag) <= 6:
        return "***"
    return f"{frag[:3]}***{frag[-3:]} (len={len(frag)})"

def scan_text(path: str, text: str) -> List[Dict]:
    findings: List[Dict] = []
    for idx, line in enumerate(text.splitlines(), start=1):
        for label, pat in PATTERNS:
            for m in pat.finditer(line):
                findings.append({
                    "path": path, "line": idx, "label": label,
                    "kind": "SECRET", "match": mask_secret(m.group(0)),
                })
        for cre in ENTROPY_RES:
            for m in cre.finditer(line):
                frag = m.group(0)
                if len(frag) < MIN_ENTROPY_LEN:
                    continue
                H = shannon_entropy(frag)
                if H >= ENTROPY_THRESHOLD:
                    findings.append({
                        "path": path, "line": idx, "label": "HIGH_ENTROPY",
                        "kind": "ENTROPY", "match": f"{mask_secret(frag)} | H={H:.2f}",
                    })
    return findings

def scan_staged() -> List[Dict]:
    findings: List[Dict] = []
    for path in staged_paths():
        blob = get_staged_blob(path)
        if not blob or len(blob) > MAX_BYTES or is_binary(blob):
            continue
        text = blob.decode("utf-8", errors="replace")
        findings.extend(scan_text(path, text))
    return findings

def print_fix(label: str) -> None:
    tips = ADVICE.get(label, []) or ADVICE.get("GENERIC_SECRET", [])
    for t in tips:
        print(f"      - {t}")
    print("      - Local Git cleanup example:")
    print("        git restore --staged <file> && sed -i 's/<secret>/<placeholder>/' <file>")
    print("        git add <file> && git commit --amend --no-edit")
    print("      - If already pushed: rewrite history with git filter-repo or BFG.")

def print_report(findings: List[Dict], allow_mode: bool) -> None:
    if not findings:
        print(f"{TOOL_NAME}: no findings.")
        return
    if allow_mode:
        print(f"{TOOL_NAME} report (ALLOW MODE: WARN only):")
    else:
        print(f"{TOOL_NAME} report (ENFORCING MODE: HIGH on ALL findings):")

    print("\nFindings:")
    for f in findings:
        sev = "WARN" if allow_mode else "HIGH"
        print(f"  {f['path']}:{f['line']} [{sev}/{f['label']}] -> {f['match']}")
        print("    Fix steps:")
        print_fix(f["label"])

    if allow_mode:
        print("\nOverride: commit message is 'allow' → NOT blocking (alerts only).")
    else:
        print("\nCommit BLOCKED: findings are HIGH by policy (no flags).")

def read_commit_message(path: Optional[str]) -> str:
    if not path:
        return ""
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace").strip()
    except Exception:
        return ""

def main() -> int:
    parser = argparse.ArgumentParser(
        description="PP-SecCommit (prepare-commit-msg / commit-msg)"
    )
    # In both hooks, first positional arg is the commit message file path.
    parser.add_argument("commit_msg_file", nargs="?", help="Path to commit message file.")
    # prepare-commit-msg also passes optional args (we ignore them safely)
    parser.add_argument("hook_opt1", nargs="?", default=None)
    parser.add_argument("hook_opt2", nargs="?", default=None)
    args = parser.parse_args()

    msg = read_commit_message(args.commit_msg_file)
    allow_mode = (msg.lower() == "allow")

    findings = scan_staged()
    print_report(findings, allow_mode)

    if allow_mode:
        return 0
    return 1 if findings else 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except subprocess.CalledProcessError as e:
        print(f"{TOOL_NAME}: git error: {e}", file=sys.stderr)
        sys.exit(2)
    except Exception as e:
        print(f"{TOOL_NAME}: runtime error: {e}", file=sys.stderr)
        sys.exit(2)
