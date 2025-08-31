# PP-SecCommit

**PP-SecCommit** is a zero-dependency, single-file Git hook that prevents secrets and high-entropy tokens from slipping into your repository.  
It runs locally on **RHEL/Rocky** (and most Linux distros with Python 3) and enforces a **hard stop** on risky commits by default.

> **Policy**  
> • `git commit` (no flags): if **anything** suspicious is found (secrets or entropy), the commit is **blocked**.  
> • `git commit -m "allow"`: the commit **always passes**, but all findings are shown as **WARN** with actionable guidance.

---

## Why this exists

Hard-coded credentials remain a leading cause of breaches: tokens, keys, and passwords frequently end up in commits, CI logs, and artifacts. Shifting this control **left**—to the developer’s machine—catches issues **before** they ever reach a remote repository.  
**PP-SecCommit** focuses on essentials: **one file**, **stateless**, **offline**, **no ceremony**.

- **Single file.** No installers, no package managers, no extra directories.
- **Stateless.** It writes nothing to disk and remembers nothing between runs.
- **Offline.** No network calls; everything runs locally.
- **Universal.** Works in **any** Git repo once symlinked as a hook.

---

## What it detects (out of the box)

- **Private keys**: `-----BEGIN … PRIVATE KEY-----` (RSA/EC/DSA/OpenSSH/PGP).
- **AWS**:  
  - Access Key IDs `AKIA[0-9A-Z]{16}`  
  - Secret Access Keys (40-char base64-like)
- **GitHub** Personal Access Tokens: `ghp_` + 36 chars
- **GitLab** Personal Access Tokens: `glpat-` + 20+ chars
- **Google** API keys: `AIza` + 35 chars
- **Slack** tokens: `xox[baprs]-…`
- **Generic secrets**: assignments like `secret|api_key|token|password = <long value>`
- **High-entropy strings**: base64/hex-looking tokens above a threshold (Shannon entropy)

> **Heuristics**  
> • Only **staged, text** files are scanned (binary files and >1 MB blobs are skipped).  
> • Findings are printed with minimal masking to avoid re-exposing secrets in logs.

---

## Quick start (RHEL/Rocky)

1) **Add the single file** to your repository root (name it exactly as your code file, e.g. `pp_seccommit.py`).  
2) **Link it** as a Git hook (no copies; just a symlink):

```bash
chmod +x ./pp_seccommit.py
ln -sf "$PWD/pp_seccommit.py" .git/hooks/prepare-commit-msg
```

That’s it. The hook now runs on every `git commit`.

> **Why `prepare-commit-msg`?**  
> It triggers **before** Git opens an editor, so risky commits are blocked early (no editor pop-ups).  
> If you *also* want to run after the message is written, you can symlink the same file as `.git/hooks/commit-msg`—the logic is identical.

---

## Usage

**Default, enforcing mode**  
```bash
git add .
git commit
# → If any secrets or high-entropy values are found, the commit is BLOCKED.
```

**Allow override (warn-only, always pass)**  
```bash
git add .
git commit -m "allow"
# → All findings are WARN; the commit proceeds.
```

> **Tip (optional): make `git commit` fully non-interactive**  
> If you dislike editors opening when there are **no** findings, set a no-op editor just for this repo:  
> `git config core.editor 'sh -c "echo auto > \"$1\"" -'`  
> Now `git commit` writes "auto" as the message and exits without opening an editor.

---

## Test locally (1 minute)

```bash
# Create a “dangerous” file
cat > ppsec_test.txt <<'EOF'
GITHUB_PAT="ghp_abcdefghijklmnopqrstuvwxyzABCD1234"
AWS_ACCESS_KEY_ID=AKIAABCDEFGHIJKLMNOP
AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
jwt_like="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.QWxhZGRpbjpvcGVuIHNlc2FtZQ=="
EOF

git add ppsec_test.txt

# 1) Enforcing (no flags)  → should BLOCK
git commit

# 2) Allow override        → should PASS with WARN
git commit -m "allow"
```

---

## Output, at a glance

**Enforcing example (`git commit`)**
```
PP-SecCommit report (ENFORCING MODE: HIGH on ALL findings):

Findings:
  app.py:12 [HIGH/GITHUB_PAT] -> ghp***234 (len=40)
    Fix steps:
      - Revoke the token in GitHub (Developer settings → Tokens).
      - Create a least-privilege token and store it as a CI secret.
      - Local Git cleanup example:
        git restore --staged <file> && sed -i 's/<secret>/<placeholder>/' <file>
        git add <file> && git commit --amend --no-edit
      - If already pushed: rewrite history with git filter-repo or BFG.

Commit BLOCKED: findings are HIGH by policy (no flags).
```

**Allow example (`git commit -m "allow"`)**
```
PP-SecCommit report (ALLOW MODE: WARN only):

Findings:
  app.py:12 [WARN/GITHUB_PAT] -> ghp***234 (len=40)
  ...
Override: commit message is 'allow' → NOT blocking (alerts only).
```

---

## Configuration (env vars, optional)

```
Variable                         Default   Meaning
------------------------------   -------   -----------------------------------------------
PPSECCOMMIT_MAX_BYTES            1000000   Max file size to scan (bytes)
PPSECCOMMIT_ENTROPY_THRESHOLD    4.0       Shannon entropy threshold for entropy candidates
PPSECCOMMIT_MIN_LEN              20        Minimum token length considered for entropy
```

Example:
```bash
PPSECCOMMIT_ENTROPY_THRESHOLD=4.3 git commit
```

---

## Security playbook (when you find a real secret)

1. **Revoke/rotate** the credential at its provider (GitHub/GitLab/AWS/Google/Slack, etc.).  
2. **Remove** the secret from the code and commit a sanitized replacement.  
3. **Amend** locally if not pushed:
   ```bash
   git restore --staged <file> && sed -i 's/<secret>/<placeholder>/' <file>
   git add <file> && git commit --amend --no-edit
   ```
4. If already pushed, **rewrite history** (e.g., `git filter-repo` or **BFG Repo-Cleaner**) and force-push with care.  
5. Add a permanent control (CI secret store, env vars, templates) to stop recurrence.

---

## Design principles

- **Blocking by default**: shift-left control that actually prevents mistakes.  
- **Stateless**: no caches or local databases; every run re-scans staged files.  
- **Single file**: easy to audit, easy to vendor, easy to remove.  
- **Deterministic output**: actionable steps printed for each finding.  
- **No noise**: only staged text is scanned; binaries and very large files are ignored.

---

## Roadmap (contributions welcome)

- Additional providers/patterns (Azure, Stripe, Twilio, Telegram, Discord).  
- Server-side **pre-receive** mode (same scanner applied to pushed commit ranges).  
- Machine-readable output (JSON/SARIF) for CI aggregation.  
- Optional per-repo policy file (allowlists/thresholds) — disabled by default to keep MVP minimal.

---

## Compatibility

- **OS**: RHEL/Rocky (tested), should work on most Linux distros with Python 3.  
- **Git**: any modern Git that supports hook scripts and symlinks.  
- **Dependencies**: none (standard Python 3 library only).  
- **Network**: not required (fully offline).

---

---

## Support & Feedback

If **PP-SecCommit** saved you from an “oops moment,” consider ⭐ **starring** the repo.  
Bugs or ideas? Open a GitHub issue with a short repro (no real secrets, please).

## Security

Do **not** share actual credentials in issues. Provide redacted samples only.  
If a sensitive report is unavoidable, share it privately with the maintainers.

## License

Licensed under the **[Apache-2.0 License](LICENSE)**.  




