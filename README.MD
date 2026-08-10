# AI-PWNDOC

Automated vulnerability writing for [PwnDoc](https://github.com/pwndoc/pwndoc) using AI.

Takes a folder of Obsidian-style `.md` notes — one per vulnerability — analyses the text and any embedded screenshots, and pushes fully structured findings directly into a PwnDoc audit. Supports **Claude** (Anthropic API), **Claude Code** (local CLI, your normal subscription) and **Gemini** (CLI).

![graph](graph.png)

---

## Project structure

```
├── ai-pwndoc.py
├── config.yml
├── requirements.txt
├── vulnerabilities.yml
└── SampleAudits
    ├── ADPentest
    │   ├── AS-REP ROASTING.md
    │   ├── AS-REP1.png
    │   ├── AS-REP2.png
    │   ├── AS-REP3.png
    │   ├── RBCD1.png
    │   ├── RBCD2.png
    │   ├── RBCD3.png
    │   └── Resource-Based Constrained Delegation.md
    └── WebAudit
        ├── MA1.png
        ├── MA2.png
        ├── MA3.png
        ├── MASS ASSIGMENT.md
        ├── Server-Side Template Injection.md
        ├── SSTI1.png
        └── SSTI2.png
```

---

## How it works

Each `.md` is an auditor's raw note. Images are referenced inline using Obsidian syntax (`![[image.png]]`) and must sit in the same folder as the note. The script:

1. Parses each note and extracts embedded image references
2. **Searches the knowledge base** for the write-ups closest to the note — only when `-e` is given
3. Calls the AI to generate structured vulnerability JSON (title, description, observation, affected assets, remediation, CVSS, etc.), **reusing the matching knowledge base entry literally** when there is one
4. Calls the AI again per image to generate a technical description and caption
5. Uploads images to PwnDoc and assembles the `poc` field with descriptions + inline images + `alt` captions
6. Pushes the finding to the selected (or newly created) audit

### Field semantics

| Field | Content |
|---|---|
| `description` | Theoretical explanation of the vulnerability class — how it works, why it exists, generic attack scenario. No client names, hosts, URLs or engagement-specific evidence. |
| `observation` | Impact of this specific finding, explicitly covering **confidentiality**, **integrity** and **availability**. If a property is not affected, that is stated too. |
| `affectedAssets` | The assets where the finding was confirmed, read from the note **and the screenshots**. Goes into PwnDoc's `scope` field, one asset per line. |

These semantics apply to text the AI writes itself. When a knowledge base entry matches, its text wins and is copied as-is — see [Knowledge base](#knowledge-base--e).

### Affected assets

Extracted from what is actually visible in the evidence — the main AI call receives the screenshots, so a host in a Burp `Host:` header or an `-dc-ip` argument in a terminal capture is picked up. One line per asset, normalised to a fixed shape and nothing else — no paths, no query strings, no commentary:

| Asset | Format | Example |
|---|---|---|
| Web | `scheme://host:port` | `https://app.example.com:443` |
| Anything else | `host:port` | `10.10.10.192:88` |

`host` is the IP or domain exactly as it appears in the evidence. The port is always stated; when it is not visible, the service default is used (`80`, `443`, `22`, `445`, `389`, `636`, `3389`, `1433`, `3306`). Assets are never invented and never copied from a knowledge base entry — it is the one field always written from this engagement's evidence. Duplicates are removed, and the result is uploaded as `<p>asset</p>` per line, matching how past reports fill the field.

---

## Audit selection

If `--audit-id` is not given, the script lists the audits available in PwnDoc and lets you pick one, **or create a new one on the fly**:

```
  1. Web App Acme 2026   6657f1a2c3b4e500123abc
  2. AD Internal Pentest 6657f1a2c3b4e500123def
  n. Create new audit
Select audit number (or 'n' for new):
```

Choosing `n` prompts for:

1. **Audit name**
2. **Language** — pulled from PwnDoc (`GET /api/data/languages`), shown as `Español (es)`, `English (en)`, …
3. **Audit type** — pulled from PwnDoc (`GET /api/data/audit-types`)

The audit is created via `POST /api/audits` and findings are pushed into it straight away. If PwnDoc does not return the language/type catalogues, both fields fall back to free text input. Invalid selections re-prompt instead of aborting.

---

## Requirements

```bash
pip3 install -r requirements.txt
```

`requirements.txt` includes: `requests`, `urllib3`, `pyyaml`, `rich`.

| Provider | Needs | Billing |
|---|---|---|
| `claude` | Anthropic API key, no CLI | Pay per token |
| `claude-code` | [Claude Code](https://claude.com/claude-code) CLI installed and logged in (`claude`) | Your Claude subscription — `ANTHROPIC_API_KEY` is stripped from the environment so it never falls back to the API |
| `gemini` | [Gemini CLI](https://github.com/google-gemini/gemini-cli) installed and authenticated | Gemini CLI account |

---

## Configuration

Create `config.yml` at the project root (next to `ai-pwndoc.py`):

```yaml
# ─────────────────────────────────────────
# AI-PWNDOC : CONFIGURATION
# ─────────────────────────────────────────

pwndoc:
  base_url: "https://localhost:8443"
  username: "admin"
  password: "admin"
  verify_ssl: false

llm:
  provider: "claude"                    # claude | claude-code | gemini

  # provider: claude → Anthropic REST API (pay per token)
  anthropic_api_key: "sk-ant-..."
  claude_model: "claude-haiku-4-5"      # claude-opus-4-6 | claude-sonnet-4-6 | claude-haiku-4-5

  # provider: claude-code → local Claude Code CLI, uses your normal subscription login.
  # No API key needed; run `claude` once and log in.
  claude_code_binary: "claude"          # path to the claude CLI
  claude_code_model: ""                 # "" = CLI default | opus | sonnet | haiku | full model id
  claude_code_timeout: 300              # seconds per call
```

`gemini` needs no config keys — the CLI handles its own auth.

---

## Knowledge base (`-e`)

**Optional.** Without `-e` the script runs exactly the same, but there is nothing to reuse: every finding is written from scratch, in the neutral register of a professional pentest report, and the wording will not match your past reports. The run starts with a warning saying so. Use this mode for a first audit, or when you don't have an export at hand.

With `-e`, the `.yml` is not just a style sample — it is the **source of truth for the wording**. For every note the script ranks the whole file and injects the closest entries into the prompt, with a hard instruction: *if one of them covers the same vulnerability, copy `description`, `observation`, `remediation`, `references`, `cvssv3`, `vulnType`, `priority` and `remediationComplexity` character for character, HTML included*. Only details contradicted by the note (versions, ports, affected components) may be adapted; everything else stays byte-identical, so the report keeps the exact terminology the team already agreed on.

A note about *"TLS 1.0 and 1.1 still enabled, RC4 and 3DES accepted"* therefore comes back written with the existing **"Algoritmos de cifrado SSL/TLS obsoletos"** text, not with a fresh paraphrase. Only when nothing in the file matches does the AI write from scratch, imitating the tone, vocabulary and HTML structure of the entries it was shown. The console prints which entry was reused (`reused KB entry: …`) or warns that the finding was `written from scratch`.

### Format

Both shapes are accepted — a PwnDoc export (`Vulnerabilities → Export`) is the intended input:

```yaml
# PwnDoc export: one entry per locale under `details`
- cvssv3: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
  priority: 4
  remediationComplexity: 2
  category: null
  details:
    - locale: es
      title: "Inyección SQL"
      vulnType: "Web"
      description: "<p>La aplicación concatena la entrada del usuario…</p>"
      observation: "<p>Confidencialidad: …</p>"
      remediation: "<p>Utilizar consultas parametrizadas…</p>"
      references:
        - "https://owasp.org/www-community/attacks/SQL_Injection"
```

```yaml
# Flat list — also works
- title: "SQL Injection in login endpoint"
  vulnType: "Web"
  description: "<p>The login form is vulnerable to SQL injection…</p>"
  observation: "<p>By sending a payload of ' OR 1=1--…</p>"
  remediation: "<p>Use parameterised queries or a prepared statement ORM.</p>"
  remediationComplexity: 2
  priority: 4
  references:
    - "https://owasp.org/www-community/attacks/SQL_Injection"
  cvssv3: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
```

### Retrieval

Matching is lexical (BM25) and runs locally — no embeddings, no extra dependency, no extra API call:

- Only entries whose `locale` matches `--lang` are searchable — verbatim reuse is only valid in the output language. If there are fewer than 5, every locale is used and a warning is printed.
- The note **filename and its markdown headings** drive the query; the body only refines it, and repeated tokens are capped so a long terminal dump cannot hijack the ranking.
- Entries scoring below **30% of the best match** are dropped. A clear winner is therefore sent alone; when nothing really matches, up to `--matches` weak entries are sent as style reference only.

Each note prints its candidates with their score and title overlap, so you can see what the AI was given:

```
  ●  Server-Side Template Injection.md
  ○  KB matches:
  ◌   216.4  (100% title)  Server-Side template injection (SSTI)
  ○  reused KB entry: Server-Side template injection (SSTI)
```

---

## Usage

```bash
# Run from the project root
python ai-pwndoc.py <audit-folder> [-e vulnerabilities.yml] [options]
```

### Arguments

| Argument | Short | Description |
|---|---|---|
| `folder` | | Folder containing `.md` notes |
| `--examples` | `-e` | `.yml` knowledge base of past vulnerabilities — matching entries are reused literally. Optional: without it everything is written from scratch |
| `--matches` | `-k` | Max knowledge base entries injected per note (default: `4`). Ignored without `-e` |
| `--provider` | `-p` | AI provider: `claude`, `claude-code` or `gemini` (overrides config) |
| `--model` | `-m` | Model override (overrides config). `claude`: full model id (e.g. `claude-opus-4-5`). `claude-code`: id or alias (`opus`, `sonnet`, `haiku`) |
| `--config` | `-c` | Path to config file (default: `config.yml`) |
| `--audit-id` | | PwnDoc audit ID — skips interactive selection / creation |
| `--lang` | | Output language: `es` (default) or `en` |
| `--instructions` | | Additional instructions injected into the system prompt |
| `--dry-run` | | Run the full AI pipeline but do not upload to PwnDoc |
| `--no-images` | | Skip image analysis and upload |

### Writing a section by hand

Every section the AI writes can be turned off. The flag drops that field from the prompt entirely — the AI is never asked for it, so it costs no tokens and cannot invent it — and the field is left out of the upload, so PwnDoc shows it empty for you to fill in.

| Flag | Skips |
|---|---|
| `--no-description` | `description` |
| `--no-observation` | `observation` |
| `--no-affected-assets` | `affectedAssets` |
| `--no-remediation` | `remediation` |
| `--no-references` | `references` |
| `--no-cvss` | `cvssv3` |
| `--no-vuln-type` | `vulnType` |
| `--no-priority` | `priority` |
| `--no-complexity` | `remediationComplexity` |
| `--no-evidence` | The evidence narrative and captions — images are still uploaded |

`--no-evidence` and `--no-images` are different: the first keeps the screenshots in the report but leaves the write-up to you, the second drops the screenshots altogether. The title is always generated, since it identifies the finding.

### Examples

```bash
# No knowledge base — every finding written from scratch
python ai-pwndoc.py SampleAudits/WebAudit/

# Basic run — interactive audit selection (or create a new audit with 'n')
python ai-pwndoc.py SampleAudits/WebAudit/ -e vulnerabilities.yml

# English output, Gemini provider
python ai-pwndoc.py SampleAudits/WebAudit/ -e vulnerabilities.yml --provider gemini --lang en

# Claude Code CLI — runs on your subscription instead of the API
python ai-pwndoc.py SampleAudits/WebAudit/ -e vulnerabilities.yml --provider claude-code

# Claude Code with a model alias
python ai-pwndoc.py SampleAudits/WebAudit/ -e vulnerabilities.yml --provider claude-code -m opus

# Use a more powerful Claude model (Anthropic API)
python ai-pwndoc.py SampleAudits/ADPentest/ -e vulnerabilities.yml --model claude-opus-4-5

# Show the AI more knowledge base candidates per note
python ai-pwndoc.py SampleAudits/WebAudit/ -e vulnerabilities.yml -k 6

# Let the AI draft everything except the scoring and the affected assets
python ai-pwndoc.py SampleAudits/WebAudit/ -e vulnerabilities.yml \
  --no-affected-assets --no-cvss --no-priority

# Inject extra instructions into the prompt
python ai-pwndoc.py SampleAudits/WebAudit/ -e vulnerabilities.yml --instructions "Always include the CWE identifier in the description."

# Skip interactive audit selection
python ai-pwndoc.py SampleAudits/ADPentest/ -e vulnerabilities.yml --audit-id 6657f1a2c3b4e500123abc

# Test without uploading anything
python ai-pwndoc.py SampleAudits/WebAudit/ -e vulnerabilities.yml --dry-run

# Full run, English, specific audit, best model
python ai-pwndoc.py SampleAudits/ADPentest/ -e vulnerabilities.yml \
  --lang en \
  --model claude-opus-4-5 \
  --audit-id 6657f1a2c3b4e500123abc
```

---

## Note format

Notes are plain Markdown files. Images are referenced using Obsidian wikilink syntax. Images must be in the same folder as the note (or any subfolder).

```markdown
# IDOR on invoice endpoint

Reviewing the billing app I noticed the endpoint `/api/invoices/{id}` does not
validate that the ID belongs to the authenticated user.

## What I found

Sequential IDs work fine with other users' data:

![[burp_request.png]]

The response leaks full invoice data: name, address, VAT number, amounts.

![[json_response.png]]

## Impact

Any authenticated user can read every other customer's invoice.
~50k users → ~50k invoices exposed.
```

The script replaces image references with `[EVIDENCE N: filename]` placeholders before sending the text to the AI, then analyses each image separately for description and caption.


