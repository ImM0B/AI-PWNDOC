#!/usr/bin/env python3
"""
AI-PWNDOC: Automated vulnerability writing for PwnDoc using AI
Supports: Claude API, Claude Code CLI (subscription), Gemini CLI
"""

import argparse
import base64
import json
import mimetypes
import os
import re
import subprocess
import sys
from pathlib import Path

import requests
import urllib3
import yaml
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
console = Console()


# ──────────────────────────────────────────────
# CONFIG
# ──────────────────────────────────────────────

DEFAULT_CONFIG = {
    "pwndoc": {
        "base_url": "https://localhost:8443",
        "username": "admin",
        "password": "adminpwd",
        "verify_ssl": False,
    },
    "llm": {
        "provider": "claude",
        "anthropic_api_key": "",
        "claude_model": "claude-haiku-4-5",
        "claude_code_binary": "claude",
        "claude_code_model": "",
        "claude_code_timeout": 300,
    },
}


def load_config(config_path: str) -> dict:
    path = Path(config_path)
    if path.exists():
        with open(path) as f:
            cfg = yaml.safe_load(f) or {}
        merged = DEFAULT_CONFIG.copy()
        for section in merged:
            if section in cfg:
                merged[section].update(cfg[section])
        return merged
    return DEFAULT_CONFIG.copy()


# ──────────────────────────────────────────────
# OBSIDIAN .md PARSING
# ──────────────────────────────────────────────

def parse_obsidian_md(md_path: str) -> dict:
    path = Path(md_path)
    content = path.read_text(encoding="utf-8")
    base_dir = path.parent
    images = []
    all_refs = []

    for match in re.finditer(r'!\[\[([^\]]+)\]\]', content):
        img_name = match.group(1)
        img_path = base_dir / img_name
        if not img_path.exists():
            found = list(base_dir.rglob(img_name))
            img_path = found[0] if found else None
        resolved = img_path if (img_path and Path(img_path).exists()) else None
        all_refs.append((match.group(0), resolved))

    for match in re.finditer(r'!\[([^\]]*)\]\(([^)]+)\)', content):
        img_path_rel = match.group(2)
        if not img_path_rel.startswith("http"):
            img_path = base_dir / img_path_rel
            resolved = img_path if img_path.exists() else None
            all_refs.append((match.group(0), resolved))

    clean_text = content
    evidence_counter = 0
    for ref_str, resolved in all_refs:
        if resolved:
            images.append(str(resolved))
            evidence_counter += 1
            label = f"[EVIDENCE {evidence_counter}: {Path(resolved).name}]"
        else:
            m = re.search(r'!\[\[([^\]]+)\]\]', ref_str)
            img_name = m.group(1) if m else ref_str
            console.print(f"  [yellow]⚠ Image not found: {img_name}[/yellow]")
            label = f"[EVIDENCE NOT FOUND: {img_name}]"
        clean_text = clean_text.replace(ref_str, label, 1)

    return {"clean_text": clean_text, "images": images}


# ──────────────────────────────────────────────
# EXAMPLES LOADER
# ──────────────────────────────────────────────

def load_vuln_examples(yml_path: str) -> list:
    with open(yml_path) as f:
        data = yaml.safe_load(f)
    if isinstance(data, list):
        return data
    if isinstance(data, dict) and "vulnerabilities" in data:
        return data["vulnerabilities"]
    return [data]


def examples_to_prompt(examples: list) -> str:
    out = []
    for i, ex in enumerate(examples[:5], 1):
        out.append(f"=== EXAMPLE {i} ===")
        for k, v in ex.items():
            if v:
                out.append(f"{k}: {v}")
        out.append("")
    return "\n".join(out)


# ──────────────────────────────────────────────
# PROMPTS
# ──────────────────────────────────────────────

VULN_FIELDS = [
    "title", "vulnType", "description", "observation",
    "remediation", "remediationComplexity", "priority", "references", "cvssv3",
]

SYSTEM_PROMPT_TEMPLATE = """You are a cybersecurity expert specialised in writing professional penetration testing reports.
Analyse the auditor's notes and generate structured vulnerability content for a professional report.

AUDITOR'S WRITING STYLE (learn from these examples):
{examples}

OUTPUT LANGUAGE: {lang_instruction}

INSTRUCTIONS:
- Follow the exact tone, technical level, and structure of the examples.
- Reply ONLY with valid JSON — no markdown, no extra explanations.
- Use null for any field you don't have enough information for.
- ALL text fields must be written in the output language specified above.
- "description": theoretical explanation of what the vulnerability class is — how it works, why it
  exists and the general attack scenario. Generic and technology-agnostic: NO client names, NO
  specific hosts, URLs, IPs or evidence from this engagement.
- "observation": impact analysis for this specific finding, explicitly covering the three security
  properties — confidentiality, integrity and availability. State for each one whether it is
  affected and how; if a property is not affected, say so briefly and why.
- "remediation" must be concise and actionable.
- "references" must be a list of strings with relevant URLs.
- "remediationComplexity": 1 (Easy), 2 (Medium), 3 (Hard)
- "priority": 1 (Low), 2 (Medium), 3 (High), 4 (Critical)
- "cvssv3": CVSS 3.x vector if applicable, otherwise null.
- "vulnType": category (e.g. "Web", "Network", "Active Directory", etc.)
- Do NOT include images/evidence in the JSON; those are handled separately.
{extra_instructions}
Reply with exactly this JSON:
{{
  "title": "...",
  "vulnType": "...",
  "description": "...",
  "observation": "...",
  "remediation": "...",
  "remediationComplexity": 2,
  "priority": 3,
  "references": ["..."],
  "cvssv3": "..."
}}
"""

EVIDENCE_ANALYSIS_SYSTEM_PROMPT = """You are a cybersecurity expert specialised in writing professional penetration testing reports.
You are given the vulnerability context and ALL the evidence screenshots for a single finding.

OUTPUT LANGUAGE: {lang_instruction}

Write the EVIDENCE section of the report as a single, cohesive narrative that walks the reader
through how the vulnerability was demonstrated, leaning on the screenshots and describing what
they show only where it adds clarity. Do NOT produce a separate description per screenshot and do
NOT restate every image one by one; write flowing prose for the section as a whole.

Also provide a short caption (pie de foto) for each screenshot, in the same order they were given.

INSTRUCTIONS:
- "evidence": HTML for the evidence section. Use <p> paragraphs (and <ul>/<li>, <code> where
  useful). Do NOT include any <img> tags — images are inserted separately.
- "captions": list with exactly one caption per screenshot, same order as provided, 15 words max each.

Reply ONLY with valid JSON in exactly this format — no markdown, no explanations:
{{
  "evidence": "<p>...</p>",
  "captions": ["...", "..."]
}}
"""

USER_PROMPT_TEMPLATE = """Here are the auditor's notes for this vulnerability:

{notes}

Available evidence images ({n_images}): {image_list}

Generate the vulnerability JSON following the system instructions."""


# ──────────────────────────────────────────────
# AI BACKENDS
# ──────────────────────────────────────────────

def call_claude_api(system_prompt: str, user_prompt: str, images: list, api_key: str, model: str = "claude-haiku-4-5") -> str:
    """Call Claude directly via the Anthropic REST API (no CLI, no session token needed)."""
    if not api_key:
        raise RuntimeError(
            "anthropic_api_key is required for Claude. Set it in config.yml under llm.anthropic_api_key"
        )

    # Build the user message content: text + optional base64 images
    content: list = []
    for img_path in images:
        mime, _ = mimetypes.guess_type(img_path)
        if not mime:
            mime = "image/png"
        with open(img_path, "rb") as f:
            b64 = base64.b64encode(f.read()).decode("utf-8")
        content.append({
            "type": "image",
            "source": {"type": "base64", "media_type": mime, "data": b64},
        })
    content.append({"type": "text", "text": user_prompt})

    payload = {
        "model": model,
        "max_tokens": 4096,
        "system": system_prompt,
        "messages": [{"role": "user", "content": content}],
    }

    resp = requests.post(
        "https://api.anthropic.com/v1/messages",
        headers={
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        },
        json=payload,
        timeout=120,
    )
    resp.raise_for_status()
    data = resp.json()
    return "".join(block["text"] for block in data["content"] if block["type"] == "text")


def call_claude_code_cli(system_prompt: str, user_prompt: str, images: list, cfg: dict) -> str:
    """Call Claude through the Claude Code CLI, using the local subscription login.

    No API key is needed: `claude -p` reuses the OAuth session of the installed CLI.
    Images are passed as absolute paths and read by the built-in Read tool.
    """
    import tempfile

    llm_cfg = cfg.get("llm", {})
    binary  = llm_cfg.get("claude_code_binary") or "claude"
    model   = llm_cfg.get("claude_code_model") or ""
    timeout = int(llm_cfg.get("claude_code_timeout") or 300)

    prompt = user_prompt
    if images:
        prompt += "\n\nRead these evidence image files with the Read tool before answering:"
        for img_path in images:
            prompt += f"\n{Path(img_path).resolve()}"
    prompt += "\n\nOutput ONLY the raw JSON object. No preamble, no markdown fences, no commentary."

    dirs_to_include = set()
    md_path = cfg.get("_md_path", "")
    if md_path:
        dirs_to_include.add(str(Path(md_path).resolve().parent))
    for img in images:
        dirs_to_include.add(str(Path(img).resolve().parent))

    cmd = [
        binary, "-p", prompt,
        "--system-prompt", system_prompt,
        "--output-format", "json",
        "--permission-mode", "bypassPermissions",
        "--tools", "Read",
        "--safe-mode",              # ignore local hooks/plugins/CLAUDE.md that could pollute stdout
        "--no-session-persistence",
    ]
    if model:
        cmd += ["--model", model]
    for d in sorted(dirs_to_include):
        cmd += ["--add-dir", d]

    # Drop ANTHROPIC_API_KEY so the CLI authenticates with the subscription, not pay-per-token API.
    env = {k: v for k, v in os.environ.items() if k != "ANTHROPIC_API_KEY"}

    with tempfile.TemporaryDirectory() as tmpdir:
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True,
                cwd=tmpdir, env=env, timeout=timeout,
            )
        except FileNotFoundError:
            raise RuntimeError(
                f"'{binary}' CLI not found. Install Claude Code: https://claude.com/claude-code"
            )
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"Claude Code CLI timed out after {timeout}s")

    if result.returncode != 0:
        raise RuntimeError(f"Claude Code CLI error (rc={result.returncode}):\n{result.stderr.strip()}")

    out = result.stdout.strip()
    try:
        envelope = json.loads(out)
    except json.JSONDecodeError:
        return out  # already plain text
    if isinstance(envelope, dict):
        if envelope.get("is_error"):
            raise RuntimeError(f"Claude Code CLI returned an error: {envelope.get('result', out)}")
        return str(envelope.get("result", out))
    return out


def call_gemini_cli(system_prompt: str, user_prompt: str, images: list, md_path: str = "") -> str:
    import tempfile
    prompt = f"{system_prompt}\n\n{user_prompt}"
    if md_path:
        prompt += f"\n\nAuditor note: @{Path(md_path).resolve()}"
    if images:
        prompt += "\n\nEvidence images (analyse each one):"
        for img_path in images:
            prompt += f"\n@{Path(img_path).resolve()}"

    dirs_to_include = set()
    if md_path:
        dirs_to_include.add(str(Path(md_path).resolve().parent))
    for img in images:
        dirs_to_include.add(str(Path(img).resolve().parent))

    cmd = ["gemini", "-p", prompt, "--yolo"]
    for d in dirs_to_include:
        cmd += ["--include-directories", d]

    with tempfile.TemporaryDirectory() as tmpdir:
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, cwd=tmpdir)
        except FileNotFoundError:
            raise RuntimeError("gemini CLI not found. Install it from: https://github.com/google-gemini/gemini-cli")

    if result.returncode != 0:
        raise RuntimeError(f"Gemini CLI error (rc={result.returncode}):\n{result.stderr.strip()}")
    return result.stdout.strip()


def call_llm(provider: str, system_prompt: str, user_prompt: str, images: list, cfg: dict) -> str:
    if provider == "claude":
        return call_claude_api(system_prompt, user_prompt, images, cfg["llm"].get("anthropic_api_key", ""), cfg["llm"].get("claude_model", "claude-haiku-4-5"))
    elif provider == "claude-code":
        return call_claude_code_cli(system_prompt, user_prompt, images, cfg)
    elif provider == "gemini":
        return call_gemini_cli(system_prompt, user_prompt, images, cfg.get("_md_path", ""))
    else:
        raise ValueError(f"Unknown provider: {provider}")


# ──────────────────────────────────────────────
# IMAGE ANALYSIS
# ──────────────────────────────────────────────

def _fallback_caption(image_path: str) -> str:
    return Path(image_path).stem.replace("_", " ").replace("-", " ").capitalize()


def analyze_evidence(provider: str, images: list, vuln: dict,
                     lang_instruction: str, cfg: dict) -> dict:
    """One call over ALL screenshots: returns a cohesive evidence narrative plus one caption per image.

    Returns {"evidence": <html str>, "captions": [<str>, ...]} with captions aligned to `images`.
    """
    if not images:
        return {"evidence": "", "captions": []}

    vuln_context = (
        f"Title: {vuln.get('title', '')}\n"
        f"Description: {vuln.get('description', '')}\n"
        f"Observation: {vuln.get('observation', '')}"
    )
    system_prompt = EVIDENCE_ANALYSIS_SYSTEM_PROMPT.format(lang_instruction=lang_instruction)
    image_names = ", ".join(Path(p).name for p in images)
    user_prompt = (
        f"Vulnerability context:\n{vuln_context}\n\n"
        f"Screenshots ({len(images)}), in order: {image_names}\n\n"
        f"Write the evidence section and one caption per screenshot."
    )

    try:
        raw = call_llm(provider, system_prompt, user_prompt, images, cfg)
        data = extract_json(raw)
    except Exception as e:
        console.print(f"  [yellow]⚠ Could not analyse evidence: {e}[/yellow]")
        return {"evidence": "", "captions": [_fallback_caption(p) for p in images]}

    evidence = data.get("evidence", "") or ""
    captions = data.get("captions") or []
    # Align captions to images: pad / fall back where the model came up short.
    captions = [
        (captions[i] if i < len(captions) and captions[i] else _fallback_caption(images[i]))
        for i in range(len(images))
    ]
    return {"evidence": evidence, "captions": captions}


# ──────────────────────────────────────────────
# JSON PARSING
# ──────────────────────────────────────────────

def extract_json(text: str) -> dict:
    text = re.sub(r'```(?:json)?\s*', '', text)
    text = re.sub(r'```', '', text)
    match = re.search(r'\{[\s\S]+\}', text)
    if match:
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON: {e}\n\nResponse:\n{text}")
    raise ValueError(f"No JSON found in response:\n{text}")


# ──────────────────────────────────────────────
# DISPLAY
# ──────────────────────────────────────────────

FIELD_LABELS = {
    "title":                 "Title",
    "vulnType":              "Type",
    "description":           "Description",
    "observation":           "Observation",
    "remediation":           "Remediation",
    "remediationComplexity": "Complexity",
    "priority":              "Priority",
    "references":            "References",
    "cvssv3":                "CVSSv3",
}

PRIORITY_MAP    = {1: "Low", 2: "Medium", 3: "High", 4: "Critical"}
COMPLEXITY_MAP  = {1: "Easy", 2: "Medium", 3: "Hard"}


def print_vuln(vuln: dict, md_name: str) -> None:
    table = Table(show_header=False, box=None, padding=(0, 1))
    table.add_column(style="dim cyan", width=14)
    table.add_column(style="white")
    for field, label in FIELD_LABELS.items():
        val = vuln.get(field, "")
        if field == "priority":
            display = f"{val} ({PRIORITY_MAP.get(val, '')})"
        elif field == "remediationComplexity":
            display = f"{val} ({COMPLEXITY_MAP.get(val, '')})"
        elif isinstance(val, list):
            display = ", ".join(str(v) for v in val)
        else:
            display = str(val) if val else "[dim]-[/dim]"
        table.add_row(label, display)
    console.print(table)


# ──────────────────────────────────────────────
# PWNDOC API
# ──────────────────────────────────────────────

class PwnDocAPI:
    def __init__(self, cfg: dict):
        self.base_url   = cfg["pwndoc"]["base_url"].rstrip("/")
        self.username   = cfg["pwndoc"]["username"]
        self.password   = cfg["pwndoc"]["password"]
        self.verify_ssl = cfg["pwndoc"]["verify_ssl"]
        self.session    = requests.Session()

    def login(self):
        resp = self.session.post(
            f"{self.base_url}/api/users/token",
            json={"username": self.username, "password": self.password},
            verify=self.verify_ssl, timeout=30,
        )
        resp.raise_for_status()
        token = resp.json()["datas"]["token"]
        self.session.headers.update({"Authorization": f"Bearer {token}"})

    def get_audits(self) -> list:
        resp = self.session.get(f"{self.base_url}/api/audits", verify=self.verify_ssl, timeout=30)
        resp.raise_for_status()
        return resp.json()["datas"]

    def get_languages(self) -> list:
        try:
            resp = self.session.get(f"{self.base_url}/api/data/languages", verify=self.verify_ssl, timeout=30)
            resp.raise_for_status()
            return resp.json()["datas"]
        except Exception:
            return []

    def get_audit_types(self) -> list:
        try:
            resp = self.session.get(f"{self.base_url}/api/data/audit-types", verify=self.verify_ssl, timeout=30)
            resp.raise_for_status()
            return resp.json()["datas"]
        except Exception:
            return []

    def create_audit(self, name: str, language: str, audit_type: str) -> dict:
        resp = self.session.post(
            f"{self.base_url}/api/audits",
            json={"name": name, "language": language, "auditType": audit_type},
            verify=self.verify_ssl, timeout=30,
        )
        resp.raise_for_status()
        datas = resp.json()["datas"]
        # PwnDoc replies {"message": "...", "audit": {...}}; older builds return the audit directly.
        return datas.get("audit", datas)

    def upload_image(self, image_path: str) -> str:
        mime, _ = mimetypes.guess_type(image_path)
        if not mime:
            mime = "image/png"
        with open(image_path, "rb") as f:
            b64 = base64.b64encode(f.read()).decode("utf-8")
        payload = {"value": f"data:{mime};base64,{b64}", "name": Path(image_path).name}
        resp = self.session.post(
            f"{self.base_url}/api/images", json=payload,
            verify=self.verify_ssl, timeout=60,
        )
        resp.raise_for_status()
        image_id = resp.json().get("datas", {}).get("_id")
        if not image_id:
            raise RuntimeError(f"PwnDoc did not return _id: {resp.text}")
        return image_id

    def add_finding(self, audit_id: str, vuln_data: dict, evidence_html: str,
                    captions: list, image_ids: list, proofs_header: str) -> dict:
        poc_parts = [proofs_header]
        if evidence_html:
            poc_parts.append(evidence_html)
        for i, img_id in enumerate(image_ids):
            caption = captions[i] if i < len(captions) else ""
            if caption:
                poc_parts.append(f'<p><img src="{img_id}" alt="{caption}"></p>')
            else:
                poc_parts.append(f'<p><img src="{img_id}"></p>')

        body = {
            "title":                 vuln_data.get("title", ""),
            "vulnType":              vuln_data.get("vulnType", ""),
            "description":           vuln_data.get("description", ""),
            "observation":           vuln_data.get("observation", ""),
            "remediation":           vuln_data.get("remediation", ""),
            "remediationComplexity": vuln_data.get("remediationComplexity", 2),
            "priority":              vuln_data.get("priority", 2),
            "references":            vuln_data.get("references", []),
            "cvssv3":                vuln_data.get("cvssv3", "") or "",
            "poc":                   "\n".join(poc_parts),
            "category":              None,
            "customFields":          [],
        }
        resp = self.session.post(
            f"{self.base_url}/api/audits/{audit_id}/findings",
            json=body, verify=self.verify_ssl, timeout=30,
        )
        resp.raise_for_status()
        return resp.json()


# ──────────────────────────────────────────────
# AUDIT SELECTION
# ──────────────────────────────────────────────

def _pick_from(api_items: list, key: str, label: str, prompt: str, show_key: str = "") -> str:
    """Show a numbered list and return the chosen value; free text if the list is empty."""
    if not api_items:
        return Prompt.ask(f"{label} (free text)")
    for i, item in enumerate(api_items, 1):
        console.print(f"  {i}. [bold]{item.get(show_key or key, '')}[/bold]")
    choice = Prompt.ask(prompt, default="1")
    try:
        idx = int(choice) - 1
        if 0 <= idx < len(api_items):
            return api_items[idx].get(key, "")
    except ValueError:
        pass
    return choice


def create_audit_interactive(api: PwnDocAPI) -> str:
    console.print("\n[bold]New audit[/bold]")
    name = Prompt.ask("Audit name")

    console.print("\n[dim]Language:[/dim]")
    languages = [
        {**lang, "label": f"{lang.get('language', '')} ({lang.get('locale', '')})"}
        for lang in api.get_languages()
    ]
    language = _pick_from(languages, "locale", "Language locale", "Select language number", show_key="label")

    console.print("\n[dim]Audit type:[/dim]")
    audit_types = api.get_audit_types()
    audit_type = _pick_from(audit_types, "name", "Audit type", "Select audit type number")

    audit = api.create_audit(name, language, audit_type)
    audit_id = audit["_id"]
    console.print(f"[green]✓[/green] Audit created: [bold]{name}[/bold]  [dim]{audit_id}[/dim]")
    return audit_id


def select_audit(api: PwnDocAPI) -> str:
    audits = api.get_audits()
    for i, audit in enumerate(audits, 1):
        console.print(f"  {i}. [bold]{audit.get('name', 'Unnamed')}[/bold]  [dim]{audit['_id']}[/dim]")
    console.print("  [bold cyan]n[/bold cyan]. Create new audit")

    while True:
        choice = Prompt.ask("Select audit number (or 'n' for new)").strip()
        if choice.lower() in ("n", "new"):
            return create_audit_interactive(api)
        try:
            idx = int(choice) - 1
        except ValueError:
            console.print("[red]Invalid selection.[/red]")
            continue
        if 0 <= idx < len(audits):
            console.print(f"[green]✓[/green] Audit: [bold]{audits[idx].get('name')}[/bold]")
            return audits[idx]["_id"]
        console.print("[red]Invalid selection.[/red]")


# ──────────────────────────────────────────────
# PROCESS SINGLE .md
# ──────────────────────────────────────────────

def process_md_file(
    md_file: str,
    system_prompt: str,
    lang_instruction: str,
    proofs_header: str,
    provider: str,
    cfg: dict,
    api,
    audit_id: str,
    dry_run: bool,
    no_images: bool,
) -> bool:  # extra_instructions injected into system_prompt before call
    name = Path(md_file).name
    console.print(f"\n  ●  [bold cyan]{name}[/bold cyan]")

    # Parse
    md_data = parse_obsidian_md(md_file)
    images  = md_data["images"]
    console.print(f"  ○  [dim]{len(md_data['clean_text'])} chars[/dim]  ·  [dim]{len(images)} image(s)[/dim]")
    for img in images:
        console.print(f"  ◌  [dim]{Path(img).name}[/dim]")

    # Query AI
    image_list  = [Path(i).name for i in images] if images else ["none"]
    user_prompt = USER_PROMPT_TEMPLATE.format(
        notes=md_data["clean_text"],
        n_images=len(images),
        image_list=", ".join(image_list),
    )
    cfg["_md_path"] = md_file

    with console.status(f"  ◎  querying {provider}..."):
        try:
            raw_response = call_llm(provider, system_prompt, user_prompt, images, cfg)
        except Exception as e:
            console.print(f"  ✗  [red]AI error: {e}[/red]")
            return False

    try:
        vuln = extract_json(raw_response)
    except ValueError as e:
        console.print(f"  ✗  [red]JSON parse error: {e}[/red]")
        return False

    # Display result
    print_vuln(vuln, name)

    # Analyse evidence (single cohesive narrative + one caption per image)
    evidence_html = ""
    captions = []
    if images and not no_images:
        with console.status(f"  ◎  writing evidence from {len(images)} image(s)..."):
            evidence = analyze_evidence(provider, images, vuln, lang_instruction, cfg)
        evidence_html = evidence["evidence"]
        captions = evidence["captions"]
        for img, cap in zip(images, captions):
            console.print(f"  ◌  [dim]{Path(img).name}[/dim]  [dim italic]{cap}[/dim italic]")

    if dry_run:
        return True

    # Upload images
    image_ids = []
    if images and not no_images:
        for img_path in images:
            try:
                img_id = api.upload_image(img_path)
                image_ids.append(img_id)
            except Exception as e:
                console.print(f"  ⚠  [yellow]upload failed {Path(img_path).name}: {e}[/yellow]")

    # Add finding
    try:
        api.add_finding(audit_id, vuln, evidence_html, captions[:len(image_ids)], image_ids, proofs_header)
        console.print(f"  ●  [green]added[/green]  [bold]{vuln.get('title', name)}[/bold]")
        return True
    except Exception as e:
        console.print(f"  ✗  [red]failed to add finding: {e}[/red]")
        return False


# ──────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="AI-PWNDOC: Automated vulnerability writing for PwnDoc using AI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python ai-pwndoc.py Audit1/ -e examples.yml
  python ai-pwndoc.py Audit1/ -e examples.yml --provider gemini --lang en
  python ai-pwndoc.py Audit1/ -e examples.yml --provider claude-code          # uses Claude Code subscription
  python ai-pwndoc.py Audit1/ -e examples.yml --provider claude-code -m opus
  python ai-pwndoc.py Audit1/ -e examples.yml --model claude-opus-4-5
  python ai-pwndoc.py Audit1/ -e examples.yml --instructions "Always include CWE identifier"
  python ai-pwndoc.py Audit1/ -e examples.yml --audit-id abc123 --dry-run
        """,
    )
    parser.add_argument("folder",            help="Folder containing Obsidian .md notes")
    parser.add_argument("--examples", "-e",  required=True, help=".yml file with example vulnerabilities")
    parser.add_argument("--provider", "-p",  choices=["claude", "claude-code", "gemini"],
                        default=None,        help="AI provider (overrides config). "
                                                  "claude = Anthropic API key | "
                                                  "claude-code = local Claude Code CLI (subscription) | "
                                                  "gemini = Gemini CLI")
    parser.add_argument("--config",  "-c",   default="config.yml", help="Config file (default: config.yml)")
    parser.add_argument("--audit-id",        help="Audit ID (skips interactive selection)")
    parser.add_argument("--lang",            choices=["es", "en"], default="es",
                        help="Output language: es (default) | en")
    parser.add_argument("--model",    "-m",  default=None,
                        help="Model override. claude: full model id (e.g. claude-opus-4-5). "
                             "claude-code: id or alias (e.g. opus, sonnet, haiku)")
    parser.add_argument("--instructions",    default=None,
                        help="Additional instructions injected into the system prompt")
    parser.add_argument("--dry-run",         action="store_true", help="Do not upload to PwnDoc")
    parser.add_argument("--no-images",       action="store_true", help="Skip image upload")
    args = parser.parse_args()

    console.print(Panel.fit(
        "[bold red]AI-PWNDOC[/bold red]  [dim]automated vulnerability writing[/dim]",
        border_style="red",
    ))

    cfg      = load_config(args.config)
    provider = args.provider or cfg["llm"]["provider"]

    # --model overrides config value
    if args.model:
        cfg["llm"]["claude_model"] = args.model
        cfg["llm"]["claude_code_model"] = args.model
    if provider == "claude":
        model_label = cfg["llm"].get("claude_model", "claude-haiku-4-5")
    elif provider == "claude-code":
        model_label = f"claude-code ({cfg['llm'].get('claude_code_model') or 'CLI default'})"
    else:
        model_label = provider
    console.print(f"[dim]provider: {model_label}  |  target: {cfg['pwndoc']['base_url']}  |  lang: {args.lang}[/dim]")

    # Discover .md files
    folder = Path(args.folder)
    if not folder.is_dir():
        console.print(f"[red]✗ '{folder}' is not a valid directory.[/red]")
        sys.exit(1)
    md_files = sorted(folder.glob("*.md"))
    if not md_files:
        console.print(f"[red]✗ No .md files found in '{folder}'.[/red]")
        sys.exit(1)

    notes_text = "  ".join(f"[bold]{f.name}[/bold]" for f in md_files)
    console.print(Panel.fit(
        f"[dim]{len(md_files)} note(s) · {folder.resolve()}[/dim]\n{notes_text}",
        title="[cyan]notes[/cyan]",
        border_style="cyan",
    ))

    # Load examples
    examples = load_vuln_examples(args.examples)
    console.print(f"[dim]Loaded {len(examples)} example(s) from {args.examples}[/dim]")

    # Build shared system prompt
    if args.lang == "en":
        lang_instruction = "English. Write ALL text fields in English."
        proofs_header    = "<p><strong>Below is the supporting evidence:</strong></p>"
    else:
        lang_instruction = "Español. Redacta TODOS los campos de texto en español."
        proofs_header    = "<p><strong>A continuación, las evidencias:</strong></p>"

    extra_block = ""
    if args.instructions:
        extra_block = f"\nADDITIONAL INSTRUCTIONS:\n{args.instructions}\n"

    system_prompt = SYSTEM_PROMPT_TEMPLATE.format(
        examples=examples_to_prompt(examples),
        lang_instruction=lang_instruction,
        extra_instructions=extra_block,
    )

    # Connect to PwnDoc (once)
    api      = None
    audit_id = None

    if not args.dry_run:
        with console.status("Connecting to PwnDoc..."):
            api = PwnDocAPI(cfg)
            try:
                api.login()
            except Exception as e:
                console.print(f"  ✗  [red]connection failed: {e}[/red]")
                sys.exit(1)
        console.print("  ●  [green]connected to PwnDoc[/green]")
        console.print()
        audit_id = args.audit_id or select_audit(api)
    else:
        console.print("  ○  [yellow]dry-run — PwnDoc upload skipped[/yellow]")

    # Process each .md
    ok, fail = [], []
    for md_file in md_files:
        success = process_md_file(
            md_file=str(md_file),
            system_prompt=system_prompt,
            lang_instruction=lang_instruction,
            proofs_header=proofs_header,
            provider=provider,
            cfg=cfg,
            api=api,
            audit_id=audit_id,
            dry_run=args.dry_run,
            no_images=args.no_images,
        )
        (ok if success else fail).append(md_file.name)

    # Summary
    console.print()
    console.print(f"  ●  [green]{len(ok)} succeeded[/green]   ✗  [red]{len(fail)} failed[/red]")
    for name in fail:
        console.print(f"  ◌  [red]{name}[/red]")


if __name__ == "__main__":
    main()