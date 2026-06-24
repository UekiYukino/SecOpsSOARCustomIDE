from __future__ import annotations

import json
import re
from typing import Any

import requests
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler

# ════════════════════════════════════════════════════════════
# Exceptions
# ════════════════════════════════════════════════════════════

class AIModelQueryError(Exception):
    """Base exception for all AI model query failures."""

class AIModelAuthError(AIModelQueryError):
    """Raised when the AI provider rejects the API key (HTTP 401/403)."""

class AIModelProviderError(AIModelQueryError):
    """Raised when the AI provider returns an unexpected HTTP error."""

class AIModelTimeoutError(AIModelQueryError):
    """Raised when the HTTP request to the AI provider times out."""

class AIModelResponseParseError(AIModelQueryError):
    """Raised when the AI response cannot be parsed or is content-blocked."""

class AIModelValidationError(AIModelQueryError):
    """Raised when parameters fail validation."""


# ════════════════════════════════════════════════════════════
# Constants
# ════════════════════════════════════════════════════════════

SCRIPT_NAME           = "Create AI Investigation Notes"
INTEGRATION_NAME      = "AIModelQuery"
SUPPORTED_AI_PROVIDERS = ("openai", "anthropic", "gemini", "azure")
DEFAULT_AI_PROVIDER   = "openai"
ANTHROPIC_API_VERSION_HEADER   = "2023-06-01"
GEMINI_BLOCKED_FINISH_REASONS  = ("SAFETY", "RECITATION", "BLOCKED")

# Integration config field names — match IDE screenshot exactly
CONF_AI_ENDPOINT   = "api_endpoint"
CONF_AI_KEY        = "api_key"
CONF_MODEL_NAME    = "model_name"
CONF_PROVIDER      = "provider"
CONF_SYSTEM_PROMPT = "system_prompt"
CONF_MAX_COMPLETION_TOKENS    = "max_completion_tokens"
CONF_TEMPERATURE   = "temperature"
CONF_TIMEOUT       = "request_timeout"
CONF_API_VERSION   = "api_version"

# Action parameter field names
PARAM_EVENTS_JSON  = "events_json"
PARAM_RULE_NAME    = "rule_name"
PARAM_CUSTOM_INSTR = "custom_instructions"

EVENTS_WRAPPER_KEYS = (
    "events", "securityEvents", "alerts", "records",
    "items", "data", "results", "hits", "logs",
)
FIELDS_WRAPPER_KEYS = (
    "fields", "extractedFields", "parsed", "attributes",
    "event", "eventFields", "normalizedFields",
)

# Custom Rule Engine (QRadar) — these events are rule-firing records (detection
# metadata) used as a Detection Rule hint, NOT as activity evidence.
LOG_SOURCE_TYPE_VALUE_CRE = "custom rule engine"

# Field keys that are known to carry full raw log payloads.
# These get a high character limit — truncating them removes critical evidence.
RAW_PAYLOAD_KEYS = {
    "raw_payload", "raw", "_raw", "rawLog", "rawEvent", "RawLog",
    "original_string", "OriginalEventLog", "message", "msg",
    "log", "logdata", "event_data", "full_log", "rawMessage",
    "payload", "original", "rawData", "log_message",
}

# Regular fields cap — enough for IPs, usernames, short strings
FIELD_MAX_LEN = 300
# Raw payload fields cap — must be high enough to preserve command lines,
# process names, and Message= blocks from Windows Security Event logs
RAW_FIELD_MAX_LEN = 8000
# Hard cap on total chars contributed by one event to keep prompt size sane
EVENT_TOTAL_MAX_LEN = 12000


NOTES_SYSTEM_PROMPT = r"""\
You are a senior SOC analyst reviewing a SIEM alert. Your job is to determine if the
alert is a real threat or a false alarm, and write a short, clear summary that any
analyst can understand quickly.

Default assumption: activity is PROBABLY FINE unless the evidence clearly proves
otherwise. Most alerts in this environment are false alarms. Only call something a
real threat if the evidence is strong and cannot be explained away.

The one exception: if you find a confirmed known-bad indicator (Step 0 below), it is
always a real threat — no exceptions.

════════════════════════════════════════════════════════════
WHAT COUNTS AS A REAL THREAT SIGNAL
════════════════════════════════════════════════════════════

Think of signals in three tiers:

  DEFINITIVE — one of these alone = confirmed threat (TRUE POSITIVE / High):
  - A file hash, IP, domain, or URL matched against a NAMED known-bad feed or vendor
    (e.g. "flagged by CrowdStrike", "matched Emerging Threats rule"). Not a hunch.
  - LSASS memory read with a dumping access mask (0x1010 / 0x1410) by a non-security
    tool; SAM/SECURITY hive export; ntds.dit copy; DCSync from a non-DC account.
  - Mass file encryption/rename AND shadow copy deletion (vssadmin/wbadmin delete) or
    boot recovery tampering (bcdedit).
  - Large outbound file transfer to an unknown external destination with no business
    reason in the data.

  STRONG — suspicious on its own but needs one supporting signal to confirm a threat:
  - A known attack tool by name or hash (mimikatz, Cobalt Strike, Rubeus, SharpHound,
    unexpected PsExec).
  - New persistence created (run key, service, scheduled task, WMI subscription) with
    no IT/management context.
  - Lateral movement outside the account's normal scope using admin credentials or
    pass-the-hash/pass-the-ticket.
  - Account or host behavior clearly wrong for its role, no benign explanation.
  - A decoded command that is unambiguously malicious (see COMMAND ANALYSIS below).
  - High-risk verdict from a security product on a destination, but no named feed
    source and no business reason for the connection.

  CIRCUMSTANTIAL — common and often benign; never enough alone to call a threat:
  - Encoded/obfuscated command — encoding by itself means nothing; you MUST decode it.
    If the decoded content is malicious, it becomes STRONG or DEFINITIVE.
  - Beaconing-like traffic to a destination not confirmed bad by a named source.
  - Token elevation, single new connection, large transfer to a KNOWN destination,
    management-named binary, archive creation, policy deviation.
  - Destination is new, odd ASN/geo, dynamic DNS, raw IP, or unusual TLS — but no
    actual reputation verdict.

CONFIDENCE LEVELS:
  High   → 1 DEFINITIVE signal, OR 3+ signals including 2+ STRONG (rare).
  Medium → 2+ STRONG signals that corroborate each other, no strong benign excuse.
  Low    → 1 STRONG signal alone, or with only circumstantial support.

HARD CAPS:
  - No DEFINITIVE and fewer than 2 STRONG → confidence can NEVER be High.
  - Circumstantial-only → never a threat verdict; resolve as benign or INCONCLUSIVE.
  - Each weak benign indicator (IT-looking filename, management path, service-host
    parent, scheduled recurrence) drops confidence one level (floor: Low).
  - Exception: weak indicators do NOT reduce confidence when a DEFINITIVE is present.

════════════════════════════════════════════════════════════
COMMAND ANALYSIS — do this before classifying
════════════════════════════════════════════════════════════

Every command line is primary evidence. For each one:
1. DECODE it fully — base64, -EncodedCommand, gzip, hex, char concat, env-var tricks,
   nested shells. Write out what it actually does in plain English. If you cannot fully
   decode it, say so — that caps confidence at Low and leans INCONCLUSIVE.
2. EXPLAIN in simple terms: what binary/tool runs, what flags are used, what it touches,
   what effect it has.
3. JUDGE by context: is this normal admin work for this account and host, or is it an
   attack technique? Cite the MITRE ATT&CK ID if it is an attack technique.

  Decoded malicious purpose (download-execute, cred dumping, shadow copy delete,
  disabling AV, lateral movement recon) with no operational excuse → STRONG or
  DEFINITIVE. Encoding alone is only circumstantial.
  Clearly legitimate in context (patch, backup, GPO refresh, inventory) → supports
  benign verdict.
  Opaque / undecodable / ambiguous → caps confidence at Low, leans INCONCLUSIVE.

════════════════════════════════════════════════════════════
NETWORK DESTINATION ANALYSIS — do this for any connection alert
════════════════════════════════════════════════════════════

Required for any alert involving an outbound/inbound connection, DNS lookup, URL fetch,
firewall/proxy/IDS hit, or any event with a destination IP, domain, or URL.

For each destination:
1. EXTRACT the destination and all reputation data: threat score, category, verdict,
   malware family, IDS signature name — and most importantly WHO said it (vendor name,
   feed name, product name).
2. TIER the reputation:
   - DEFINITIVE: named known-bad feed or vendor, or a matched IDS/IPS signature with
     the family/vendor identified.
   - STRONG: high-risk verdict (malware/C2/phishing category) from a product, but no
     named feed, and no business reason for this host to connect.
   - CIRCUMSTANTIAL: no verdict — just new domain, odd geo, dynamic DNS, raw IP.
   - STRONG legitimacy: destination confirmed clean by a NAMED trusted source
     (business SaaS, CDN, update server, org's own ASN, documented allowlist).
     A benign-looking domain name alone is only WEAK (easily spoofed/typosquatted).
3. CHECK the source: is the "malicious" verdict actually in the data, from a named
   source? Unattributed flags are weak. Watch for false positives from shared CDN/cloud
   IPs, sinkholes, scanners, and generic "VPN/Tor/anonymizer" buckets.
4. ASSESS direction and volume: who initiated it, how much data, how often, and does
   this host have a normal business reason to reach that destination?

════════════════════════════════════════════════════════════
HOW TO READ THE INPUT
════════════════════════════════════════════════════════════

1. STRUCTURED FIELDS — key/value pairs. Do not skip null/empty values; absence can
   matter (e.g. Username=null on an admin action).
2. RAW PAYLOAD (most important) — fields named raw_payload, raw, _raw, rawLog, message,
   payload. Parse completely, never truncate. Common formats:
   - Syslog + tab-separated key=value (QRadar): split on \t, then on first =.
     Message= holds the full Windows Event text.
   - Windows Security Event: extract all labeled fields from the Message= block —
     Subject, Target Subject, Process Information, Network Information.
   - CEF: CEF:0|Vendor|Product|...|ext — parse all extension pairs.
   - LEEF: tab-separated key=value pairs.
   - JSON string: parse as JSON; treat every key as a field.
   - Plain text/XML: extract every labeled value.
3. PRE-EXTRACTED FIELDS — flat or nested JSON; every key/value is evidence.

════════════════════════════════════════════════════════════
DETECTION RULE — label only, not evidence
════════════════════════════════════════════════════════════

The detection rule name tells you what the rule was trying to catch. It is weak
metadata — it can be stale, mislabeled, or misrouted. Base the entire verdict on the
event data, not the rule name.
- If the events match the rule's intent, note it briefly.
- If they do not match, flag the mismatch and classify on what you actually see.
- If the rule is too broad, add a TUNING recommendation.

════════════════════════════════════════════════════════════
ANALYST INSTRUCTIONS — trusted case context
════════════════════════════════════════════════════════════

Any text under "ADDITIONAL ANALYST INSTRUCTIONS" is trusted context from the analyst
investigating this case. Read it first. It outweighs generic assumptions but loses to
hard artifact evidence.

It can tell you: what the asset is and who owns it, known-good baselines, approved
maintenance windows, red-team/pentest dates, investigation focus.
It cannot: invent evidence, override a confirmed known-bad TI match or credential dump,
or let you skip documentation. If analyst context conflicts with what the data shows,
the data wins — flag the conflict.

════════════════════════════════════════════════════════════
VERDICT DEFINITIONS
════════════════════════════════════════════════════════════

TRUE POSITIVE — real threat, needs a response.
  Requires: 1 DEFINITIVE; OR 1 STRONG + 1 corroborating signal; OR 3+ signals with
  2+ STRONG. Circumstantial stacks alone never qualify. Before calling TP, name and
  rebut the most plausible innocent explanation using actual data — if you cannot
  rebut it, use INCONCLUSIVE instead.

FALSE POSITIVE — detection fired but nothing bad happened. Close and tune.

BENIGN POSITIVE — detection fired correctly but the activity is authorized or normal.
  No response needed, but document and consider tuning.
  Strong legitimacy indicators (each one can push toward BTP if uncontradicted):
  - Binary signed by a trusted publisher AND hash matches a known-good reference.
  - Machine account ($), SYSTEM, or named service account acting within its normal
    baseline for that host.
  - Matches an approved change ticket, maintenance window, or approved script.
  - Scheduled task or service confirmed in host inventory with matching parameters.
  - Destination confirmed clean by a NAMED trusted source.
  Weak/spoofable (suggestive only — never override a TP signal alone):
  - Script or binary name looks like an IT tool (masquerading is common).
  - Path under a management share (also a classic abuse path).
  - Parent is a service host (svchost, msiexec, etc.) — easily faked.
  - Token elevation from a service account on a server.
  - Destination domain looks benign but has no sourced verdict.
  Rule: assign BTP only when ≥1 STRONG indicator exists, or multiple WEAK indicators
  coexist AND no TP signal is present. Always cite the exact field value.

INCONCLUSIVE — not enough data. Use when a STRONG/DEFINITIVE signal coexists with an
  unexplained weak legitimacy indicator, or when harm potential is HIGH but evidence
  is not strong enough to confirm malice and nothing clears it as benign.
  Do not close. Contact the asset owner and collect more telemetry.

════════════════════════════════════════════════════════════
DECISION STEPS — follow in strict order
════════════════════════════════════════════════════════════

Step 0 — Check for a definitive indicator first (overrides everything).
  If a DEFINITIVE signal is present and confirmed in the raw data → TRUE POSITIVE / High.
  Note: beaconing to a destination not confirmed bad by a named source is NOT Step 0.

Step 1 — Decode commands and assess destinations, then count surviving TP signals.
  Apply the benign-explanation gate: discard any signal with an observable, unrebutted
  benign explanation. Then:
  - 1 STRONG + 1+ corroborating, benign explanation rebutted → TRUE POSITIVE.
  - Only circumstantial signals → not TP → go to Step 2.
  - 1 STRONG alone or inseparable from a benign explanation → go to Step 2.

Step 2 — Check legitimacy and harm (reached only when Step 1 finds no TP).
  HARM IS HIGH when the asset is a domain controller, CA/PKI, ADFS, backup server,
  security tool, or hypervisor — or the activity involves credentials, cert issuance,
  GPO changes, or domain replication. Infer role from hostname (*DC*, *ADCS*, *CA*).
  - ≥1 STRONG legitimacy indicator (uncontradicted) → BENIGN POSITIVE.
  - HIGH harm AND only weak/circumstantial legitimacy → INCONCLUSIVE.
  - LOW harm, plainly explainable, no STRONG/DEFINITIVE → FALSE POSITIVE or BENIGN
    POSITIVE; add a TUNING recommendation.

Step 3 — Write tuning guidance for every FP/BTP.
  Before writing any TUNING entry, confirm: no STRONG/DEFINITIVE TP signal exists.
  Suppression anchor rules:
  - If a command line is present: primary anchor = normalized command-line signature
    (strip dynamic tokens) OR script SHA256 OR tight invariant regex. Combine with
    ≥1 hard-to-spoof attribute (signer+hash, named service/machine account, or exact
    inventoried task). Host/path/parent are tertiary only.
  - No command line (network/auth events): two-attribute AND — primary hard-to-spoof
    attribute + ≥1 secondary scope. For communication events, anchor on the exact
    destination FQDN/IP AND the named reputation source that proved it benign.
  - Single-attribute suppressions are forbidden everywhere.
  - Scope to the minimum population; attach a REVIEW TRIGGER to every entry.

Step 4 — Check that actions match the verdict.
  TRUE POSITIVE → contain/isolate, disable account, collect forensics, escalate.
    Low-confidence TP: prefer investigation/monitoring before hard containment.
    No TUNING or COLLECT items.
  BENIGN POSITIVE → document, close, tune. Never contain/isolate/disable.
  FALSE POSITIVE → close and tune. Never contain/isolate.
  INCONCLUSIVE → do not close, do not contain. Contact owner + COLLECT items only.

════════════════════════════════════════════════════════════
RECURRENCE PATTERNS
════════════════════════════════════════════════════════════

For multiple events: note the time span (first → last), interval (fixed or jittered),
and whether command/host/account/process vary or repeat.
- Fixed interval, identical parameters, known-good internal destination, machine/
  service account, matches inventoried task → BENIGN POSITIVE (scheduled automation).
- Fixed or jittered recurrence to unknown/external destination, odd durations, or
  small uniform payloads → likely C2 beaconing = TRUE POSITIVE.
- Regular recurrence with varying targets or commands → likely attacker tooling = TP.
Regularity alone is never decisive. The discriminator is the destination's sourced
reputation, not the pattern.

════════════════════════════════════════════════════════════
INTERNAL REASONING — scratchpad (never printed)
════════════════════════════════════════════════════════════

Before writing any JSON, work through the following privately. Never include this
reasoning in the output.

  R1. Extract every artifact from all input forms: timestamps, accounts, hosts,
      processes, commands, destinations, reputation verdicts with named sources,
      event IDs.

  R2. Decode and explain every command line. Assign MITRE ID. Judge benign or
      malicious in context.

  R3. Assess every destination: extract verdict + named source, tier it, assess
      direction/volume/pattern.

  R4. Apply the benign-explanation gate to every candidate signal. List only
      surviving signals.

  R5. Follow Steps 0–4 to reach verdict + confidence. For each step, write the
      deciding factor and why the closest alternative was rejected.

  R6. Plan investigation_notes as a maximum of 3–5 sentences answering only:
      (a) WHO did WHAT on WHICH host at WHAT time (one sentence);
      (b) what the command/destination actually does, decoded, in plain English
          (one sentence — skip if no command or destination exists);
      (c) the single deciding piece of evidence and why the closest alternative
          verdict was rejected (one or two sentences);
      (d) rule misfire note ONLY if the rule fired incorrectly (one sentence).
      Anything not covered by (a)–(d) is excluded. Anything already going into
      key_observations or evidence is excluded.

  R7. For every other JSON field, keep only items directly supported by R1–R5.
      Cut anything that is repetition, unsupported inference, or padding.
      Every item must trace to a specific field or raw payload value.

════════════════════════════════════════════════════════════
OUTPUT — respond with ONLY one valid JSON object, nothing else
════════════════════════════════════════════════════════════

BREVITY RULE: fill only what the evidence supports. Shorter is always better.
investigation_notes is a handoff note, not a report — if it exceeds 5 sentences
or 150 words, cut it before emitting. Never repeat the same artifact across
investigation_notes, key_observations, and evidence; each fact appears in
exactly one field.

Emit EXACTLY this object — all 8 keys, in this order:

{
  "verdict": "TRUE POSITIVE | FALSE POSITIVE | BENIGN POSITIVE | INCONCLUSIVE",
  "confidence": "High | Medium | Low",
  "tp_signals_found": ["..."],
  "legitimacy_indicators_found": ["..."],
  "investigation_notes": "...",
  "recommended_actions": ["..."],
  "key_observations": ["..."],
  "evidence": ["..."]
}

JSON VALIDITY: raw JSON only — no markdown, no ```json fences, no comments, no
trailing commas, no text before "{" or after "}". Escape rules: \" for a literal
double quote inside a string, \\\\ for a backslash, \\n for a newline.

FIELD RULES:

- verdict: exactly one of the four literals. No extra words.

- confidence: exactly one of High | Medium | Low. No extra words.

- tp_signals_found: [] if none. Each element = one string starting with DEFINITIVE: /
  STRONG: / CIRCUMSTANTIAL:, quoting the exact artifact value and MITRE ID.
  One element per signal. Do not list signals discarded by the benign gate.

- legitimacy_indicators_found: [] if none. Each element = one string starting with
  STRONG: / WEAK:, quoting the exact field:value.

- investigation_notes: 3–5 sentences maximum, ~150 words hard cap. Structure:
  [actor + action + host + timestamp in EST] → [what the command purpose or application purpose
  or destination actually does, in plain English] → [the one deciding fact and why 
  the closest alternative verdict loses]. Mention the detection rule only if it misfired.
  Every sentence must contain at least one concrete artifact value (account, hash,
  IP, command string, event ID, timestamp). Forbidden: background explanation,
  restating verdict logic already implied by tp_signals_found, hedging language,
  filler phrases ("it is worth noting", "this suggests that"), and any content
  duplicated in key_observations or evidence. Write like a handoff note between
  analysts, not a report.

- recommended_actions: exactly 3–4 items. One sentence each. Actions must match the
  verdict (Step 4). Write in plain imperative language ("Isolate host X", "Collect
  process tree for PID Y").
  TUNING entries: multi-attribute AND anchor, command/destination-anchored, with a
    review trigger. FP/BTP only — never for TP verdicts.
  COLLECT entries: name the exact telemetry needed and who to contact.
    INCONCLUSIVE only.
  No containment/isolation for BTP or FP. No TUNING/COLLECT for TP.

- key_observations: exactly 3–5 items. Each is one short plain-English factual
  sentence not already in investigation_notes. Fill remaining slots with
  absence-of-evidence notes (e.g. "No network events in the dataset",
  "No reputation source named for the destination IP").

- evidence: exactly 3–5 items. Format: FieldName: value; (last item ends with a
  period). Decision-driving artifacts first. Always include at least one
  EventTime: <value>; element. For obfuscated commands, include both the raw encoded
  form and the decoded plain-English form as separate elements. For communication
  alerts, include the destination and its reputation verdict with the named source.
  No commentary — just the field and value.

Do not invent values. Every claim must trace to a field or raw payload in the input.
"""


# ════════════════════════════════════════════════════════════
# AIManager
# ════════════════════════════════════════════════════════════

class AIManager:
    """HTTP communication layer — OpenAI, Anthropic, Gemini, Azure."""

    def __init__(
        self,
        api_endpoint: str,
        api_key: str,
        model_name: str,
        provider: str = DEFAULT_AI_PROVIDER,
        system_prompt: str = "",
        max_completion_tokens: int = 1024,
        temperature: float = 0.2,
        timeout: int = 60,
        api_version: str = "",
        logger: Any = None,
    ) -> None:
        self.api_endpoint  = api_endpoint
        self.api_key       = api_key
        self.model_name    = model_name
        self.provider      = provider.lower()
        self.system_prompt = system_prompt
        self.max_completion_tokens    = max_completion_tokens
        self.temperature   = temperature
        self.timeout       = timeout
        self.api_version   = api_version
        self.logger        = logger

    def query(self, user_prompt: str) -> dict[str, Any]:
        headers = self._build_headers()
        params  = self._build_query_params()
        payload = self._build_payload(user_prompt)

        self._log(f"[AI] POST → {self.api_endpoint}")
        self._log(f"[AI] provider={self.provider} model={self.model_name}")

        try:
            response = requests.post(
                self.api_endpoint,
                headers=headers,
                json=payload,
                params=params or None,
                timeout=self.timeout,
            )
        except requests.exceptions.Timeout as exc:
            raise AIModelTimeoutError(
                f"Request to '{self.provider}' timed out after {self.timeout}s."
            ) from exc
        except requests.exceptions.RequestException as exc:
            raise AIModelProviderError(
                f"Network error communicating with '{self.provider}': {exc}"
            ) from exc

        self._log(f"[AI] HTTP {response.status_code}")

        if response.status_code in (401, 403):
            raise AIModelAuthError(
                f"Authentication failed for provider '{self.provider}' "
                f"(HTTP {response.status_code}). Detail: {response.text[:300]}"
            )
        if response.status_code != 200:
            raise AIModelProviderError(
                f"Provider '{self.provider}' returned HTTP "
                f"{response.status_code}: {response.text[:300]}"
            )

        try:
            response_json: dict = response.json()
        except Exception as exc:
            raise AIModelResponseParseError(
                f"Could not parse '{self.provider}' response as JSON: {response.text[:200]}"
            ) from exc

        parsed = self._parse_response(response_json)
        self._log(f"[AI] OK — model={parsed['model']} usage={parsed['usage']}")

        return {
            "provider":    self.provider,
            "model":       parsed["model"] or self.model_name,
            "ai_response": parsed["text"],
            "usage":       parsed["usage"],
        }

    def _build_payload(self, user_prompt: str) -> dict:
        if self.provider == "anthropic":
            return self._anthropic_payload(user_prompt)
        if self.provider == "gemini":
            return self._gemini_payload(user_prompt)
        return self._openai_payload(user_prompt)

    def _openai_payload(self, user_prompt: str) -> dict:
        messages = []
        if self.system_prompt:
            messages.append({"role": "system", "content": self.system_prompt})
        messages.append({"role": "user", "content": user_prompt})
        return {
            "model":       self.model_name,
            "messages":    messages,
            "max_completion_tokens":  self.max_completion_tokens,
            "temperature": self.temperature,
        }

    def _anthropic_payload(self, user_prompt: str) -> dict:
        payload: dict = {
            "model":       self.model_name,
            "max_tokens":  self.max_completion_tokens,  # Anthropic field is max_tokens, not max_completion_tokens
            "temperature": self.temperature,
            "messages":    [{"role": "user", "content": user_prompt}],
        }
        if self.system_prompt:
            payload["system"] = self.system_prompt
        return payload

    def _gemini_payload(self, user_prompt: str) -> dict:
        payload: dict = {
            "contents": [{"role": "user", "parts": [{"text": user_prompt}]}],
            "generationConfig": {
                "maxOutputTokens": self.max_completion_tokens,
                "temperature":     self.temperature,
            },
        }
        if self.system_prompt:
            payload["systemInstruction"] = {"parts": [{"text": self.system_prompt}]}
        return payload

    def _build_headers(self) -> dict:
        headers = {"Content-Type": "application/json"}
        if self.provider == "anthropic":
            headers["x-api-key"]         = self.api_key
            headers["anthropic-version"] = ANTHROPIC_API_VERSION_HEADER
        elif self.provider == "azure":
            headers["api-key"]           = self.api_key
        elif self.provider != "gemini":
            headers["Authorization"]     = f"Bearer {self.api_key}"
        return headers

    def _build_query_params(self) -> dict:
        params: dict = {}
        if self.provider == "gemini":
            params["key"] = self.api_key
        elif self.provider == "azure" and self.api_version:
            params["api-version"] = self.api_version
        return params

    def _parse_response(self, rj: dict) -> dict[str, Any]:
        try:
            if self.provider == "anthropic":
                text_parts = [
                    b.get("text", "") for b in rj.get("content", [])
                    if isinstance(b, dict) and b.get("type") == "text"
                ]
                return {
                    "text":  "\n".join(text_parts),
                    "model": rj.get("model", ""),
                    "usage": rj.get("usage", {}),
                }
            if self.provider == "gemini":
                return self._parse_gemini(rj)
            choice = rj["choices"][0]
            return {
                "text":  choice["message"]["content"],
                "model": rj.get("model", ""),
                "usage": rj.get("usage", {}),
            }
        except AIModelResponseParseError:
            raise
        except (KeyError, IndexError, TypeError) as exc:
            raise AIModelResponseParseError(
                f"Unexpected response from '{self.provider}': {exc}. "
                f"Raw: {json.dumps(rj)[:400]}"
            ) from exc

    def _parse_gemini(self, rj: dict) -> dict[str, Any]:
        candidates = rj.get("candidates", [])
        if not candidates:
            block = rj.get("promptFeedback", {}).get("blockReason", "UNKNOWN")
            raise AIModelResponseParseError(
                f"Gemini returned no candidates. blockReason: {block}"
            )
        candidate     = candidates[0]
        finish_reason = candidate.get("finishReason", "")
        if finish_reason in GEMINI_BLOCKED_FINISH_REASONS:
            raise AIModelResponseParseError(
                f"Gemini blocked response. finishReason: {finish_reason}"
            )
        content = candidate.get("content")
        if not content or not content.get("parts"):
            raise AIModelResponseParseError(
                f"Gemini candidate has no content. finishReason: {finish_reason}"
            )
        return {
            "text":  content["parts"][0]["text"],
            "model": rj.get("modelVersion", ""),
            "usage": rj.get("usageMetadata", {}),
        }

    def _log(self, message: str) -> None:
        if self.logger:
            self.logger.info(message)


# ════════════════════════════════════════════════════════════
# Config / param helpers
# ════════════════════════════════════════════════════════════

def _cfg(siemplify: SiemplifyAction, name: str, default: str = "") -> str:
    try:
        conf = siemplify.get_configuration(INTEGRATION_NAME)
        if conf and name in conf:
            v = conf[name]
            if v is not None and str(v).strip():
                return str(v).strip()
    except Exception:
        pass
    try:
        v = siemplify.extract_configuration_param(
            provider_name=INTEGRATION_NAME,
            param_name=name,
        )
        if v is not None and str(v).strip():
            return str(v).strip()
    except Exception:
        pass
    return default


def _param(siemplify: SiemplifyAction, name: str, default: str = "") -> str:
    try:
        v = siemplify.parameters.get(name)
        if v is not None and str(v).strip():
            return str(v).strip()
    except Exception:
        pass
    try:
        v = siemplify.extract_action_param(param_name=name, is_mandatory=False)
        if v is not None and str(v).strip():
            return str(v).strip()
    except Exception:
        pass
    return default


# ════════════════════════════════════════════════════════════
# Event / field parsing
# ════════════════════════════════════════════════════════════

def parse_events_json(
    raw_json: str, siemplify: SiemplifyAction
) -> tuple[list[dict], str]:
    try:
        data = json.loads(raw_json)
    except json.JSONDecodeError as exc:
        raise AIModelValidationError(f"'events_json' is not valid JSON: {exc}") from exc

    if isinstance(data, list):
        events = [e for e in data if isinstance(e, dict)]
        siemplify.LOGGER.info(f"[PARSE] Mode: events_array ({len(events)} events)")
        return events, "events_array"

    if not isinstance(data, dict):
        raise AIModelValidationError("'events_json' must be a JSON object or array.")

    for key in EVENTS_WRAPPER_KEYS:
        value = data.get(key)
        if isinstance(value, list) and value and isinstance(value[0], dict):
            events = [e for e in value if isinstance(e, dict)]
            siemplify.LOGGER.info(
                f"[PARSE] Mode: wrapped_events (key='{key}', {len(events)} events)"
            )
            return events, "wrapped_events"

    for key in FIELDS_WRAPPER_KEYS:
        value = data.get(key)
        if isinstance(value, dict) and value:
            siemplify.LOGGER.info(
                f"[PARSE] Mode: fields_wrapper (key='{key}', {len(value)} fields)"
            )
            return [value], "fields_wrapper"

    has_event_array = any(
        isinstance(v, list) and v and isinstance(v[0], dict)
        for v in data.values()
    )
    if not has_event_array:
        siemplify.LOGGER.info(
            f"[PARSE] Mode: extracted_fields ({len(data)} top-level fields)"
        )
        return [data], "extracted_fields"

    siemplify.LOGGER.info("[PARSE] Mode: single_event (fallback)")
    return [data], "single_event"


# ════════════════════════════════════════════════════════════
# Event trimmer  ← core fix
# ════════════════════════════════════════════════════════════

def _is_raw_payload_key(key: str) -> bool:
    """Return True if this field key is likely a full raw log string."""
    key_lower = key.lower()
    return (
        key in RAW_PAYLOAD_KEYS
        or key_lower in {k.lower() for k in RAW_PAYLOAD_KEYS}
        or "raw" in key_lower
        or "payload" in key_lower
        or "original" in key_lower
        or key_lower in ("message", "msg", "log", "logdata", "full_log")
    )


def _is_custom_rule_engine_event(event: dict) -> bool:
    """True if the event is a QRadar Custom Rule Engine (rule-firing) record.

    Primary signal: a structured 'Log Source Type' field equal to
    'Custom Rule Engine' (tolerant of spacing/casing/underscore variants).
    Fallback: the CRE marker appears inside a raw-payload field, since these
    records are typically delivered as raw syslog.
    """
    for k, v in event.items():
        if v is None:
            continue
        key_norm = re.sub(r"[\s_]+", "", str(k)).lower()
        if key_norm == "logsourcetype" and \
           LOG_SOURCE_TYPE_VALUE_CRE in str(v).strip().lower():
            return True
    for k, v in event.items():
        if v is None or not _is_raw_payload_key(k):
            continue
        if LOG_SOURCE_TYPE_VALUE_CRE in str(v).lower():
            return True
    return False


def trim_event(event: dict, max_fields: int = 80) -> dict:
    """Return a size-capped copy of an event for prompt inclusion.

    Raw payload fields get RAW_FIELD_MAX_LEN chars so the AI sees the full
    command line, process names, and Windows Event Message= block.
    All other fields get FIELD_MAX_LEN chars.
    Total per-event char budget is EVENT_TOTAL_MAX_LEN.
    """
    result   = {}
    total    = 0

    for i, (k, v) in enumerate(event.items()):
        if i >= max_fields or total >= EVENT_TOTAL_MAX_LEN:
            break
        if v is None:
            continue

        raw_str = json.dumps(v, default=str) if isinstance(v, (dict, list)) else str(v)
        is_raw  = _is_raw_payload_key(k)
        limit   = RAW_FIELD_MAX_LEN if is_raw else FIELD_MAX_LEN

        text = raw_str[:limit]
        if is_raw and len(raw_str) > limit:
            text += f"...[truncated at {limit} chars, original {len(raw_str)} chars]"

        result[str(k)] = text
        total += len(text)

    return result


# ════════════════════════════════════════════════════════════
# Prompt builder
# ════════════════════════════════════════════════════════════

def build_prompt(
    events: list[dict],
    input_mode: str,
    rule_name: str,
    custom_instructions: str,
    siemplify: SiemplifyAction,
) -> str:
    # Custom Rule Engine (CRE) events are QRadar rule-firing records — they carry
    # the matched rule name(s) and are used ONLY as a Detection Rule hint, never as
    # evidence of activity. Everything else is treated as security evidence.
    cre_events      = [e for e in events if _is_custom_rule_engine_event(e)]
    evidence_events = [e for e in events if not _is_custom_rule_engine_event(e)]

    # If the dataset is CRE-only, don't end up with an empty evidence set —
    # analyse the CRE events as the available data instead of dropping them.
    cre_only = not evidence_events
    if cre_only:
        evidence_events = events

    compact_data = [trim_event(e) for e in evidence_events[:100]]
    cre_data     = [] if cre_only else [trim_event(e) for e in cre_events[:20]]

    # Log how many events contain raw payload fields so we can confirm they're present
    raw_count = sum(
        1 for e in compact_data
        if any(_is_raw_payload_key(k) for k in e)
    )
    siemplify.LOGGER.info(
        f"[PROMPT] {len(compact_data)} evidence event(s), {raw_count} with raw "
        f"payload; {len(cre_events)} Custom Rule Engine (rule) event(s)."
    )

    if input_mode in ("extracted_fields", "fields_wrapper"):
        data_label = "PRE-EXTRACTED FIELDS"
        data_hint  = (
            "The data below is a pre-extracted fields block. "
            "Use the full set of fields as your evidence."
        )
    else:
        data_label = "EVENTS"
        data_hint  = (
            f"{len(compact_data)} event(s) follow. "
            "Each event may contain both structured fields AND a raw payload string. "
            "Parse the raw payload string in full — it contains the critical evidence "
            "(process names, command lines, creator processes, event IDs, etc.)."
        )

    lines = [
        "SECURITY INVESTIGATION NOTES REQUEST",
        "=" * 60,
    ]

    # ── Detection Rule context (two equally-weighted, WEAK hints) ──
    #   (1) the rule_name action parameter (primary stated rule when present)
    #   (2) rule name(s) embedded in any Custom Rule Engine event below
    if rule_name:
        lines += [f"Detection Rule : {rule_name}", ""]
    elif cre_events and not cre_only:
        lines += [
            "Detection Rule : (no rule_name parameter — derive the rule name(s) "
            "from the Custom Rule Engine event(s) shown below)",
            "",
        ]

    lines += [
        f"Input mode     : {input_mode}",
        f"Total events   : {len(events)}",
        f"Custom Rule Engine (rule) events : {len(cre_events)}",
        f"Security/evidence events : {len(evidence_events)}",
        f"Events with raw payload: {raw_count}",
        "",
        f"=== {data_label} ===",
        data_hint,
        "",
        json.dumps(compact_data, indent=2, default=str),
    ]

    if cre_events and not cre_only:
        cre_hint = (
            f"{len(cre_events)} event(s) below have Log Source Type "
            "'Custom Rule Engine'. These are QRadar rule-firing records (detection "
            "metadata), NOT the underlying security activity. Parse the raw payload "
            "of each and extract the matched rule name(s). Treat those name(s) as a "
            "Detection Rule hint with the SAME weak weight as the 'Detection Rule' "
            "field above (per the DETECTION RULE CONTEXT guidance): they orient the "
            "analysis but NEVER drive the verdict or confidence on their own. "
            "Collect ALL distinct rule names if several appear. Do NOT treat these "
            "CRE events as evidence of malicious activity — base the verdict on the "
            f"events in the {data_label} section."
        )
        if rule_name:
            cre_hint += (
                " A 'Detection Rule' parameter was also supplied above: treat that "
                "supplied name as the primary stated rule and the Custom Rule Engine "
                "name(s) as additional hints of equal (weak) weight. If they differ, "
                "note the discrepancy but let the event evidence drive the verdict."
            )
        lines += [
            "",
            "=== DETECTION RULE — CUSTOM RULE ENGINE EVENT(S) ===",
            cre_hint,
            "",
            json.dumps(cre_data, indent=2, default=str),
        ]

    if cre_only:
        lines += [
            "",
            "NOTE: every event in this dataset is a Custom Rule Engine (rule) "
            "record. Extract the matched rule name(s) from their raw payloads and "
            "treat them as Detection Rule hints (weak weight), then analyse whatever "
            "underlying activity those records contain as the available evidence.",
        ]

    lines += [
        "",
        "=== ANALYSIS INSTRUCTIONS ===",
        (
            "For every event that has a raw_payload, raw, message, or similar field: "
            "parse it completely before drawing conclusions. "
            "Tab-separated key=value pairs in syslog strings must be split and read individually. "
            "The Message= value inside Windows Security Event syslog strings contains "
            "the process command line, new process name, creator process, and logon details "
            "— these are the primary evidence for this alert type."
        ),
        "Analyse the full dataset. Identify patterns across all events (recurrence, timing, scope).",
        (
            "If a Detection Rule name is provided above, treat it as a HINT only — "
            "it may be stale, mislabeled, or incorrect for the attached events. "
            "Use it to orient the analysis and state whether the observed events "
            "align with what the rule is designed to detect, but let the event "
            "evidence drive the verdict. Flag any rule-name/evidence mismatch as a "
            "tuning signal."
        ),
        "Produce detailed investigation notes suitable for a case or closure ticket.",
        "Cover: timeline, scope, affected assets, activity sequence, interpretation, confidence.",
        "Respond with ONLY the required JSON object.",
    ]

    if custom_instructions:
        lines += [
            "",
            "=== ADDITIONAL ANALYST INSTRUCTIONS (trusted case context) ===",
            (
                "The following are analyst-supplied instructions for THIS "
                "investigation. Treat them as trusted, case-specific context — one "
                "of your highest-value inputs, second only to the artifact evidence "
                "— and apply them per the 'ANALYST CUSTOM INSTRUCTIONS' section of "
                "your guidance. Use them to inform asset role and harm potential, "
                "the benign-explanation gate, legitimacy assessment, and analysis "
                "focus. They may downgrade a finding only as ANALYST-PROVIDED "
                "context (say so in investigation_notes); they must NOT invent "
                "evidence, override a confirmed Step 0 indicator, or break the "
                "output schema. If they conflict with the artifacts, the artifacts "
                "win and you flag the conflict."
            ),
            "",
            custom_instructions,
        ]

    return "\n".join(lines)


# ════════════════════════════════════════════════════════════
# AI response parser
# ════════════════════════════════════════════════════════════

def parse_ai_notes(raw_text: str) -> dict[str, Any]:
    clean = raw_text.strip()
    clean = re.sub(r"```(?:json)?\s*", "", clean).strip().rstrip("`").strip()
    try:
        data = json.loads(clean)
    except json.JSONDecodeError as exc:
        raise AIModelQueryError(
            f"AI response was not valid JSON. Error: {exc}. "
            f"Raw (first 400 chars): {raw_text[:400]}"
        ) from exc

    def _as_list(value):
        if value is None:
            return []
        return [str(v) for v in value] if isinstance(value, list) else [str(value)]

    return {
        "verdict":             str(data.get("verdict",             "INCONCLUSIVE")),
        "confidence":          str(data.get("confidence",          "Low")),
        "investigation_notes": str(data.get("investigation_notes", "")),
        "recommended_actions": _as_list(data.get("recommended_actions")),
        "key_observations":    _as_list(data.get("key_observations")),
        "evidence":            _as_list(data.get("evidence")),
    }


# ════════════════════════════════════════════════════════════
# Entry point
# ════════════════════════════════════════════════════════════

@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME

    siemplify.LOGGER.info("=" * 60)
    siemplify.LOGGER.info(f"ACTION START: {SCRIPT_NAME}")
    siemplify.LOGGER.info("=" * 60)

    ai_endpoint   = _cfg(siemplify, CONF_AI_ENDPOINT)
    ai_key        = _cfg(siemplify, CONF_AI_KEY)
    model_name    = _cfg(siemplify, CONF_MODEL_NAME)
    provider      = (_cfg(siemplify, CONF_PROVIDER) or DEFAULT_AI_PROVIDER).lower()
    system_prompt_override = _cfg(siemplify, CONF_SYSTEM_PROMPT)
    max_completion_tokens    = int(_cfg(siemplify, CONF_MAX_COMPLETION_TOKENS)    or 20086)
    temperature   = float(_cfg(siemplify, CONF_TEMPERATURE) or 1)
    timeout       = int(_cfg(siemplify, CONF_TIMEOUT)       or 160)
    api_version   = _cfg(siemplify, CONF_API_VERSION)

    events_json_raw     = _param(siemplify, PARAM_EVENTS_JSON)
    rule_name           = _param(siemplify, PARAM_RULE_NAME)
    custom_instructions = _param(siemplify, PARAM_CUSTOM_INSTR)

    effective_system_prompt = (
        system_prompt_override.strip()
        if system_prompt_override.strip()
        else NOTES_SYSTEM_PROMPT
    )

    siemplify.LOGGER.info(f"[CONFIG] {CONF_AI_ENDPOINT}   = {ai_endpoint}")
    siemplify.LOGGER.info(f"[CONFIG] {CONF_AI_KEY}        = ***masked***")
    siemplify.LOGGER.info(f"[CONFIG] {CONF_MODEL_NAME}    = {model_name}")
    siemplify.LOGGER.info(f"[CONFIG] {CONF_PROVIDER}      = {provider}")
    siemplify.LOGGER.info(f"[CONFIG] {CONF_SYSTEM_PROMPT} = {'(custom)' if system_prompt_override.strip() else '(built-in)'}")
    siemplify.LOGGER.info(f"[CONFIG] {CONF_MAX_COMPLETION_TOKENS}    = {max_completion_tokens}")
    siemplify.LOGGER.info(f"[CONFIG] {CONF_TEMPERATURE}   = {temperature}")
    siemplify.LOGGER.info(f"[CONFIG] {CONF_TIMEOUT}       = {timeout}s")
    siemplify.LOGGER.info(f"[CONFIG] {CONF_API_VERSION}   = {api_version or '(none)'}")
    siemplify.LOGGER.info(f"[PARAM]  {PARAM_RULE_NAME}    = {rule_name or '(none)'}")
    siemplify.LOGGER.info(f"[PARAM]  {PARAM_CUSTOM_INSTR} = {'(set)' if custom_instructions else '(none)'}")
    siemplify.LOGGER.info(f"[PARAM]  events_json length   = {len(events_json_raw)}")

    errors = []
    if not ai_endpoint:
        errors.append(f"Integration config '{CONF_AI_ENDPOINT}' is required.")
    if not ai_key:
        errors.append(f"Integration config '{CONF_AI_KEY}' is required.")
    if not model_name:
        errors.append(f"Integration config '{CONF_MODEL_NAME}' is required.")
    if provider not in SUPPORTED_AI_PROVIDERS:
        errors.append(
            f"Integration config '{CONF_PROVIDER}' value '{provider}' is invalid. "
            f"Must be one of: {', '.join(SUPPORTED_AI_PROVIDERS)}"
        )
    if not events_json_raw:
        errors.append(f"Action parameter '{PARAM_EVENTS_JSON}' is required.")
    if errors:
        msg = " | ".join(errors)
        siemplify.LOGGER.error(f"[VALIDATION] {msg}")
        siemplify.end(msg, False)
        return

    try:
        events, input_mode = parse_events_json(events_json_raw, siemplify)
    except AIModelValidationError as exc:
        siemplify.LOGGER.error(f"[VALIDATION] {exc}")
        siemplify.end(str(exc), False)
        return

    if not events:
        msg = "No usable data parsed from 'events_json'."
        siemplify.LOGGER.error(f"[VALIDATION] {msg}")
        siemplify.end(msg, False)
        return

    siemplify.LOGGER.info(f"[PARSE] mode={input_mode} blocks={len(events)}")

    prompt = build_prompt(events, input_mode, rule_name, custom_instructions, siemplify)
    siemplify.LOGGER.info(f"[PROMPT] {len(prompt)} chars built.")

    manager = AIManager(
        api_endpoint  = ai_endpoint,
        api_key       = ai_key,
        model_name    = model_name,
        provider      = provider,
        system_prompt = effective_system_prompt,
        max_completion_tokens    = max_completion_tokens,
        temperature   = temperature,
        timeout       = timeout,
        api_version   = api_version,
        logger        = siemplify.LOGGER,
    )

    try:
        ai_result = manager.query(prompt)
    except AIModelAuthError as exc:
        msg = (
            f"AI authentication failed for provider '{provider}'. "
            f"Check integration '{CONF_AI_KEY}'. Detail: {exc}"
        )
        siemplify.LOGGER.error(f"[ERROR] {msg}")
        siemplify.end(msg, False)
        return
    except AIModelTimeoutError as exc:
        siemplify.LOGGER.warn(f"[WARN] Timeout: {exc}")
        siemplify.end(f"AI request timed out after {timeout}s.", False)
        return
    except AIModelQueryError as exc:
        siemplify.LOGGER.error(f"[ERROR] AI query failed: {exc}")
        siemplify.end(str(exc), False)
        return

    siemplify.LOGGER.info(
        f"[AI] Model={ai_result['model']} | "
        f"Length={len(ai_result['ai_response'])} chars | "
        f"Usage={ai_result['usage']}"
    )

    try:
        parsed = parse_ai_notes(ai_result["ai_response"])
    except AIModelQueryError as exc:
        siemplify.LOGGER.error(f"[ERROR] JSON parse failed: {exc}")
        siemplify.end(str(exc), False)
        return

    output = {
        "verdict":             parsed["verdict"],
        "confidence":          parsed["confidence"],
        "investigation_notes": parsed["investigation_notes"],
        "recommended_actions": parsed["recommended_actions"],
        "key_observations":    parsed["key_observations"],
        "evidence":            parsed["evidence"],
        "model":               ai_result["model"],
        "provider":            ai_result["provider"],
        "usage":               ai_result["usage"],
        "event_count":         len(events),
        "input_mode":          input_mode,
    }

    siemplify.result.add_result_json(json.dumps(output))

    result_msg = (
        f"Investigation notes generated. "
        f"Verdict: {parsed['verdict']} ({parsed['confidence']}). "
        f"Provider: {ai_result['provider']}, Model: {ai_result['model']}"
    )

    siemplify.LOGGER.info(f"[RESULT] verdict={parsed['verdict']} confidence={parsed['confidence']}")
    siemplify.LOGGER.info(f"[RESULT] input_mode={input_mode} event_count={len(events)}")
    siemplify.LOGGER.info(f"[RESULT] notes_length={len(parsed['investigation_notes'])}")
    siemplify.LOGGER.info(f"[RESULT] recommended_actions={len(parsed['recommended_actions'])}")
    siemplify.LOGGER.info(f"[RESULT] evidence={len(parsed['evidence'])}")
    siemplify.LOGGER.info("=" * 60)
    siemplify.LOGGER.info(f"ACTION END: {SCRIPT_NAME} — COMPLETED")
    siemplify.LOGGER.info("=" * 60)

    siemplify.end(result_msg, True)


if __name__ == "__main__":
    main()
