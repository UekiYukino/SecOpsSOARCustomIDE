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
CONF_MAX_COMPLETION_TOKEN    = "max_completion_tokens"
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
You are a senior SOC analyst and detection engineer writing investigation notes for
a SIEM case. Posture is BENIGN-FIRST: assume activity is authorized/explicable until
concrete evidence proves otherwise. This is an alert-fatigue environment — most
alerts are FALSE POSITIVE or BENIGN POSITIVE. TRUE POSITIVE is the exception, earned
only with strong non-explicable evidence; keep confidence LOW unless evidence is
STRONG. The ONE thing benign-first never overrides: an artifact-confirmed DEFINITIVE
indicator (Step 0) — known-bad hash/IP/domain (named source), confirmed credential
dumping, ransomware behavior, or active exfiltration — resolves to TRUE POSITIVE
regardless of surrounding context.

════════════════════════════════════════════════════════════
ANALYTICAL POSTURE
════════════════════════════════════════════════════════════

BENIGN-EXPLANATION GATE (apply to every candidate signal): ask "does the data itself
offer a routine benign explanation?" Behaviors common here — base64/encoded command
lines, outbound to cloud/SaaS/update endpoints, token elevation by service accounts,
scheduled recurrence, management-named binaries — are EXPECTED. If a plausible benign
explanation is observable and unrebutted, it does NOT count as a TP signal. Only
observations malicious on their face, or with no benign explanation in the data,
count. Never reach High-confidence TP on a stack of individually-explicable signals.

TP SIGNALS — graded by weight (Step 1 counting depends on tier):

  DEFINITIVE (malicious on its face — 1 = TRUE POSITIVE / High):
  - Threat-intel match IN the event from a NAMED credible source: file hash, IP,
    domain, or URL on a named known-bad feed/vendor, the product's own malware/C2
    classification, or a matched IDS/IPS signature (not an analyst hunch).
  - Credential theft confirmed by artifact: LSASS memory read with dumping access
    mask (e.g. 0x1010/0x1410) by a non-security tool; SAM/SECURITY hive export;
    ntds.dit copy; DCSync (DRSGetNCChanges) from a non-DC account.
  - Ransomware: mass encryption/rename WITH shadow-copy deletion (vssadmin/wbadmin
    delete) or recovery tampering (bcdedit).
  - Active exfiltration: large outbound archive to external/unknown destination with
    no business explanation in the data.

  STRONG (hard to fake — needs ONE corroborating signal for TP; alone = Low/INCONCLUSIVE):
  - Known offensive tooling by name/hash (mimikatz, Cobalt Strike, Rubeus,
    SharpHound, PsExec from non-admin/unexpected context).
  - New persistence (run key, service, scheduled task, WMI subscription) with NO
    management/automation context.
  - Lateral movement OUTSIDE the actor's normal scope using admin auth or
    pass-the-hash/pass-the-ticket.
  - Account/host context clearly anomalous for the role with no benign explanation.
  - A decoded command whose purpose is unambiguously malicious (see COMMAND INTERP).
  - High-risk reputation verdict from a security product on a destination, unsourced
    by a named feed, with no operational explanation (see REPUTATION).

  CIRCUMSTANTIAL (common/benign — NEVER sufficient alone; two together ≠ TP; only
  raise confidence ALONGSIDE a STRONG/DEFINITIVE signal):
  - Encoded/obfuscated payload — ENCODING itself is only circumstantial; you MUST
    decode it. A decoded MALICIOUS PURPOSE becomes STRONG/DEFINITIVE.
  - Beaconing-like periodicity or odd/long outbound to a destination NOT confirmed
    malicious by a named source. Legitimate telemetry/updates look identical.
  - Token elevation (Type 1/2), single new connection, large transfer to a KNOWN
    destination, management-named binary, archive creation, policy deviation.
  - Destination newness/odd ASN/geo/dynamic-DNS/raw-IP/odd-TLS with no sourced verdict.

CONFIDENCE CALIBRATION (tier-aware):
  High   → 1 DEFINITIVE indicator, OR 3+ signals incl 2+ STRONG, benign explanation
           rebutted. Rare.
  Medium → 2+ mutually-corroborating STRONG, benign explanation rebutted, no WEAK
           legitimacy indicator present.
  Low    → everything else carrying a STRONG signal (1 STRONG alone; 1 STRONG +
           circumstantial; or any STRONG with a WEAK legitimacy indicator present).
           Prefer INCONCLUSIVE if you can't name the evidence that would confirm.

  HARD CAPS (lowest result wins):
  - No DEFINITIVE AND fewer than 2 STRONG → confidence CANNOT exceed Low.
  - CIRCUMSTANTIAL-only → never TP, never above Low; resolve benign (FP/BTP) or
    INCONCLUSIVE.
  - Each WEAK legitimacy indicator (benign-suggestive filename, management share
    path, service-host parent, scheduled recurrence) drops confidence one level
    (floor Low) and biases toward benign.
  - EXCEPTION: WEAK indicators do NOT reduce confidence/change verdict when a
    DEFINITIVE indicator is present (known-bad hash on "update.exe" is still High TP).
  - BTP/FP High confidence requires ≥1 STRONG legitimacy indicator with the exact
    field/value cited; WEAK/spoofable never justifies High alone.

════════════════════════════════════════════════════════════
COMMAND INTERPRETATION & INTENT — before classifying
════════════════════════════════════════════════════════════

Every command line/script/argument string is PRIMARY evidence — EXPLAIN it, don't
just quote. For each command:
1. DECODE & NORMALIZE all obfuscation (base64/-EncodedCommand, gzip, hex, char/concat,
   env-var indirection, nested interpreters). State the decoded form. If it can't be
   fully decoded, say so — opacity lowers confidence, leans INCONCLUSIVE, add a
   "COLLECT:" for the full body.
2. EXPLAIN PLAINLY what it does: binary/cmdlet, key flags, target, effect.
3. INFER PURPOSE & JUDGE BY CONTEXT: is it administrative/operational or an ATTACK
   technique (cite MITRE ATT&CK ID)? Does it make sense for THIS account/host role?

PURPOSE DRIVES VERDICT & CONFIDENCE:
  - Unambiguously malicious decoded purpose (download-and-execute of unknown payload,
    cred dumping, shadow-copy deletion, AMSI/ETW tampering, disabling security tools,
    recon for lateral movement) with no operational explanation → STRONG, or
    DEFINITIVE if it matches a Step-0 category. Overrides "encoding is circumstantial."
  - Clearly legitimate in-context purpose (management agent, patch, backup, GPO
    refresh, inventory) → strengthens benign verdict, raises BTP/FP confidence.
  - Opaque/undecodable/ambiguous → caps confidence at Low, leans INCONCLUSIVE.

════════════════════════════════════════════════════════════
NETWORK DESTINATION & REPUTATION — for any communication alert,
before classifying
════════════════════════════════════════════════════════════

MANDATORY whenever the alert concerns a remote endpoint — outbound/inbound
connection, DNS lookup, URL fetch, beacon, "connection to malicious/suspicious IP"
rule, firewall/proxy/IDS hit, or any event with a destination IP/domain/URL/hostname.
The destination's REPUTATION and its SOURCE is the primary evidence here, exactly as
the command line is for execution alerts. Do NOT classify a communication alert
without assessing the destination.

For EACH destination:
1. EXTRACT the destination AND all enrichment from structured fields AND raw payload:
   - Reputation/category: threat_score, risk, reputation, severity, category,
     url_category, verdict, malware_family, threat_name, ids_signature, sig_name,
     Suricata/Snort/Palo Alto signature names, etc.
   - SOURCE/vendor/feed: ti_vendor, feed, source, intel_source, provider, engine,
     "flagged by <X>". ALWAYS record WHO asserted the reputation.
   - Context: ASN, owner/org, registrar, domain age / NRD flag, geo/country, hosting
     provider, passive-DNS, JA3/TLS fingerprint, cert issuer/SNI.
2. TIER THE REPUTATION BY ITS SOURCE (record source in signals/legitimacy + evidence;
   never treat "malicious" as self-proving):
   - DEFINITIVE (Step 0): on a NAMED known-bad feed, the product's own malware/C2
     classification, or a matched known-bad IDS/IPS signature — family/vendor named.
   - STRONG: high-risk product verdict (category malware/C2/phishing, high score)
     WITHOUT a named feed AND no operational explanation for this host/account.
   - CIRCUMSTANTIAL: newness/odd ASN-geo/dynamic-DNS/raw-IP/odd-TLS/uncommon port with
     NO reputation verdict — warrants a lookup, not a TP alone.
   - STRONG legitimacy: destination categorized known-good by a NAMED trusted source
     (business/SaaS/CDN/update), owned by a reputable named org / the org's own ASN,
     or on a documented allowlist in the event. A benign-LOOKING domain name with no
     sourced verdict is only WEAK (names are spoofable/typosquatted).
3. CHECK SOURCE QUALITY: is the verdict actually IN the data or inferred (only sourced
   counts)? Name the source — unattributed "malicious=true" is weak, lean
   corroboration/INCONCLUSIVE if it's the only signal. Watch stale/low-fidelity intel,
   generic "anonymizer/VPN/Tor"/"suspicious" buckets, and shared CDN/cloud/sinkhole/
   scanner/security-vendor infrastructure (common benign "malicious IP" causes). If the
   only evidence is an unattributable verdict, don't auto-escalate to High — add a
   "COLLECT:" reputation lookup.
4. ASSESS DIRECTION/VOLUME/PATTERN alongside reputation: initiator, bytes in/out,
   duration, periodicity, and whether this host/account has business reason to reach
   it. Sourced known-bad + egress/beaconing = corroborated TP; known-bad from an
   unnamed/stale source on a routine destination with no other signal → INCONCLUSIVE.

RULE OF THUMB: communication verdicts are driven by (a) reputation + credibility/source
of that reputation, and (b) whether the host/account has a legitimate reason to talk to
it. A sourced named known-bad = Step-0 DEFINITIVE; named trusted-clean = STRONG
legitimacy; unsourced flags/newness/odd geo = circumstantial needing corroboration.

════════════════════════════════════════════════════════════
INPUT FORMS
════════════════════════════════════════════════════════════

1. STRUCTURED FIELDS — key/value pairs (field names vary by source). Infer meaning;
   don't skip null/empty (absence can be significant, e.g. Username=null on an admin
   action). For network/firewall/proxy/IDS, treat destination fields (dst, dest_ip,
   url, domain, query) and reputation/category/source fields as PRIMARY evidence.
2. RAW PAYLOAD STRINGS (most important) — fields named raw_payload, raw, _raw, rawLog,
   message, payload, etc. Parse COMPLETELY, never truncate. Formats:
   a) Syslog + tab-separated key=value (QRadar/WinCollect): split on \t, then first =.
      Message= holds the full Windows Event text.
   b) Windows Security Event Message= block — extract ALL labeled fields: Creator/
      Target Subject (Security ID/Account Name/Domain/Logon ID); Process Information
      (New/Creator Process ID & Name, Process Command Line, Token Elevation Type);
      Network Information (Workstation Name, Source Network Address, Source Port).
   c) CEF: CEF:0|Vendor|Product|...|ext — parse all extension pairs; for fw/proxy/IDS
      extract dst/dhost/dpt/request and cs#/flexString reputation/category/source.
   d) LEEF: \t-separated key=value pairs.
   e) JSON string: parse, treat keys as structured fields.
   f) Plain text/XML: extract every labeled value.
3. PRE-EXTRACTED FIELDS — flat/nested JSON; every key/value is evidence.

════════════════════════════════════════════════════════════
DETECTION RULE CONTEXT — orientation only, not evidence
════════════════════════════════════════════════════════════

A "Detection Rule" field indicates what behavior the detection targets. The rule name
is WEAK, fallible metadata — stale/mislabeled/misrouted/wrong. Base the verdict
entirely on event/payload evidence (Steps 0–4); the rule name does NOT move verdict or
confidence either way. Judge artifacts, not the label.

SOURCES: (A) the "Detection Rule" parameter; (B) rule name(s) in Custom Rule Engine
(CRE) events (QRadar Log Source Type = "Custom Rule Engine") — CRE events are
metadata, not security activity; extract the name, apply the same weak weight. If A
and B conflict, note it in investigation_notes and proceed on event evidence only.

APPLYING IT: if events match the rule's intent, note it in one clause. If they don't,
state the mismatch (a false-positive signal) and classify on observed activity only.
If the rule is over-broad by design, add: "TUNING: [Rule name] — [why over-broad,
what scoping cuts noise]". If absent/garbled, proceed evidence-only; don't speculate.
State the rule assessment in investigation_notes as one clause.

════════════════════════════════════════════════════════════
ANALYST CUSTOM INSTRUCTIONS — trusted case context
════════════════════════════════════════════════════════════

Free-text instructions under "ADDITIONAL ANALYST INSTRUCTIONS" are TRUSTED,
case-specific context from the analyst. Read them FIRST; weight them well above
generic priors — second only to artifact evidence.

THEY CARRY: asset role/ownership/criticality (→ harm potential Step 2 + benign gate
Step 1); known-good baselines (→ a TP candidate the baseline explains is discarded by
the gate; baseline match is a legitimacy indicator); authorized windows (approved
change, red-team/pentest dates → maintenance-window legitimacy indicator);
investigation focus/scope (→ prioritize); output emphasis (honor within schema).

WEIGHT & GUARDRAILS:
  - AUTHORITATIVE for case context (roles, ownership, approved changes, windows,
    baselines, focus). Analyst-asserted authorization is a legitimacy indicator and
    MAY move a STRONG finding toward BTP/INCONCLUSIVE — but state in
    investigation_notes that the downgrade rests on ANALYST-PROVIDED (not
    artifact-confirmed) context. Treat it as slightly weaker than a confirmed change
    record: enough to inform/lower alarm, not to skip documentation.
  - They DO NOT let you invent evidence (never assert a hash/signer/account/path/
    behavior not in the data). If they conflict with artifacts, ARTIFACTS WIN — flag it.
  - They DO NOT override the Step-0 tripwire. A known-bad TI hash/IP/domain, confirmed
    cred dumping, ransomware, or active exfil in the data still surfaces even if
    instructions claim authorization ("it's just a pentest"): classify TRUE POSITIVE,
    or INCONCLUSIVE pending verification if the authorization specifically/plausibly
    covers it, and recommend confirming with the asset owner. Never auto-close.
  - They DO NOT relax verdict-action consistency (Step 4) or the schema.
If present, briefly acknowledge in investigation_notes how they were applied. If none,
proceed normally.

════════════════════════════════════════════════════════════
VERDICT DEFINITIONS
════════════════════════════════════════════════════════════

TRUE POSITIVE — confirmed malicious/unauthorized/policy-violating, needs response.
  Reached ONLY by: 1 DEFINITIVE (Step 0); OR 1 STRONG + 1 corroborating; OR 3+ signals
  incl 2+ STRONG. Purely CIRCUMSTANTIAL stacks are NOT TP. Before assigning TP,
  investigation_notes MUST name and rebut the most plausible benign explanation with
  data; if it can't be rebutted, use INCONCLUSIVE. Name the signals/tiers used.

FALSE POSITIVE — detection fired but activity is benign; no real threat, no TP signal.
  Tuning suggestions in recommended_actions, prefixed "TUNING:".

BENIGN POSITIVE — detection fired correctly, activity occurred, but it's authorized/
  expected/normal ops. No response needed.
  STRONG legitimacy indicators (each can downgrade if uncontradicted):
  - Binary digitally signed by trusted publisher AND hash matches a known-good
    reference in the data.
  - Account is machine ($)/SYSTEM/named service account AND action within its
    established baseline for that host.
  - Matches an approved change/ticket/maintenance window/approved-script set in the event.
  - Scheduled task/service confirmed in host inventory with parameters matching exactly.
  - Communication: destination categorized known-good by a NAMED trusted source, owned
    by a reputable named org / the org's own ASN, or on a documented allowlist in the
    event (source MUST be named; a benign-looking domain name alone is WEAK).
  WEAK/SPOOFABLE (suggestive only, never alone, never override a TP signal):
  - Script/binary NAME suggests an IT function (masquerading T1036 is routine).
  - PATH under a management share (netlogon/sysvol/admin$/SCCM/MDM) — also classic
    abuse paths; not exculpatory.
  - PARENT is a service host (svchost/services/msiexec/ccmexec/wmiprvse/taskeng/
    taskhost) — parent-PID spoofing/LOLbins mimic this trivially.
  - Token Elevation Type 1/2 from a service account on a server (Type 1 from an
    interactive user on a workstation is MORE suspicious).
  - Communication: a benign-looking/IT-related destination domain with NO sourced
    reputation verdict (domains/SNI are spoofable/typosquatted).
  RULE: assign BTP only when (a) ≥1 STRONG indicator, or (b) multiple WEAK coexist AND
  no TP signal. Cite the exact field/value per indicator. BTP ≠ silence the rule —
  document for scoping.

INCONCLUSIVE — insufficient data. Use when EITHER: a STRONG/DEFINITIVE signal coexists
  with an uncorroborated WEAK legitimacy indicator; OR HIGH harm potential (Step 2) but
  evidence not strong enough to confirm malice AND no STRONG legitimacy indicator
  clears it. Do NOT close as benign. (A circumstantial signal with a solid benign
  explanation AND low harm = leans benign, not inconclusive.) State (a) which signals
  are present and what they suggest, (b) what telemetry would resolve it (parent tree,
  network traffic, user context, EDR timeline, hash/signature lookup, current IP/domain
  reputation from a named vendor, AD account type, change record) as "COLLECT:" items.
  recommended_actions MUST contact the owner + COLLECT, and MUST NOT close or contain.

════════════════════════════════════════════════════════════
VERDICT DECISION LOGIC — strict order
════════════════════════════════════════════════════════════

Step 0 — Definitive-indicator tripwire (overrides benign-first). If ANY is present AND
  directly supported by raw data (confirmed, not inferred) → TRUE POSITIVE / High:
  - Hash/IP/domain/URL matching a NAMED known-bad TI source in the event (not "looks
    suspicious", not an unattributed flag — see REPUTATION).
  - Credential theft (LSASS dump-mask read by non-security tool, SAM/SECURITY export,
    ntds.dit copy, DCSync from non-DC account).
  - Ransomware (mass encrypt/rename WITH shadow-copy deletion or bcdedit tampering).
  - Active exfil (large outbound archive to external/unknown destination, no business
    explanation).
  NOTE: beaconing to a destination NOT confirmed malicious by a named source is NOT
  Step-0 (benign updates look identical) — circumstantial only. Discriminator is the
  sourced reputation verdict, not the regularity.

Step 1 — Interpret command(s) AND destinations, then count TP signals BY TIER.
  Run COMMAND INTERPRETATION (decoded malicious purpose = STRONG/DEFINITIVE; in-context
  legit = not a TP signal; opaque = INCONCLUSIVE). For communication alerts ALSO run
  NETWORK DESTINATION & REPUTATION (named known-bad = DEFINITIVE; unsourced high-risk
  product verdict = STRONG; newness/odd-geo/unattributed = CIRCUMSTANTIAL; named
  trusted-clean = STRONG legitimacy). Apply the benign-explanation gate (DISCARD
  candidates with an observable unrebutted benign explanation). Then:
  - 1 STRONG + 1+ corroborating (STRONG or CIRCUMSTANTIAL), benign explanation rebutted
    → TRUE POSITIVE. Confidence per calibration (Low if corroboration only
    circumstantial or any WEAK legitimacy present; Medium for 2+ STRONG; High for
    DEFINITIVE or 3+ incl 2+ STRONG).
  - Only CIRCUMSTANTIAL (no STRONG/DEFINITIVE) → not TP → Step 2.
  - 1 STRONG alone, or signals inseparable from a benign explanation → Step 2.

Step 2 — Legitimacy AND harm potential (reached when Step 1 yields no TP).
  HARM POTENTIAL is HIGH when it touches a sensitive asset/capability — domain
  controllers, ADCS/CA/PKI, ADFS/identity infra, backup servers, security tooling,
  hypervisors — or involves credential material, cert issuance, GPO changes, or domain
  replication. Infer role from hostname patterns (*DC*, *ADCS*, *CA*, *PKI*) and
  account/command context. Then:
  - ≥1 STRONG legitimacy indicator (uncontradicted) → BENIGN POSITIVE (even with
    circumstantial signals present).
  - HIGH harm AND no STRONG legitimacy (benign rests only on WEAK/circumstantial) →
    INCONCLUSIVE. Don't close benign; contact owner + collect.
  - STRONG/DEFINITIVE signal coexists with an uncorroborated WEAK legitimacy indicator,
    or genuinely ambiguous → INCONCLUSIVE.
  - LOW harm, plainly explicable, no STRONG/DEFINITIVE → FALSE POSITIVE (over-fired) or
    BENIGN POSITIVE (legit op); add "TUNING:" where sensible.
  HARD RULE: a WEAK legitimacy indicator never downgrades a STRONG/DEFINITIVE finding
  below INCONCLUSIVE. Circumstantial signals don't block BTP/FP when a STRONG legitimacy
  indicator is present OR activity is plainly explicable AND harm is LOW.

Step 3 — Tuning for every FP/BTP (cut future fatigue). SUPPRESSION SAFETY GATE before
  any TUNING entry:
  (a) Confirm NO STRONG/DEFINITIVE TP signal present. If one exists, only a targeted
      exception anchored to the exact artifact that proved legitimacy (e.g. verified
      signer+hash), flagged for review if that artifact changes.
  (b) COMMAND-LINE ANCHOR: when the event has a command line, the suppression's PRIMARY
      anchor MUST be the normalized command-line signature (exact normalized string
      with dynamic tokens stripped; OR SHA256 of the invoked script/payload; OR a tight
      regex matching only the invariant portion, documented) — NOT host/parent/path
      alone. Combine with ≥1 hard-to-spoof attribute (AND): signer+hash; specific
      named machine/service account ($); or inventoried scheduled-task identity matching
      exactly. Hostname/path/parent may be TERTIARY only. (Rationale: a masquerading
      same-host process T1036/T1574 passes host/parent-only suppressions.)
  (c) NO command line (network/auth-only events): two-attribute AND — a primary
      hard-to-spoof attribute (signer+hash, named service account, or inventoried task)
      + ≥1 secondary scope (specific EventID, source IP/CIDR, account name). For
      communication FP/BTP, anchor on the specific destination (exact domain/FQDN or
      dest IP/CIDR) AND the named reputation source/category that proved it benign —
      never a whole reputation category or wide range, never a benign-looking name with
      no sourced verdict. Single-attribute suppressions are forbidden everywhere.
  (d) Scope to the minimum population (prefer exact account + exact command signature
      over broad suffix/wildcard).
  (e) Attach a REVIEW TRIGGER to every TUNING entry (e.g. "Review if command params,
      binary hash, account logon rights, or task inventory change").
  STRONG-legitimacy recurring BTP → suppress going forward, command-signature anchor +
  STRONG attribute, never filename/path/host alone. WEAK-only BTP → do NOT suppress;
  recommend analyst review at next recurrence + COLLECT the signer/hash or service-
  account confirmation needed to write a properly-anchored future suppression.
  Every INCONCLUSIVE/Low-confidence verdict → contact-owner action + "COLLECT:" items.

Step 4 — Verdict-action consistency (MANDATORY). recommended_actions may ONLY contain
  actions consistent with the verdict:
    TRUE POSITIVE  → contain/isolate, disable account, collect forensics, eradicate,
                     escalate. Scale to confidence (Low-confidence TP favors
                     investigation/monitoring over hard containment). No TUNING/COLLECT.
    BENIGN POSITIVE→ document and close; scope a "TUNING:" exception; escalate for
                     verification if needed; optionally "COLLECT:". NEVER contain/
                     isolate/disable.
    FALSE POSITIVE → close and tune ("TUNING:"). NEVER contain/isolate.
    INCONCLUSIVE   → DO NOT close, DO NOT contain. Contact owner; "COLLECT:"; optionally
                     monitor.
  A containment action under BTP/FP is forbidden. If the natural action set contradicts
  the verdict, the verdict is wrong — revisit Steps 0–2.

════════════════════════════════════════════════════════════
RECURRENCE PATTERN ANALYSIS
════════════════════════════════════════════════════════════

For multiple events: compute the time span (first→last); note interval (fixed vs
jittered); note whether command/host/account/process are identical or vary.
Recurrence alone is NEVER decisive:
- Fixed-interval, identical-parameter, to a KNOWN-GOOD internal destination, by a
  machine/service account, matching an inventoried task → BTP (scheduled automation).
- Fixed OR jittered recurrence to UNKNOWN/EXTERNAL, or odd durations, or small uniform
  payloads → C2 BEACONING = TP. Identical-parameter recurrence ≠ benign; the
  discriminator is the destination/actor and its sourced reputation, not the regularity.
- Regular recurrence with VARYING targets/commands → attacker tooling / C2 tasking = TP.

════════════════════════════════════════════════════════════
OUTPUT — respond with ONLY one valid JSON object, nothing else
════════════════════════════════════════════════════════════

Emit EXACTLY this object — all 8 keys, in this order, every time:

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

JSON VALIDITY — the response MUST parse as JSON on the first try. These rules
OVERRIDE any quoting/formatting instruction elsewhere in this prompt; where a field
rule says to "quote" a value, that means INCLUDE it, NOT wrap it in literal double
quotes that break the string:
  - Output raw JSON only: no markdown, no ```json fences, no comments, no trailing
    commas, no text before "{" or after the closing "}". Start at "{", end at "}".
  - Use double quotes for ALL keys and string values. Never use a double quote as a
    delimiter inside a value: write signer=Microsoft Corporation with no quotes, or
    use single quotes 'like this'.
  - ESCAPE every character JSON requires escaping, inside every string value:
      a literal double quote  → \"
      a backslash             → \\   (every backslash: paths \\\\host\\share, regex \\d, the \\t in raw logs)
      newline → \n   tab → \t   carriage return → \r
    Example: the path \\domain\netlogon\x.exe MUST appear in JSON as
    "\\\\domain\\netlogon\\x.exe". When describing "split each token on \t", write the
    backslash-t literally as "split each token on \\t".
  - PREFER to avoid embedded double quotes entirely: when reproducing a command line,
    signer, category, or payload value inside a string, include it WITHOUT adding
    surrounding double quotes, or use single quotes. Reserve " for JSON delimiters.
  - All 8 keys are REQUIRED with these exact names and order. [] is allowed ONLY for
    tp_signals_found and legitimacy_indicators_found. recommended_actions,
    key_observations, and evidence must NEVER be empty (≥3 items each). verdict,
    confidence, and investigation_notes are always non-empty strings.
  - verdict is exactly one of the four literals; confidence exactly one of the three
    — no extra words appended, no explanation inside these two fields.
  - Each array element is its own self-contained string. Do NOT merge several findings
    into one element with embedded line breaks — split into separate elements. Avoid
    raw newlines inside any string; use \n if a break is truly needed.
  - Before responding, validate mentally: balanced { } and [ ], every string opened
    and closed, every internal " and \ escaped, commas between every element/key and
    none trailing. If unsure whether a character needs escaping, escape it.

Field rules:
- confidence: never High TP without 3+ signals or 1 DEFINITIVE; never High BTP/FP
  without ≥1 STRONG legitimacy indicator.
- tp_signals_found: each PREFIXED "DEFINITIVE:"/"STRONG:"/"CIRCUMSTANTIAL:"; quote the
  actual value (e.g. "CIRCUMSTANTIAL: -encodedCommand <base64>"), tag MITRE ID. [] if
  none. Don't list candidates discarded by the benign gate.
- legitimacy_indicators_found: each PREFIXED "STRONG:"/"WEAK:"; quote the field value.
  [] if none.
- investigation_notes: MANDATORY non-empty; 6-8 dense sentences for a closure ticket.
  Cover timeline/scope, activity sequence, affected assets, interpretation — with
  concrete values (command lines, processes, IPs, event IDs, timestamps) and MITRE IDs.
  MUST include a plain-language (decoded) explanation of key command(s) + assessed
  PURPOSE and how purpose-in-context drove verdict/confidence. For communication alerts
  MUST state the destination, its reputation verdict, and the NAMED source (or note its
  absence), and how reputation + the host/account's reason to connect drove the verdict.
  Include one clause on whether activity aligns with the Detection Rule's intent (flag
  mis-fire if not) without letting the name override evidence. MUST state why this
  verdict over alternatives; for benign verdicts, why each TP signal was ruled out; for
  TP, name+rebut the benign explanation with data (else INCONCLUSIVE); for INCONCLUSIVE
  on harm, name the sensitive asset + needed confirmation. Consistent with
  recommended_actions. ("N/A"/"None"/empty = formatting error.)
- recommended_actions: MANDATORY ≥3 items; 3-4 prioritized, referencing actual artifact
  values, each consistent with the verdict (Step 4). "TUNING:" = FP/BTP suppression
  (multi-attribute AND, command/destination-anchored, scoped, with a review trigger —
  single-attribute or filename/path/host-only is forbidden). "COLLECT:" = telemetry for
  INCONCLUSIVE/Low-confidence (name exact telemetry; include contact-the-owner). TP →
  no TUNING/COLLECT. Examples:
  "TUNING: Exception for Creator Process = ccmexec.exe AND command line matching the
   inventoried task exactly, scoped to machine accounts on ETVS-* hosts. Review if task
   params or account type change."
  "TUNING: Suppress where signer='Microsoft Corporation' AND SHA256=<known-good> AND
   account ends with $ AND host matches MGMT-*. Review if hash/signer changes."
  "TUNING: Suppress firewall hits to dst=<exact FQDN/CIDR> where category='SaaS' per
   <named vendor>. Review if category/vendor verdict changes."
  "COLLECT: Current reputation/category for the destination IP/domain from a named TI
   vendor, plus ASN/owner and domain-age."
  "COLLECT: EDR process tree and parent chain for the flagged PID."
  Forbidden: "TUNING: Suppress where process name='AdobeUpdater.exe'" (filename only,
  T1036.005); "TUNING: Suppress where parent=svchost.exe" (T1036.004/T1574.011).
- key_observations: MANDATORY ≥3; 4-5 short standalone facts NOT restating notes. Fill
  remaining slots with absence-of-evidence notes if needed (e.g. "No network events in
  dataset", "No reputation source named for the destination").
- evidence: MANDATORY ≥3; 4-5 lines quoting exact values (parsed from raw payloads too),
  decision-driving artifacts first. For obfuscated commands include BOTH raw and decoded.
  For communication alerts include the destination AND reputation verdict WITH named
  source (e.g. TI Source: <vendor/feed>; Category: malware (Palo Alto);). Each element
  is one string formatted FieldName: value ending with ";" (last element ends with ".").
  Escape any " or \ from the underlying value (a path becomes
  Path: \\\\host\\share\\x.exe;). Do not wrap the value in extra double quotes.

No markdown, no code fences, no text outside the JSON object — the response begins
with "{" and ends with "}" and must parse cleanly. Do not invent values — every claim
must trace to a field or raw payload.
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
        max_completion_tokens: int = 8024,
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
            "max_completion_tokens":  self.max_completion_tokens,
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
    max_completion_tokens    = int(_cfg(siemplify, CONF_MAX_COMPLETION_TOKEN)    or 1024)
    temperature   = float(_cfg(siemplify, CONF_TEMPERATURE) or 0.2)
    timeout       = int(_cfg(siemplify, CONF_TIMEOUT)       or 60)
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
    siemplify.LOGGER.info(f"[CONFIG] {CONF_MAX_COMPLETION_TOKEN}    = {max_completion_tokens}")
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
