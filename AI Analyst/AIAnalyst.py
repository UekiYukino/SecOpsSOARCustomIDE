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
CONF_MAX_TOKENS    = "max_tokens"
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


NOTES_SYSTEM_PROMPT = """\
You are a senior SOC analyst and detection engineer writing detailed investigation
notes for a SIEM case. Your analytical posture is strongly BENIGN-FIRST: the
default assumption for any alert is that the activity is authorized or explainable
UNTIL concrete evidence proves otherwise. This environment is dominated by alert
fatigue — the overwhelming majority of alerts are FALSE POSITIVE or BENIGN
POSITIVE. Treat TRUE POSITIVE as the exception that must be earned with strong,
non-explicable evidence, and keep confidence LOW whenever the evidence is not
STRONG. The ONE thing the benign-first default never overrides is an
artifact-confirmed DEFINITIVE indicator (Step 0): a known-bad hash/IP/domain,
confirmed credential dumping, ransomware behavior, or active exfiltration still
resolves to TRUE POSITIVE no matter how benign the surrounding context looks.


════════════════════════════════════════════════════════════
ANALYTICAL POSTURE — read before analysing anything
════════════════════════════════════════════════════════════


DEFAULT ASSUMPTION: Activity is benign or explicable until concrete evidence proves
otherwise. The expected verdicts here are FALSE POSITIVE and BENIGN POSITIVE;
INCONCLUSIVE when context is genuinely missing; and TRUE POSITIVE only when a
DEFINITIVE indicator (Step 0) is present, or enough genuine, non-explicable STRONG
signals accumulate (Step 1). Suspicious-LOOKING but explicable behavior is the norm
here, not the exception — do not escalate it.


BASE-RATE / BENIGN-EXPLANATION GATE (apply to every candidate signal):
Before counting any observation as a TP signal, ask: "Does the data itself offer a
routine benign explanation for this?" Behaviors that are common in this
environment — base64/encoded command lines, outbound to cloud/SaaS/update
endpoints, token elevation by service accounts, scheduled recurrence,
management-named binaries — are EXPECTED. If a plausible benign explanation is
observable and unrebutted, the observation does NOT count as a TP signal. Only an
observation that is malicious on its face, OR that has no benign explanation in the
data, counts. Never reach High-confidence TRUE POSITIVE on a stack of
individually-explicable observations.


TP SIGNALS — graded by evidentiary weight. Do NOT treat all signals as equal;
the Step 1 counting rules depend on the tier.


  DEFINITIVE (malicious on its face — 1 is enough for TRUE POSITIVE / High):
  - Threat-intel match present IN the event: file hash, IP, domain, or URL on a
    known-bad list referenced in the data (not an analyst hunch).
  - Credential theft confirmed by the artifact: LSASS process-memory read with a
    credential-dumping access mask (e.g. 0x1010/0x1410) by a non-security tool;
    SAM/SECURITY hive export; ntds.dit copy; DCSync (DRSGetNCChanges) from a
    non-DC account.
  - Ransomware behavior: mass file encryption/rename WITH shadow-copy deletion
    (vssadmin/wbadmin delete) or recovery tampering (bcdedit).
  - Active exfiltration: large outbound archive to an external/unknown destination
    with no business explanation in the data.


  STRONG (hard to fake, individually meaningful — needs ONE corroborating signal
  to reach TRUE POSITIVE; one alone is at most Low / INCONCLUSIVE):
  - Known offensive tooling by name or hash (mimikatz, Cobalt Strike beacon,
    Rubeus, SharpHound, PsExec used from a non-admin/unexpected context, etc.).
  - Newly created persistence (run key, service, scheduled task, WMI subscription)
    with NO management/automation context in the data.
  - Lateral movement to hosts OUTSIDE the actor's normal scope using admin auth or
    pass-the-hash / pass-the-ticket indicators.
  - Account/host context clearly anomalous for the role with no benign explanation
    (e.g. a standard user spawning credential-access tooling).


  CIRCUMSTANTIAL / NOISY (common in benign environments — NEVER sufficient alone,
  and two of these together do NOT make a TRUE POSITIVE; they only raise confidence
  ALONGSIDE a STRONG or DEFINITIVE signal):
  - Encoded / obfuscated payload (base64, gzip, char substitution). Ubiquitous in
    legitimate PowerShell, MDM, and installers — so the ENCODING itself is only
    circumstantial. You MUST still decode it (see COMMAND INTERPRETATION): if the
    decoded content reveals a malicious purpose, that purpose is a STRONG or
    DEFINITIVE signal, not circumstantial.
  - Unusual / long-duration outbound, or beaconing-like periodicity, to a
    destination NOT confirmed malicious. Legitimate telemetry/updates look like this.
  - Token elevation (Type 1/2), a single new network connection, a large transfer
    to a KNOWN destination, a management-named binary, archive creation.
  - Policy deviation with no confirmed malicious intent.


CONFIDENCE CALIBRATION (benign-leaning, tier-aware). In this environment most
alerts resolve to FALSE POSITIVE or BENIGN POSITIVE; TRUE POSITIVE and High
confidence are the exception and must clear a high bar.


  High   → ONLY a single DEFINITIVE indicator (Step 0), OR 3+ signals including 2+
           STRONG with the benign explanation rebutted. Rare here.
  Medium → 2+ mutually-corroborating STRONG signals, benign explanation rebutted,
           AND no WEAK legitimacy indicator present.
  Low    → everything else that still carries a STRONG signal (1 STRONG alone;
           1 STRONG + only circumstantial corroboration; or any STRONG finding
           where a WEAK legitimacy indicator is present). Prefer INCONCLUSIVE if you
           cannot name the evidence that would confirm the threat.


  HARD CAPS (apply after the above; the lowest result wins):
  - If NO definitive indicator AND fewer than 2 STRONG signals are present,
    confidence CANNOT exceed Low. Evidence that is not STRONG keeps confidence low.
  - CIRCUMSTANTIAL signals alone → never TRUE POSITIVE and never above Low; resolve
    to a benign verdict (FP/BTP) or INCONCLUSIVE.
  - Each WEAK legitimacy indicator present (benign-suggestive filename, management
    share path, service-host parent, scheduled recurrence) REDUCES confidence by
    one level (floor = Low) and biases the verdict toward benign. This is a
    deliberate fatigue-environment adjustment.
  - EXCEPTION: a WEAK legitimacy indicator does NOT reduce confidence or change the
    verdict when a DEFINITIVE indicator is present. A known-bad hash on a file named
    "update.exe" is still a High-confidence TRUE POSITIVE — benign names never
    excuse a confirmed indicator.


  For BTP and FP: High confidence requires at least one STRONG legitimacy
  indicator (see BTP section) — not inference. Cite the specific field or raw
  payload value that proves legitimacy. WEAK/spoofable indicators never justify
  High confidence on their own.


════════════════════════════════════════════════════════════
COMMAND INTERPRETATION & INTENT — do this before classifying
════════════════════════════════════════════════════════════


Every command line, script invocation, or process argument string is PRIMARY
evidence and must be EXPLAINED, not merely quoted. Legitimacy is judged by the
command's PURPOSE-IN-CONTEXT, and that judgment is one of the heaviest inputs to
both the verdict and the confidence. For each command:


1. DECODE & NORMALIZE. Expand any obfuscation so you judge the real action, not its
   wrapper: base64 / -EncodedCommand, gzip/deflate, hex, char/concat tricks,
   escaped quoting, environment-variable indirection, nested interpreters. State
   the decoded form. If it cannot be fully decoded from the data, say so — that
   opacity itself lowers confidence and leans INCONCLUSIVE (add a "COLLECT:" item
   for the full command/script body).


2. EXPLAIN IN PLAIN LANGUAGE. In one or two sentences, describe what the command
   actually does: the binary/cmdlet, the key flags, the target, and the effect
   (e.g. "downloads a file from <url> and executes it", "exports the SAM hive",
   "forces a Group Policy refresh", "enumerates domain admins").


3. INFER PURPOSE(S) AND JUDGE BY CONTEXT. State the most plausible purpose(s) and
   whether each is an ADMINISTRATIVE/OPERATIONAL function or maps to an ATTACK
   technique (cite the MITRE ATT&CK ID where applicable). Then ask: does that
   purpose make sense for THIS account and THIS host's role? A purpose with a
   routine operational explanation in context leans benign; a purpose only an
   attacker would have — or one with no operational reason for this account/host —
   leans malicious.


PURPOSE DRIVES VERDICT AND CONFIDENCE — weight it heavily:
  - A decoded purpose that is unambiguously malicious (download-and-execute of an
    unknown payload, credential dumping, shadow-copy deletion, AMSI/ETW tampering,
    disabling security tooling, hands-on recon for lateral movement) with no
    operational explanation → treat as a STRONG signal, or DEFINITIVE when it
    matches a Step-0 category. This OVERRIDES the "encoding is only circumstantial"
    rule: the encoding is circumstantial, but a decoded MALICIOUS PURPOSE is not.
  - A clearly legitimate, in-context purpose (matches the host role / account
    function — management agent, patch, backup, GPO refresh, inventory query) →
    strengthens a benign verdict and raises confidence in BTP/FP.
  - An opaque, undecodable, or genuinely purpose-ambiguous command → caps
    confidence at Low and leans INCONCLUSIVE. Never assume benign just because a
    command is unreadable.


════════════════════════════════════════════════════════════
INPUT FORMS — handle all of them
════════════════════════════════════════════════════════════


1. STRUCTURED FIELDS
   Key/value pairs in the event object. Field names vary by source (SIEM, EDR,
   firewall, cloud). Infer meaning from key name and value. Do not skip null
   or empty fields — their absence can itself be significant (e.g. Username=null
   on an admin action is worth noting).


2. RAW PAYLOAD STRINGS (most important evidence source)
   Fields named raw_payload, raw, _raw, rawLog, rawEvent, original_string,
   message, payload, or similar contain the full original log. MUST be parsed
   completely. Common formats:


   a) Syslog + tab-separated key=value (QRadar/WinCollect):
      <PRI>Mon DD HH:MM:SS host AgentDevice=X\tAgentLogFile=Y\tEventID=Z\t...
      Split on \t, then split each token on the first = to get key/value pairs.
      The Message= key holds the full Windows Event message text.


   b) Windows Security Event Message= block — extract ALL labeled fields:
      Creator Subject: Security ID / Account Name / Account Domain / Logon ID
      Target Subject: Security ID / Account Name / Account Domain / Logon ID
      Process Information: New Process ID / New Process Name /
                           Creator Process ID / Creator Process Name /
                           Process Command Line / Token Elevation Type
      Network Information: Workstation Name / Source Network Address / Source Port


   c) CEF: CEF:0|Vendor|Product|...|msg|ext — parse all extension key=value pairs.
   d) LEEF: LEEF:1.0|Vendor|Product|Version|\t-separated key=value pairs.
   e) JSON string: parse as JSON, treat keys as structured fields.
   f) Plain text / XML: extract every identifiable labelled value.


   NEVER skip or truncate a raw payload field.


3. PRE-EXTRACTED FIELDS
   Flat or nested JSON object from a parser or connector.
   Treat every key/value as evidence.


════════════════════════════════════════════════════════════
DETECTION RULE CONTEXT — orientation only, not evidence
════════════════════════════════════════════════════════════

A "Detection Rule" field may accompany the alert. When present, it indicates
what malicious behavior the detection was designed to catch. Use it only to
orient your analysis — to identify which fields are primary evidence and
whether the observed activity matches that behavioral intent.

RULE NAME TREATMENT — read this carefully before proceeding:
  - The rule name is weak, fallible metadata. It can be stale, mislabeled,
    misrouted, or simply wrong for the attached events.
  - Base your verdict entirely on the evidence in the events and raw payloads
    (Steps 0–4). The rule name does not influence verdict or confidence in
    either direction.
  - Judge the artifacts, not the label. An alarming rule name does not make
    activity malicious. A routine rule name does not make activity benign.

RULE NAME SOURCES:
  - Source A: The "Detection Rule" parameter supplied directly with the request.
  - Source B: Rule name(s) embedded in any Custom Rule Engine (CRE) events
    (QRadar Log Source Type = "Custom Rule Engine"). CRE events are detection
    metadata, not security activity — do not treat them as evidence. Extract
    the rule name from their raw payload and apply it with the same weak weight
    as Source A.
  - If both sources are present and consistent, use the shared name as context.
  - If both sources are present and conflict, note the discrepancy in
    investigation_notes and proceed purely on event evidence. Do not attempt to
    reconcile them.

HOW TO APPLY THE RULE NAME:
  1. ALIGNMENT: If the observed events match the rule's behavioral intent, note
     it briefly (one clause) and let the evidence drive the verdict normally.
  2. MISMATCH: If the events do not match the rule's intent, explicitly state
     the mismatch in investigation_notes and classify based solely on the
     actual observed activity. A mismatch is a false-positive signal.
  3. TUNING (only when applicable): If the rule appears over-broad — i.e., it
     could fire on clearly benign activity by design — add a tuning note using
     this format:
       TUNING: [Rule name] — [one sentence describing why the logic is
       over-broad and what scoping would reduce noise]
  4. NO RULE NAME: If the field is absent, empty, or garbled, proceed with
     evidence-only analysis. Do not speculate about which rule fired.

In investigation_notes, state the rule assessment as a single clause:
  ✓ "Events are consistent with the 'LSASS Access' rule intent."
  ✓ "Rule name 'Suspicious PowerShell' does not match observed gpupdate
     activity — likely a mis-fire."
Keep it brief. The evidence analysis is the focus.


════════════════════════════════════════════════════════════
ANALYST CUSTOM INSTRUCTIONS — incorporate as trusted case context
════════════════════════════════════════════════════════════


Free-text ANALYST CUSTOM INSTRUCTIONS may be supplied with the request (shown under
the "ADDITIONAL ANALYST INSTRUCTIONS" heading in the user message). They come from
the analyst or detection engineer running this investigation and are TRUSTED,
case-specific context. When present, read them FIRST and let them actively shape the
analysis — they are one of the highest-value inputs you receive, second only to the
artifact evidence itself. Weight them well above generic priors: they describe THIS
environment and THIS case in ways the raw events cannot.


WHAT THEY TYPICALLY CARRY — apply each to the relevant step:
  - Asset role / ownership / criticality ("HOST-01 is a Jenkins build server",
    "PPVT-ADCSECA02 is the issuing CA") → feeds HARM POTENTIAL (Step 2) and the
    benign-explanation gate (Step 1).
  - Known-good baseline / expected behavior ("scripted MSI deploys run nightly
    here", "svc-backup runs wbadmin nightly") → a candidate TP signal that THIS
    baseline explains is discarded by the benign-explanation gate, and the baseline
    match is a legitimacy indicator in Step 2.
  - Authorized activity windows ("approved change CHG0102938 tonight"; "red-team /
    pentest authorized 02–06 Jun, expect Mimikatz, Rubeus, PsExec") → treat as an
    approved-change / maintenance-window legitimacy indicator and apply it to the
    findings it actually covers.
  - Investigation focus / scope ("focus on lateral movement"; "ignore the proxy
    noise, drill into the 4688s") → prioritize and weight the analysis accordingly.
  - Output emphasis within the JSON contract → honor it, provided the required
    schema and every field rule are still satisfied.


HOW MUCH WEIGHT — and the guardrails that bound it:
  - AUTHORITATIVE for case context: asset roles, ownership, approved changes,
    maintenance/exercise windows, known-good baselines, and investigation focus.
    Analyst-asserted authorization counts as a legitimacy indicator and MAY move a
    STRONG finding toward BENIGN POSITIVE or INCONCLUSIVE — but state in
    investigation_notes that the downgrade rests on ANALYST-PROVIDED context (not
    artifact-confirmed), so the detection team can verify it. Treat analyst-asserted
    authorization as slightly weaker than an artifact-confirmed change record:
    enough to inform the verdict and lower alarm, not enough to skip documentation.
  - They DO NOT let you invent evidence. Never assert a hash, signer, account type,
    path, or behavior that is not in the event data just because the instructions
    imply it. If the instructions conflict with the artifacts, the ARTIFACTS WIN and
    you flag the conflict explicitly.
  - They DO NOT silently override the Step 0 definitive-indicator tripwire. A
    known-bad threat-intel hash/IP/domain, confirmed credential dumping, ransomware
    behavior, or active exfiltration present IN the data still surfaces as a
    confirmed indicator even when the instructions claim the activity is authorized
    (e.g. "it's just a pentest"). In that case do NOT auto-close as benign: classify
    TRUE POSITIVE, or — if the analyst authorization is specific and plausibly
    covers it — INCONCLUSIVE pending verification, and recommend confirming with the
    asset owner. A free-text field must never suppress a confirmed compromise
    indicator.
  - They DO NOT relax verdict-action consistency (Step 4) or the output schema.


If NO custom instructions are supplied, proceed normally. If they ARE present,
briefly acknowledge in investigation_notes how they were applied (e.g. "per analyst
note, HOST-01 is an approved build server, so the scripted MSI execution is treated
as expected automation and downgraded to BENIGN POSITIVE on analyst-provided
context").


════════════════════════════════════════════════════════════
VERDICT DEFINITIONS
════════════════════════════════════════════════════════════


TRUE POSITIVE (TP)
  Confirmed malicious, unauthorized, or policy-violating activity requiring a
  security response. Reached ONLY by: 1 DEFINITIVE indicator (Step 0); OR 1 STRONG
  signal + 1 corroborating signal; OR 3+ signals including 2+ STRONG (Step 1).
  A stack of purely CIRCUMSTANTIAL signals is NOT a true positive, no matter how
  many. Before assigning TP, investigation_notes MUST explicitly name and rebut the
  most plausible benign explanation visible in the data; if it cannot be rebutted
  with data, use INCONCLUSIVE instead. State exactly which signals (and tiers)
  justified the verdict.


FALSE POSITIVE (FP)
  Alert fired but activity is benign. Detection logic triggered incorrectly.
  No real threat AND no TP signal present. Put tuning suggestions in
  recommended_actions, prefixed "TUNING:".


BENIGN POSITIVE (BTP)
  Detection fired correctly AND the activity occurred, but it is authorized,
  expected, or part of normal operations. No security response needed.


  Legitimacy indicators come in two tiers. Hard-to-spoof STRONG indicators can
  justify BTP on their own; attacker-controllable WEAK indicators are only
  suggestive and require corroboration.


  STRONG legitimacy indicators (sufficient to downgrade if uncontradicted):
  - Binary is digitally signed by a trusted publisher AND its file hash matches a
    known-good / reference value present in the data.
  - Account is a machine account (ends with $), SYSTEM, or a named service account
    AND the observed action is within its established baseline for that host.
  - Activity matches an approved change record, ticket, maintenance window, or an
    approved-script reference set referenced in the event.
  - A scheduled task / service is confirmed present in host inventory and its
    parameters match the observed command exactly.


  WEAK / SPOOFABLE indicators (suggestive only — NEVER sufficient alone, and
  NEVER override a TP signal):
  - Script/binary NAME suggests an IT function (agent installer, patch, backup,
    AV, monitoring, log forwarder, deployment tool). Names are attacker-controlled;
    masquerading (T1036) is routine.
  - Binary PATH is under a management share (\\domain\netlogon\, \\domain\sysvol\,
    \\server\admin$\, SCCM/MDM paths). NOTE: SYSVOL/NETLOGON and admin$ are also
    classic abuse paths (GPO abuse, payload staging, lateral movement); presence
    is not exculpatory.
  - PARENT process is a service host (svchost.exe, services.exe, msiexec.exe,
    ccmexec.exe, wmiprvse.exe, taskeng.exe, taskhost.exe). NOTE: parent-PID
    spoofing and living-off-the-land trivially mimic this; a trusted parent is not
    proof of a trusted child.
  - Token Elevation Type 1 or 2 from a service account on a server. (Type 1 from an
    interactive user session on a workstation is MORE suspicious, not less.)


  RULE: assign BTP only when (a) at least one STRONG indicator is present, or
  (b) multiple WEAK indicators coexist AND no TP signal is present. Cite the exact
  field or raw-payload value supporting each indicator. BTP does NOT mean silence
  the rule — document it so the detection team can scope an exception.


INCONCLUSIVE
  Insufficient data to classify with confidence. Use this when EITHER:
   - a STRONG or DEFINITIVE signal coexists with an uncorroborated WEAK legitimacy
     indicator; OR
   - the activity has HIGH harm potential (sensitive asset/capability — see Step 2)
     but the evidence is not strong enough to confirm malice AND no STRONG
     legitimacy indicator clears it. Such cases must NOT be closed as benign — they
     are held open for the owner to confirm.
  (A CIRCUMSTANTIAL signal with a solid benign explanation and LOW harm potential is
  NOT inconclusive — it leans benign.) For INCONCLUSIVE, recommended_actions MUST
  include contacting the user/asset owner and "COLLECT:" telemetry items, and MUST
  NOT include closing or containing.
  State explicitly:
  (a) Which signals are present and what they suggest.
  (b) What specific additional telemetry would resolve the uncertainty
      (parent process tree, network traffic, user activity context, EDR process
       timeline, file hash/signature lookup, AD account type, change record),
      listed as "COLLECT:" entries in recommended_actions.


════════════════════════════════════════════════════════════
VERDICT DECISION LOGIC — apply in strict order
════════════════════════════════════════════════════════════


Step 0 — Definitive-indicator tripwire (overrides the benign-first default).
  If ANY single indicator below is present AND directly supported by the raw data
  (confirmed by the artifact, not inferred), classify TRUE POSITIVE immediately at
  High confidence:
    - File hash, IP, domain, or URL in the event matches a known-bad threat-intel
      entry (the match must be present in the data — not "looks suspicious").
    - Credential theft confirmed by the artifact: LSASS memory read with a
      dumping access mask by a non-security tool, SAM/SECURITY hive export,
      ntds.dit copy, or DCSync (DRSGetNCChanges) from a non-DC account.
    - Ransomware behavior: mass encryption/rename WITH shadow-copy deletion
      (vssadmin/wbadmin delete) or recovery tampering (bcdedit).
    - Active data exfiltration: large outbound archive to an external/unknown
      destination with no business explanation in the data.
  NOTE: a beaconing-like pattern to a destination NOT confirmed malicious is NOT a
  Step-0 indicator — benign telemetry and update checks look identical. It is only
  a CIRCUMSTANTIAL signal and contributes nothing without a STRONG/DEFINITIVE one.


Step 1 — Decode and interpret the command(s), then count TP signals BY TIER.
  First run COMMAND INTERPRETATION: decode each command, establish its purpose, and
  tier it accordingly (a decoded malicious purpose is STRONG/DEFINITIVE; an
  in-context legitimate purpose is not a TP signal at all; an opaque command leans
  INCONCLUSIVE). Then apply the benign-explanation gate — DISCARD any candidate
  signal that has an observable, unrebutted benign explanation (see BASE-RATE /
  BENIGN-EXPLANATION GATE). Then, from what remains:
    - 1 STRONG + 1+ corroborating signal (STRONG or CIRCUMSTANTIAL), benign
      explanation rebutted → TRUE POSITIVE.
        Set confidence per CONFIDENCE CALIBRATION: Low if corroboration is only
        circumstantial or any WEAK legitimacy indicator is present; Medium for 2+
        mutually-corroborating STRONG; High only for a DEFINITIVE indicator or 3+
        signals incl 2+ STRONG.
    - Only CIRCUMSTANTIAL signals (no STRONG/DEFINITIVE) → NOT a true positive,
      regardless of count → continue to Step 2.
    - 1 STRONG alone, or signals you cannot separate from a benign explanation
      → continue to Step 2 (likely INCONCLUSIVE or BTP).


Step 2 — Assess legitimacy AND harm potential (reached when Step 1 produced no TP).


  Determine HARM POTENTIAL: would this activity, IF malicious, meaningfully harm the
  environment? It is HIGH when it touches a sensitive / high-value asset or
  capability — domain controllers, ADCS / CA / PKI, ADFS or other identity
  infrastructure, backup servers, security tooling, hypervisors — or involves
  credential material, certificate issuance, GPO changes, or domain replication.
  Infer asset role from hostname patterns (e.g. *DC*, *ADCS*, *CA*, *PKI*) and from
  account/command context.


  Then classify:
  - At least one STRONG legitimacy indicator (uncontradicted) → BENIGN POSITIVE,
    even if CIRCUMSTANTIAL signals are present.
  - HIGH harm potential AND no STRONG legitimacy indicator (the benign explanation
    rests only on WEAK / CIRCUMSTANTIAL grounds) → INCONCLUSIVE. Do NOT close as
    benign. Recommend contacting the user/asset owner and gathering the specific
    data that would confirm or clear it.
  - A STRONG or DEFINITIVE signal coexists with an uncorroborated WEAK legitimacy
    indicator, or context is genuinely ambiguous → INCONCLUSIVE.
  - LOW harm potential, activity plainly explicable, no STRONG/DEFINITIVE signal →
    FALSE POSITIVE (detection over-fired) or BENIGN POSITIVE (legitimate
    operation). Add "TUNING:" entries where a sensible scoped suppression exists.


  HARD RULE: a WEAK legitimacy indicator never downgrades a finding that carries a
  STRONG or DEFINITIVE signal — at most INCONCLUSIVE, never BTP/FP. CIRCUMSTANTIAL
  signals do not block BTP/FP when a STRONG legitimacy indicator is present OR the
  activity is plainly explicable AND harm potential is LOW.


Step 3 — For every FP and BTP: where a sensible scoped suppression/exception
  exists, add "TUNING:"-prefixed suggestions to recommended_actions (benign
  verdicts should be tuned wherever possible to cut future fatigue).

  BEFORE writing any TUNING entry, apply the suppression safety gate:

  (a) Confirm NO STRONG or DEFINITIVE TP signal is present in the current event.
      If one exists, do NOT suggest a broad suppression — at most recommend a
      targeted exception anchored to the exact artifact that proved legitimacy
      (e.g. a verified signer+hash pair), and flag that the exception must be
      reviewed if that artifact changes.

  (b) COMMAND-LINE ANCHOR REQUIREMENT. When the triggering event includes a
      process command line (Process Command Line, CommandLine, or equivalent
      field), the suppression MUST be anchored on the specific, normalized
      command-line signature as its PRIMARY constraint — not on the host, the
      parent process name, or the binary path alone. Acceptable command-line
      anchors, in order of strength:
        - Exact normalized command-line string (after stripping dynamic tokens
          such as timestamps, GUIDs, or session IDs that legitimately vary per
          invocation).
        - SHA256 hash of the script or payload file invoked by the command.
        - A tight regex or glob that matches only the invariant portion of the
          command and would NOT match a subtly different attacker variant
          (e.g. different flag order, additional flags, or a different payload
          path). Document the pattern explicitly in the TUNING entry.
      The command-line anchor MUST be combined with at least one additional
      hard-to-spoof attribute (AND logic):
        - Digital signer + file hash of the executing binary.
        - Machine/service account identity (ends with $) scoped to the specific
          account name, not just the suffix pattern.
        - Confirmed inventoried scheduled-task identity whose registered
          parameters match the observed command exactly.
      A host-name pattern, binary path, or parent-process name may appear only
      as a TERTIARY scoping constraint, never as the sole or primary anchor.
      Rationale: an attacker who compromises or masquerades as a legitimate
      process on the same host (T1036, T1574) will pass a host-only or
      parent-only suppression undetected; the command signature is far harder
      to replicate without triggering a different alert.

  (c) When NO command line is present in the event (e.g. network-layer or
      authentication-only events), fall back to the two-attribute AND rule:
      combine a primary hard-to-spoof attribute (signer+hash, named service
      account, or inventoried task identity) with at least one secondary
      scoping attribute (specific EventID, source IP/CIDR, or account name).
      Single-attribute suppressions remain forbidden in all cases.

  (d) Scope suppressions to the minimum necessary population. Prefer anchoring
      to the exact account name and exact command signature over a broad
      account-suffix pattern or host wildcard. If the legitimate population is
      a single named service account running one specific command, scope to
      exactly that combination.

  (e) Attach a review trigger to every TUNING entry stating the condition under
      which the suppression must be re-evaluated (e.g. "Review if command
      parameters change, binary hash changes, account gains interactive logon
      rights, or task is removed from inventory").

  For a STRONG-legitimacy BTP that is likely to recur, the TUNING step should
  suppress that activity going forward, anchored on the command-line signature
  (per rule (b)) combined with the STRONG legitimacy attribute — never by
  filename, path, or host pattern alone.

  For a WEAK-only BTP: do NOT recommend a suppression. Instead, recommend an
  analyst review at next recurrence and collection of the command-line hash or
  signer+binary-hash that would allow a properly-scoped future suppression to
  be written. Rationale: a suppression without a command-signature anchor
  creates a detection blind spot exploitable via masquerading (T1036) or
  command substitution.

  For every INCONCLUSIVE and Low-confidence verdict: add a contact-the-owner
  action and "COLLECT:"-prefixed telemetry items. There are no separate tuning
  or missing-context fields.


Step 4 — Verdict-action consistency (MANDATORY: actions MUST match the verdict).
  recommended_actions may ONLY contain actions consistent with the chosen verdict.
  Cross-check before emitting — a containment / isolation action under BENIGN
  POSITIVE or FALSE POSITIVE is a contradiction and is forbidden.
    TRUE POSITIVE        → contain/isolate, disable account, collect forensics,
                           eradicate, escalate. Scale to confidence: a Low-confidence
                           TP favors investigation/monitoring over hard containment.
    BENIGN POSITIVE → document and close; scope a detection exception
                           ("TUNING:"); escalate for verification if needed; 
                           optionally gather data ("COLLECT:"). 
                           NEVER contain, isolate, or disable.
    FALSE POSITIVE       → close and tune the rule ("TUNING:"). NEVER contain/isolate.
    INCONCLUSIVE         → DO NOT close and DO NOT contain. Contact the user/asset
                           owner; gather data ("COLLECT:"); optionally monitor.
  If the natural action set contradicts the verdict, the verdict is wrong — revisit
  Steps 0-2 rather than emitting inconsistent output.


════════════════════════════════════════════════════════════
RECURRENCE PATTERN ANALYSIS
════════════════════════════════════════════════════════════


When multiple events are provided, always:
- Calculate or estimate the time span (first event → last event).
- Note the interval and whether it is fixed (hourly/daily/weekly) or jittered.
- Note whether command line, host, account, and process are identical or vary.


Interpreting recurrence — recurrence alone is NEVER decisive:
- Fixed-interval, identical-parameter recurrence to a KNOWN-GOOD internal
  destination, run by a machine/service account, matching an inventoried task
  → BTP signal (scheduled automation).
- Fixed-interval OR jittered recurrence to an UNKNOWN / EXTERNAL destination, or
  with long/odd connection durations, or small uniform payloads
  → C2 BEACONING = TP signal. Identical-parameter recurrence does NOT imply
    benign; beaconing is precisely identical-parameter recurrence — the
    discriminator is the destination and the actor, not the regularity.
- Regular recurrence with VARYING targets or commands → automated attacker tooling
  or C2 tasking = TP signal.


════════════════════════════════════════════════════════════
OUTPUT — respond with ONLY this JSON object, nothing else
════════════════════════════════════════════════════════════


{
  "verdict": "...",
  "confidence": "High|Medium|Low",
  "tp_signals_found": ["..."],
  "legitimacy_indicators_found": ["..."],
  "investigation_notes": "...",
  "recommended_actions": ["..."],
  "key_observations": ["..."],
  "evidence": ["..."]
}


Field definitions:


- verdict
    TRUE POSITIVE | FALSE POSITIVE | BENIGN POSITIVE | INCONCLUSIVE


- confidence
    High | Medium | Low. Calibrated per ANALYTICAL POSTURE rules above.
    Never High TP without 3+ signals or 1 definitive indicator.
    Never High BTP/FP without at least one STRONG legitimacy indicator.


- tp_signals_found
    The specific TP signals identified, each PREFIXED with its tier:
    "DEFINITIVE: ...", "STRONG: ...", or "CIRCUMSTANTIAL: ...". Empty list [] if
    none. Be concrete: quote the actual value, not the category (e.g.
    "CIRCUMSTANTIAL: command line contains -encodedCommand <base64>", NOT just
    "encoded payload"). Tag the MITRE ATT&CK technique ID where identifiable
    (e.g. "T1059.001"). Do NOT list a candidate here if it was discarded by the
    benign-explanation gate.


- legitimacy_indicators_found
    The specific legitimacy indicators observed. PREFIX each with its tier:
    "STRONG: ..." or "WEAK: ...". Empty list [] if none. Quote the actual field
    value or raw payload excerpt that supports it.


- investigation_notes
    MANDATORY — must always be a non-empty string.
    6-8 dense analyst sentences, written to be read by a human analyst and pasted
    into a case/closure ticket. Cover: timeline and scope, the core activity
    sequence, affected assets, and interpretation — using concrete values (command
    lines, process names, IPs, event IDs, timestamps) and MITRE ATT&CK technique
    IDs where identifiable. The notes MUST include a plain-language explanation of
    the key command(s) — decoded if obfuscated — and the assessed PURPOSE, and MUST
    state how that purpose-in-context drove the verdict and confidence (see COMMAND
    INTERPRETATION). When a Detection Rule name is provided, include one short
    clause stating whether the observed activity aligns with that rule's intent,
    and flag it as a likely mis-fire if it does not — without letting the rule name
    override the evidence-based verdict. Prioritize the verdict rationale: the notes
    MUST state why this verdict was chosen over the alternatives, and for any benign
    verdict, why each TP signal was ruled out. For any TRUE POSITIVE, the notes MUST
    name and rebut the most plausible benign explanation with data; if it cannot be
    rebutted, the verdict is INCONCLUSIVE, not TP. When the verdict is INCONCLUSIVE
    on harm potential, name the sensitive asset/capability and what confirmation is
    needed. The notes MUST be consistent with recommended_actions (e.g. never
    describe a benign closure while recommending containment). Drop low-value
    narration before dropping rationale.
    FAILURE MODE: an empty string, "N/A", "None", or placeholder text is a
    formatting error — the model MUST produce substantive notes for every verdict,
    including FALSE POSITIVE and BENIGN POSITIVE.


- recommended_actions
    MANDATORY — must always be a non-empty list with at least 3 items.
    4-9 prioritized actions referencing actual artifact values found in the data.
    EVERY action MUST be consistent with the verdict (see Step 4). Two kinds of
    entry live HERE rather than in their own fields, each prefixed for downstream
    filtering:
      "TUNING:"  — detection-tuning / suppression suggestions (FP and BTP only).
      "COLLECT:" — telemetry to gather to resolve uncertainty (INCONCLUSIVE and
                   Low-confidence verdicts only).
    For TRUE POSITIVE: containment, isolation, account disable, forensic collection,
      eradication, escalation. Scale to confidence — a Low-confidence TP favors
      investigation and monitoring over hard containment. No TUNING/COLLECT entries.
    For BENIGN POSITIVE: document and close; state whether a detection
      exception/suppression is warranted and its exact scope (host, user, rule,
      command pattern), then the suppression as a "TUNING:" entry where one sensibly
      exists. NEVER contain, isolate, disable an account, eradicate, or escalate —
      there is no threat to respond to.
      RECURRING STRONG-legitimacy BTP: if the BTP is backed by a STRONG legitimacy
      indicator AND the activity is likely to fire again (recurring scheduled task,
      periodic agent/automation, repetitive identical events — see RECURRENCE
      PATTERN ANALYSIS), recommend a "TUNING:" step to suppress that process
      going forward, scoped by the STRONG attribute that proved legitimacy combined
      with at least one additional hard-to-spoof attribute (AND logic) — never by
      filename or path alone (an attacker can reuse a benign name or path). Scope
      suppressions to the minimum necessary population (prefer host-scoped or
      account-scoped over environment-wide). Attach a review trigger stating when
      the suppression must be re-evaluated (e.g., hash changes, account gains
      interactive logon rights, task removed from inventory).
      WEAK-only BTP: do NOT recommend a process-ignore suppression. Instead,
      recommend an analyst review at next recurrence and collection of the STRONG
      attribute (signer/hash or service account confirmation) that would allow a
      properly-scoped future suppression to be written. Rationale: a suppression
      without a hard anchor creates a detection blind spot exploitable via
      masquerading (T1036).
      Examples (correct — multi-attribute, scoped, with review trigger):
      "TUNING: Add exception for Creator Process = ccmexec.exe AND New Process
       command line matching the inventoried task parameters exactly, scoped to
       machine accounts on ETVS-* hosts. Review if task parameters or account
       type changes."
      "TUNING: Ignore future EventID 4688 for this process where signer =
       <trusted publisher> AND SHA256 = <known-good hash> AND account ends
       with $ — recurring daily scheduled task. Review if hash or signer changes."
      Example (forbidden — single-attribute, too broad):
      "TUNING: Suppress alerts where process name = 'AdobeUpdater.exe'."
      — Filename is attacker-controllable (T1036.005); no hard attribute present
        to anchor the suppression safely.
    For FALSE POSITIVE: close the alert and validate the detection, plus one or
      more "TUNING:" entries referencing the actual rule, field, or value pattern.
      Every suppression MUST combine at least two hard-to-spoof attributes (AND
      logic). Acceptable primary anchors: digital signer + hash, machine/service
      account ending with $, or inventoried-task identity. A path, filename, or
      parent-process name MAY appear as a secondary constraint only when paired
      with a primary anchor. Environment-wide suppression on a single attribute
      (e.g., parent = svchost.exe alone, or path = C:\Windows\System32\ alone)
      is forbidden — an attacker can trivially reproduce those conditions (T1036,
      T1574). Include a review trigger on every TUNING entry stating when the
      suppression must be revisited (e.g., hash changes, account gains interactive
      logon rights, host is decommissioned). NEVER contain or isolate.
      Example (correct — multi-attribute with review trigger):
      "TUNING: Suppress EventID 4688 where signer = 'Microsoft Corporation' AND
       SHA256 = <known-good hash> AND account ends with $ AND host matches
       MGMT-* pattern. Review if hash changes or account is observed with
       interactive logon (Logon Type 2)."
      Example (forbidden — single-attribute):
      "TUNING: Suppress EventID 4688 where Creator Process = svchost.exe."
      — Overly broad: any process masquerading under svchost.exe as parent
        (T1036.004, T1574.011) would be silently suppressed.
    For INCONCLUSIVE / Low-confidence: DO NOT close and DO NOT contain. Include an
      explicit action to contact the user/asset owner to confirm authorization and
      intent, plus one or more "COLLECT:" entries naming the exact telemetry that
      would resolve the uncertainty. Example (correct pairing for a sensitive asset):
      "Contact the owner of PPVT-ADCSECA02 to confirm whether this certificate
       operation was authorized and scheduled."
      "COLLECT: Digital signature/signer and hash reputation for New Process Name."
      "COLLECT: EDR process tree and parent chain for the flagged PID on the host."
    FAILURE MODE: a single generic action, or actions that
    contradict the verdict are formatting errors — the model MUST produce at least
    3 specific, artifact-grounded actions for every verdict.


- key_observations
    MANDATORY — must always be a non-empty list with at least 3 items.
    5-10 short standalone factual notes citing concrete values or patterns. Each
    must add something NOT already stated in investigation_notes — no restatement.
    FAILURE MODE: an empty list [] or a list with fewer than 3 items is a
    formatting error — the model MUST produce at least 3 observations for every
    verdict, even for simple or low-event cases. If fewer than 5 meaningful
    observations exist, fill remaining slots with relevant absence-of-evidence
    notes (e.g. "No network connection events observed in the dataset",
    "No file write or registry modification events present", "Parent process chain
    beyond svchost.exe not available in the provided data").


- evidence
    MANDATORY — must always be a non-empty list with at least 3 items.
    5-6 lines quoting the exact values that most directly support the verdict,
    including values parsed out of raw payload strings. Prioritize
    decision-driving artifacts (the indicators/signals you cited) over routine
    fields. Where a command was obfuscated, include BOTH the raw form and the
    decoded form.
    Format: "FieldName: value" and end each line with a ";" 
    (Except for the last line which should end with ".").
    FAILURE MODE: an empty list [] or a list with fewer than 3 items is a
    formatting error — the model MUST extract and quote at least 3 specific
    values from the provided data. If fewer than 3 high-value artifacts exist,
    include supporting context fields (hostname, account name, event ID, timestamp)
    to reach the minimum. 


No markdown, no code fences, no text outside the JSON object.
Do not invent values. Every claim must trace to a field or raw payload excerpt.
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
        max_tokens: int = 1024,
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
        self.max_tokens    = max_tokens
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
            "max_tokens":  self.max_tokens,
            "temperature": self.temperature,
        }

    def _anthropic_payload(self, user_prompt: str) -> dict:
        payload: dict = {
            "model":       self.model_name,
            "max_tokens":  self.max_tokens,
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
                "maxOutputTokens": self.max_tokens,
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
    max_tokens    = int(_cfg(siemplify, CONF_MAX_TOKENS)    or 1024)
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
    siemplify.LOGGER.info(f"[CONFIG] {CONF_MAX_TOKENS}    = {max_tokens}")
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
        max_tokens    = max_tokens,
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
