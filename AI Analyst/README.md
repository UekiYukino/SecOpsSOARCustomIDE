***

## Overview

**Action name:** `Create AI Investigation Notes`  
**Integration name:** `AIModelQuery`  
**Supported AI providers:** `openai` · `anthropic` · `gemini` · `azure`

A custom Google SecOps (Chronicle SOAR) action that submits security event data to an AI provider (OpenAI, Anthropic, Gemini, or Azure OpenAI) and returns structured investigation notes for case enrichment and closure tickets.

The action accepts a JSON blob of security events (raw SIEM events, pre-extracted fields, or wrapped event arrays), builds an analysis prompt, and returns a structured JSON result containing a verdict, confidence level, investigation notes, key observations, evidence items, and recommended actions.

***

## Prerequisites

Before deploying the integration, ensure the following are in place:

- Access to the **Google SecOps (Chronicle SOAR)** IDE with permission to create integrations and actions.
- A valid **API key** for at least one of the supported AI providers.
- Outbound HTTPS access from the SOAR engine to the AI provider endpoint (port 443). Confirm with your network/firewall team if the SOAR node runs in an air-gapped or restricted environment.
- Python 3.8+ runtime available on the SOAR engine (standard for Chronicle SOAR deployments).
- The `requests` library available in the SOAR Python environment (it is included by default in Chronicle SOAR).

***

## Integration Setup

### Step 1 — Create the Integration in the SOAR IDE

1. Log in to the **Chronicle SOAR** console.
2. Navigate to **Response → Integrations**.
3. Click **New Integration** (or select an existing custom integration to extend).
4. Set the **Integration Name** to exactly: `AIModelQuery`  
   *(This value is hard-coded in the action script as `INTEGRATION_NAME` and must match exactly.)*
5. Save the integration shell before adding parameters.

***

### Step 2 — Add Integration Configuration Parameters

In the integration editor, add the following configuration parameters. The **Parameter Name** values must match exactly as listed — they map directly to the constants defined in the script.

| Parameter Name    | Display Label        | Type     | Required | Description |
|-------------------|----------------------|----------|----------|-------------|
| `api_endpoint`    | API Endpoint         | String   | Yes      | Full HTTPS URL of the AI provider inference endpoint (see provider-specific values below). |
| `api_key`         | API Key              | Password | Yes      | API key or secret token for authenticating with the AI provider. Stored as a credential. |
| `model_name`      | Model Name           | String   | Yes      | The model identifier to use for inference (e.g., `gpt-4o`, `claude-3-5-sonnet-20241022`). |
| `provider`        | Provider             | String   | Yes      | One of: `openai`, `anthropic`, `gemini`, `azure`. Must be lowercase. |
| `system_prompt`   | System Prompt        | String   | No       | Optional override for the built-in investigation system prompt. Leave blank to use the built-in prompt. |
| `max_tokens`      | Max Tokens           | Integer  | No       | Maximum tokens to generate in the response. Default: `1024`. |
| `temperature`     | Temperature          | Float    | No       | Sampling temperature. Default: `0.2`. Lower values produce more deterministic output. |
| `request_timeout` | Request Timeout (s)  | Integer  | No       | HTTP request timeout in seconds. Default: `60`. |
| `api_version`     | API Version          | String   | No       | Required for Azure OpenAI only (e.g., `2024-02-01`). Leave blank for all other providers. |

***

### Step 3 — Provider-Specific Endpoint & Model Values

Configure `api_endpoint`, `model_name`, and `provider` according to your chosen AI provider:

#### OpenAI

| Parameter      | Value |
|----------------|-------|
| `provider`     | `openai` |
| `api_endpoint` | `https://api.openai.com/v1/chat/completions` |
| `model_name`   | e.g., `gpt-4o`, `gpt-4-turbo`, `gpt-4o-mini` |
| `api_key`      | Your OpenAI API key (`sk-...`) |
| `api_version`  | *(leave blank)* |

#### Anthropic (Claude)

| Parameter      | Value |
|----------------|-------|
| `provider`     | `anthropic` |
| `api_endpoint` | `https://api.anthropic.com/v1/messages` |
| `model_name`   | e.g., `claude-3-5-sonnet-20241022`, `claude-3-haiku-20240307` |
| `api_key`      | Your Anthropic API key |
| `api_version`  | *(leave blank — the script sets the `anthropic-version` header automatically to `2023-06-01`)* |

#### Google Gemini

| Parameter      | Value |
|----------------|-------|
| `provider`     | `gemini` |
| `api_endpoint` | `https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent` — replace `{model}` with your model ID, e.g., `gemini-1.5-pro-latest` |
| `model_name`   | e.g., `gemini-1.5-pro-latest`, `gemini-1.5-flash` |
| `api_key`      | Your Google AI Studio API key (passed as a `key` query parameter automatically) |
| `api_version`  | *(leave blank)* |

> **Note:** For Gemini, embed the model name directly in the `api_endpoint` URL. The `model_name` field is used for logging purposes only with this provider.

#### Azure OpenAI

| Parameter      | Value |
|----------------|-------|
| `provider`     | `azure` |
| `api_endpoint` | `https://{your-resource}.openai.azure.com/openai/deployments/{deployment-name}/chat/completions` |
| `model_name`   | Your Azure deployment name (e.g., `gpt-4o-deployment`) |
| `api_key`      | Your Azure OpenAI API key |
| `api_version`  | e.g., `2024-02-01` |

***

### Step 4 — Add the Action Script

1. Inside the `AIModelQuery` integration, navigate to the **Actions** tab.
2. Click **New Action**.
3. Set the **Action Name** to: `Create AI Investigation Notes`
4. Paste the full Python script into the **Script** editor.
5. Add the following **Action Parameters** (these are the per-run inputs the action reads at execution time):

| Parameter Name         | Display Label           | Type    | Required | Description |
|------------------------|-------------------------|---------|----------|-------------|
| `events_json`          | Events JSON             | String  | Yes      | JSON string containing security events. Accepts an array of event objects, a wrapped object (`{"events": [...]}`) or a flat pre-extracted fields object. |
| `rule_name`            | Rule Name               | String  | No       | Detection rule name that triggered the alert. Used as a weak analysis hint; does not override event evidence. |
| `custom_instructions`  | Custom Instructions     | String  | No       | Free-text analyst instructions providing case-specific context (e.g., asset roles, known-benign activity, investigation focus). Treated as trusted input second only to artifact evidence. |

6. Save the action.

***

### Step 5 — Test the Integration

1. From the integration editor, click **Test** (or run the action from a test case in the SOAR console).
2. Supply a minimal `events_json` value — a simple JSON array works:
   ```json
   [{"src_ip": "192.168.1.10", "dst_ip": "10.0.0.1", "action": "ALLOW", "bytes": 1500}]
   ```
3. Verify the action returns a result JSON with the following keys: `verdict`, `confidence`, `investigation_notes`, `recommended_actions`, `key_observations`, `evidence`, `model`, `provider`, `usage`, `event_count`, `input_mode`.
4. Check the action logs for `[CONFIG]` lines confirming all parameters were read correctly and `[AI] OK` confirming a successful round-trip to the provider.

***

## Action Output Schema

On success, the action sets a result JSON with the following structure:

```json
{
  "verdict":             "BENIGN | SUSPICIOUS | MALICIOUS | INCONCLUSIVE",
  "confidence":          "Low | Medium | High",
  "investigation_notes": "Full narrative investigation notes...",
  "recommended_actions": ["Action 1", "Action 2"],
  "key_observations":    ["Observation 1", "Observation 2"],
  "evidence":            ["Evidence item 1", "Evidence item 2"],
  "model":               "gpt-4o",
  "provider":            "openai",
  "usage":               { "prompt_tokens": 800, "completion_tokens": 400 },
  "event_count":         5,
  "input_mode":          "events_array"
}
```

***

## Accepted `events_json` Formats

The action auto-detects the input structure. All of the following are valid:

```json
// Array of event objects (most common — direct SIEM export)
[{"src_ip": "...", "dst_ip": "...", "raw": "..."}, {...}]

// Wrapped object with a known events key
{"events": [{...}, {...}]}
{"securityEvents": [{...}]}
{"alerts": [{...}]}

// Pre-extracted fields object (single event, flat key-value)
{"src_ip": "10.0.0.1", "username": "jdoe", "event_id": "4688"}
```

***

## QRadar Custom Rule Engine (CRE) Events

If the event dataset contains QRadar **Custom Rule Engine** events (identified by `Log Source Type = Custom Rule Engine`), the action automatically separates them from evidence events. CRE events are treated as detection metadata (rule name hints) only — they are never used as primary evidence for the verdict. The rule name is extracted from the CRE raw payload and used as a weak analysis hint alongside the `rule_name` parameter.

***

## Troubleshooting

| Symptom | Likely Cause | Resolution |
|---------|-------------|------------|
| Action fails with `api_endpoint is required` | Integration config not saved or parameter name mismatch | Verify the parameter name is exactly `api_endpoint` (no spaces, lowercase) |
| HTTP 401 / 403 error | Invalid or expired API key | Regenerate the API key from your provider console and update the integration credential |
| HTTP 404 on Azure | Incorrect deployment URL or missing `api-version` | Confirm the full Azure endpoint URL includes the deployment name and set `api_version` |
| Gemini returns no candidates | Content blocked by safety filters | Review the prompt content; optionally adjust `system_prompt` to reduce filter triggers |
| Timeout after N seconds | Provider latency or large prompt | Increase `request_timeout`; reduce event count or field verbosity in `events_json` |
| `AI response was not valid JSON` | Model returned markdown-wrapped or partial JSON | Increase `max_tokens`; check the system prompt enforces JSON-only output |
| `No usable data parsed from events_json` | Input is an empty array or non-dict/non-array type | Ensure `events_json` contains at least one event object |

***

## Security Considerations

- The `api_key` parameter should always be stored as a **Password / Credential** type in the SOAR IDE — never as a plain string parameter.
- Avoid passing sensitive PII in `events_json` that is not already part of the alert context, since this data is transmitted to an external AI provider.
- For environments with data residency requirements, use **Azure OpenAI** or a self-hosted/on-premises model endpoint to keep data within your boundary.
- Review your AI provider's data processing and retention policies before enabling this integration in production.
