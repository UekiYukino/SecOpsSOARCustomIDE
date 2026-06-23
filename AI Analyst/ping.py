# ============================================================
# Google SecOps SOAR - AIModelQuery Integration
# ACTION: Ping
# Tests connectivity and authentication for all providers.
# ============================================================

from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
import requests
import json

INTEGRATION_NAME = "AIModelQuery"


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = "Ping"

    # ── Read integration-level parameters ───────────────────
    api_endpoint  = siemplify.extract_configuration_param(
                        INTEGRATION_NAME, "api_endpoint",  is_mandatory=True)
    api_key       = siemplify.extract_configuration_param(
                        INTEGRATION_NAME, "api_key",       is_mandatory=True)
    model_name    = siemplify.extract_configuration_param(
                        INTEGRATION_NAME, "model_name",    is_mandatory=True)
    provider      = (siemplify.extract_configuration_param(
                        INTEGRATION_NAME, "provider",      default_value="openai") or "openai").lower()
    api_version   = siemplify.extract_configuration_param(
                        INTEGRATION_NAME, "api_version",   default_value="") or ""

    ping_prompt = "Reply with the word PONG only."
    headers     = {"Content-Type": "application/json"}
    params      = {}

    # ── Build provider-specific auth + minimal payload ──────
    if provider == "anthropic":
        headers["x-api-key"]          = api_key
        headers["anthropic-version"]  = "2023-06-01"
        payload = {
            "model":      model_name,
            "max_tokens": 10,
            "messages":   [{"role": "user", "content": ping_prompt}],
        }

    elif provider == "gemini":
        # Gemini auth is a query param — no Authorization header
        params["key"] = api_key
        payload = {
            "contents": [
                {
                    "role":  "user",
                    "parts": [{"text": ping_prompt}]
                }
            ],
            "generationConfig": {"maxOutputTokens": 10},
        }
        # NOTE: api_endpoint must already include the model name, e.g.:
        # https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent

    elif provider == "azure":
        headers["api-key"] = api_key
        if api_version:
            params["api-version"] = api_version
        payload = {
            "model":      model_name,
            "messages":   [{"role": "user", "content": ping_prompt}],
            "max_tokens": 10,
        }

    else:  # openai / openai-compatible
        headers["Authorization"] = f"Bearer {api_key}"
        payload = {
            "model":      model_name,
            "messages":   [{"role": "user", "content": ping_prompt}],
            "max_completion_tokens": 10,
        }

    # ── Send request ─────────────────────────────────────────
    try:
        response = requests.post(
            api_endpoint,
            headers=headers,
            json=payload,
            params=params if params else None,
            timeout=15,
        )

        if response.status_code == 200:
            # Try to extract the reply text for extra confirmation
            try:
                resp_json = response.json()
                if provider == "anthropic":
                    reply = resp_json["content"][0]["text"]
                elif provider == "gemini":
                    candidate = resp_json.get("candidates", [{}])[0]
                    reply = candidate.get("content", {}).get(
                        "parts", [{}])[0].get("text", "(no text)")
                else:
                    reply = resp_json["choices"][0]["message"]["content"]
            except Exception:
                reply = "(response received but could not extract text)"

            siemplify.end(
                f"Ping successful. "
                f"Provider: {provider} | Model: {model_name} | "
                f"HTTP 200 | Reply: {reply.strip()}",
                True,
            )

        elif response.status_code == 401:
            siemplify.end(
                f"Authentication failed (HTTP 401). "
                f"Check your api_key for provider '{provider}'. "
                f"Detail: {response.text[:300]}",
                False,
            )

        elif response.status_code == 403:
            siemplify.end(
                f"Access forbidden (HTTP 403). "
                f"Key may lack permissions or model access. "
                f"Detail: {response.text[:300]}",
                False,
            )

        elif response.status_code == 404:
            siemplify.end(
                f"Endpoint not found (HTTP 404). "
                f"Check api_endpoint and model_name. "
                f"Detail: {response.text[:300]}",
                False,
            )

        elif response.status_code == 400:
            siemplify.end(
                f"Bad request (HTTP 400). "
                f"Check model_name and api_endpoint format for provider '{provider}'. "
                f"Detail: {response.text[:300]}",
                False,
            )

        else:
            siemplify.end(
                f"Unexpected HTTP {response.status_code} from provider '{provider}'. "
                f"Detail: {response.text[:300]}",
                False,
            )

    except requests.exceptions.Timeout:
        siemplify.end(
            "Ping timed out after 15 seconds. "
            "Check network connectivity between SOAR and the AI endpoint.",
            False,
        )
    except requests.exceptions.RequestException as req_err:
        siemplify.end(f"Ping failed with network error: {req_err}", False)


if __name__ == "__main__":
    main()
