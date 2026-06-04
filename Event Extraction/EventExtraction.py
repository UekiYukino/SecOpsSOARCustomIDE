"""Google SecOps SOAR - Custom Action: extract all events from the current case.

Collects every security event attached to every alert in the case that the
action runs on, and returns them as a JSON result. Uses ONLY the native
Siemplify SDK (no TIPCommon).

Because the events are read from the case object that the platform has already
loaded, this action makes NO external API calls and needs NO integration
configuration and NO action parameters.
"""

import json

from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED


INTEGRATION_NAME = "MyIntegration"
SCRIPT_NAME = "List Case Events"


def _json_default(obj):
    """Make SDK objects (e.g. SecurityEventInfo) JSON-serializable.

    json.dumps calls this for any value it can't serialize on its own. It
    prefers the object's raw event fields (additional_properties), then falls
    back to the object's attributes, then to a string.
    """
    props = getattr(obj, "additional_properties", None)
    if isinstance(props, dict):
        return props
    if hasattr(obj, "__dict__"):
        return vars(obj)
    return str(obj)


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = f"{INTEGRATION_NAME} - {SCRIPT_NAME}"
    siemplify.LOGGER.info("================= Main - Param Init =================")
    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    status = EXECUTION_STATE_COMPLETED
    result_value = "false"
    output_message = ""
    json_results = {"total_events": 0, "events": [], "alerts": []}

    try:
        all_events = []

        # siemplify.case holds the full case, including every alert it contains.
        case = siemplify.case

        for alert in case.alerts:
            # Each alert carries its raw security events as a list of dicts.
            events = list(alert.security_events or [])
            all_events.extend(events)

            # Per-alert summary (counts only, so events aren't duplicated).
            json_results["alerts"].append({
                "alert_identifier": alert.identifier,
                "alert_name": getattr(alert, "name", None),
                "event_count": len(events),
            })

            siemplify.LOGGER.info(
                f"Alert {alert.identifier}: collected {len(events)} event(s)."
            )

        # Flat list of every event in the case.
        json_results["events"] = all_events
        json_results["total_events"] = len(all_events)

        if all_events:
            result_value = "true"
            output_message = (
                f"Successfully extracted {len(all_events)} event(s) from "
                f"{len(case.alerts)} alert(s) in the case."
            )
        else:
            output_message = "No events were found in this case."

    except Exception as e:
        status = EXECUTION_STATE_FAILED
        result_value = "false"
        output_message = f'Error executing action "{SCRIPT_NAME}". Reason: {e}'
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)

    # Attach the JSON result. add_result_json expects a JSON string.
    # default=_json_default converts SecurityEventInfo objects into dicts.
    siemplify.result.add_result_json(json.dumps(json_results, default=_json_default))

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(f"Status: {status}")
    siemplify.LOGGER.info(f"Result Value: {result_value}")
    siemplify.LOGGER.info(f"Output Message: {output_message}")

    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
