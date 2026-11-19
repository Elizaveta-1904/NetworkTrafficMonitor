"""Normalize exported authentication, cloud and threat intelligence records."""

import ipaddress


def normalize(provider, document):
    if provider == "aws":
        for row in document["Records"]:
            yield {"provider": provider, "time": row["eventTime"],
                   "action": row["eventName"], "source": row.get("sourceIPAddress"),
                   "outcome": "error" if row.get("errorCode") else "success"}
    elif provider == "azure":
        for row in document["value"]:
            yield {"provider": provider, "time": row["eventTimestamp"],
                   "action": row["operationName"]["value"],
                   "source": row.get("callerIpAddress"),
                   "outcome": row["status"]["value"]}
    else:
        for row in document["events"]:
            outcome = row["outcome"]
            if outcome not in {"success", "failure"}:
                raise ValueError("Invalid authentication outcome")
            yield {"provider": provider, "time": row["timestamp"],
                   "action": "biometric_authentication", "source": row.get("source_ip"),
                   "outcome": outcome}


def threat_index(misp, otx):
    # MISP Attribute search export and OTX pulse export.
    result = {}
    attributes = misp["response"]["Attribute"]
    indicators = [("MISP", row["value"]) for row in attributes
                  if row["type"] in {"ip-src", "ip-dst"} and row.get("to_ids") is True]
    indicators += [("OTX", row["indicator"]) for pulse in otx["results"]
                   for row in pulse["indicators"] if row["type"] in {"IPv4", "IPv6"}]
    for provider, address in indicators:
        result.setdefault(str(ipaddress.ip_address(address)), set()).add(provider)
    return result
