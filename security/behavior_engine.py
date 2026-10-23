from security.risk_scoring import (
    increase_risk
)


def detect_behavior(event_type):

    if event_type == "mass_file_change":

        increase_risk(40)

        return "Mass file activity detected"

    if event_type == "suspicious_process":

        increase_risk(30)

        return "Suspicious process detected"

    if event_type == "network_connection":

        increase_risk(20)

        return "Unknown network connection"

    return "Normal behavior"