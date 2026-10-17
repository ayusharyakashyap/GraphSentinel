"""Allowed labels, required properties, and relationship endpoint types."""

NODE_REQUIRED_PROPERTIES = {
    "Identity": {"id", "name", "department", "privilege_level"},
    "Device": {"id", "hostname", "device_type", "criticality", "state"},
    "Service": {"id", "name", "criticality", "environment", "state"},
    "Alert": {"id", "type", "severity", "timestamp", "status", "description"},
    "Event": {"id", "type", "timestamp", "source", "confidence", "description"},
    "Vulnerability": {"id", "cve", "severity", "exploitable", "description"},
    "Incident": {"id", "type", "risk_score", "status", "created_at", "summary"},
    "Evidence": {
        "id", "description", "source", "timestamp", "confidence",
        "evidence_type", "supports_finding",
    },
    "ResponseAction": {
        "id", "action_type", "status", "created_at", "approved_by", "result",
    },
    "InvestigationEpisode": {
        "id", "alert_id", "summary", "risk_score", "risk_level", "confidence",
        "evidence_completeness", "created_at", "outcome", "event_types_json",
        "entity_ids_json", "evidence_ids_json", "attack_paths_json",
        "risk_factors_json", "recommendation_json", "result_json",
    },
    "ActionAudit": {
        "id", "action_id", "event_type", "from_state", "to_state", "actor",
        "timestamp", "details_json",
    },
}

RELATIONSHIP_ENDPOINTS = {
    "USES": {("Identity", "Device")},
    "ACCESSES": {("Identity", "Service")},
    "CONNECTS_TO": {("Device", "Service")},
    "DEPENDS_ON": {("Service", "Service")},
    "HAS_VULNERABILITY": {("Service", "Vulnerability")},
    "OBSERVED_ON": {
        ("Alert", "Identity"), ("Alert", "Device"), ("Alert", "Service"),
    },
    "INVOLVES": {
        ("Event", "Identity"), ("Event", "Device"), ("Event", "Service"),
        ("Incident", "Identity"), ("Incident", "Device"),
        ("Incident", "Service"),
        ("InvestigationEpisode", "Identity"),
        ("InvestigationEpisode", "Device"),
        ("InvestigationEpisode", "Service"),
    },
    "HAS_EVENT": {("Alert", "Event"), ("InvestigationEpisode", "Event")},
    "HAS_EVIDENCE": {
        ("Alert", "Evidence"), ("InvestigationEpisode", "Evidence"),
    },
    "ABOUT": {("Evidence", "Identity"), ("Evidence", "Device"), ("Evidence", "Service")},
    "SUPPORTED_BY": {("Incident", "Evidence")},
    "RELATED_TO": {("Incident", "Incident")},
    "FOLLOWED_PATH": {
        ("Incident", "Service"), ("InvestigationEpisode", "Service"),
    },
    "PROPOSES": {
        ("Incident", "ResponseAction"), ("InvestigationEpisode", "ResponseAction"),
    },
    "RESOLVED_BY": {
        ("Incident", "ResponseAction"), ("InvestigationEpisode", "ResponseAction"),
    },
    "INVESTIGATES": {("InvestigationEpisode", "Alert")},
    "HAS_AUDIT_EVENT": {("ResponseAction", "ActionAudit")},
    "DISCOVERED": {("InvestigationEpisode", "Vulnerability")},
}