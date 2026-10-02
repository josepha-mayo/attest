"""Structured exception taxonomy — the reason-code layer EVV-style exception
queues (Sandata, state Medicaid EVV systems) use so a flagged record can't be
closed with a shrug: every human conclusion carries a coded reason.

Attest's version stays honest: a reason code classifies the *coordinator's
stated explanation* — it never asserts what physically happened. Codes are
signed into the resolution review so the disposition is part of the chain,
auditable and exportable (the CSV register carries them)."""

from __future__ import annotations

# code -> human label. Borrowed in spirit from published state-EVV exception
# taxonomies (schedule/service differences, authorization, device/telephony
# causes, participant causes, worker causes) — adapted to what a camera-anchored
# record can actually distinguish.
REASON_CODES: dict[str, str] = {
    "schedule_difference": "Service or timing differed from the plan",
    "authorization_gap": "Plan/authorization coverage lapsed or ended",
    "device_fault": "Camera or sensor faulted — channel interruption recorded",
    "subscription_lapse": "Ring subscription ended mid-window",
    "mobile_or_network_issue": "Worker's phone/app or the home network failed",
    "service_outside_home": "Service happened away from the camera's view",
    "worker_error": "Worker forgot the check-in step or used it wrong",
    "worker_unavailable": "Worker was unavailable or reassigned",
    "participant_unavailable": "Household wasn't home or didn't answer",
    "participant_refused": "Household declined the visit or the device",
    "weather_or_disaster": "Weather/emergency prevented the visit",
    "no_electronic_confirmation": "No device confirmation exists — unexplained gap",
    "other": "Other — the statement carries the detail",
}

# visit flag code -> reason codes a coordinator would plausibly reach for.
# Pure UI suggestion order — the flag itself stays the machine's observation,
# the reason is the human's stated cause.
_FLAG_SUGGESTIONS: dict[str, list[str]] = {
    "no_observation": [
        "participant_unavailable",
        "worker_unavailable",
        "device_fault",
        "subscription_lapse",
        "weather_or_disaster",
        "no_electronic_confirmation",
    ],
    "departure_unconfirmed": [
        "device_fault",
        "worker_error",
        "service_outside_home",
        "no_electronic_confirmation",
    ],
    "observed_interval_short": ["participant_unavailable", "service_outside_home", "schedule_difference"],
    "late": ["schedule_difference", "worker_unavailable", "weather_or_disaster", "worker_error"],
    "early": ["schedule_difference", "worker_error"],
    "no_checkin": ["worker_error", "mobile_or_network_issue", "service_outside_home"],
    "observation_gap": ["device_fault", "subscription_lapse", "mobile_or_network_issue"],
    "media_unavailable": ["device_fault", "subscription_lapse"],
    "idle_close": ["device_fault", "service_outside_home"],
    "unscheduled": ["schedule_difference", "worker_error", "other"],
    "clock_conflict": ["worker_error", "other"],
}


def suggest(flag_codes: list[str]) -> list[str]:
    """Reason codes worth offering first for a record's flags — ordered,
    deduplicated, then the rest of the taxonomy appended."""
    seen: list[str] = []
    for code in flag_codes:
        for c in _FLAG_SUGGESTIONS.get(code, []):
            if c not in seen:
                seen.append(c)
    return seen + [c for c in REASON_CODES if c not in seen]


def label(code: str | None) -> str:
    return REASON_CODES.get(code or "", code or "")
