# ruff: noqa: E501 — prose string table; wrapping sentences mid-string would
# make diffs and translation review harder for no safety gain.
"""Household-view localisation.

The household/family page is the audience that most needs the record's
honesty boundary in plain language — and it is also the audience most
likely to read a language other than English. Strings here are
sentence-level translations that preserve the claim boundary exactly:
observation ≠ attendance, silence ≠ absence, signature ≠ truth, and every
human voice stays verbatim and self-reported. Worker and household
statements are never translated — the signed words render as written.
"""

from __future__ import annotations

SUPPORTED = ("en", "es")


def pick(lang: str | None) -> str:
    """Resolve a ?lang= query value to a supported code — English is the
    default and the fallback for anything unrecognized."""
    return lang if lang in SUPPORTED else "en"


_EN = {
    "brand": "Attest · observation record",
    "page_title": "visit record",
    "og_desc": "A tamper-evident record of a scheduled visit. Open to review what the camera observed, what the worker reported, and what remains uncertain.",
    "scheduled": "scheduled",
    "unscheduled": "Unscheduled record",
    "hero_open_h": "This visit is still in progress",
    "hero_open_p": "This record hasn't been closed and signed yet — what you see below is what has been received so far.",
    "hero_unmatched_h": "Activity was recorded outside any scheduled visit",
    "hero_unmatched_p": "The camera reported activity that doesn't match a scheduled window — flagged for a person to review.",
    "hero_none_h": "No activity was reported",
    "cov_full": "The camera was checked {polls} times across the whole window and reported nothing.",
    "cov_part": "The camera was checked for {pct}% of the window and reported nothing",
    "cov_part_gap": " — some of the window wasn't watched",
    "cov_none": "The camera reported no activity during this window.",
    "cov_interrupt": "The camera itself reported it stopped reporting for part of that time ({reason}) — that gap has a recorded cause.",
    "none_not_proof": "No activity is not proof nobody came — it only means the camera reported nothing.",
    "hero_ok_h": "Activity was observed",
    "hero_ok_p": "The camera reported activity between {a} and {b}",
    "hero_ok_span": " — about {m} minutes between the first and last report",
    "k_first": "First observation",
    "k_last": "Last observation",
    "k_worker": "Scheduled worker",
    "k_checkin": "Worker check-in",
    "checkin_self": " — self-reported from their link; identity isn't verified by the check-in itself.",
    "checkin_none": "Not received",
    "k_account": "Worker's account",
    "k_conclusion": "Conclusion",
    "conclusion": "A coordinator concluded that {outcome} — signed by the coordinator. The worker's statement stays in the record unchanged.",
    "k_integrity": "Integrity",
    "integrity": "Signed record #{n} — tampering after signing is detectable.",
    "full_record": "Full record",
    "k_liveview": "Live view",
    "liveview_open": "The service opened a live view of the camera at {t}.",
    "liveview_limit": "The record shows the stream was opened — it cannot show what a person saw through it.",
    "worker_words": "In the worker's words",
    "worker_words_resolved": "In the worker's words — concluded, kept on record",
    "worker_attr": "— {name}, appended to the signed record (never edited after)",
    "worker_attr_resolved": "; concluded by the coordinator: {stmt}",
    "hh_words": "In the household's words — {perception}",
    "hh_attr": "— household account via the family link, appended to the signed record. Self-reported; it doesn't change the camera's observations or the worker's account.",
    "flash_posted": "Your account was added to the signed record — it now sits alongside the camera's observations and the worker's report. It can't be edited or removed.",
    "form_legend": "What did you see or hear around this visit?",
    "choice_saw": "I saw or heard someone there",
    "choice_saw_d": " — a person at the door",
    "choice_none": "I didn't see or hear anyone",
    "choice_none_d": " — as far as you know, nobody came",
    "choice_unsure": "Not sure",
    "choice_unsure_d": " — you can't say either way",
    "own_words": "In your own words",
    "own_words_ph": "What you saw, heard, or know — e.g. “I was home and the doorbell never rang” or “My neighbor saw someone at 10:15”.",
    "submit": "Add your account to the record",
    "form_note": "This is appended to the signed record as the household's own account — like the worker's statement, it's self-reported. It isn't proof on its own and never changes what the camera reported; a coordinator weighs all three separately. You can come back to this page until the link expires.",
    "snap_title": "Camera snapshots",
    "snap_alt": "Snapshot {t}",
    "snap_cap": "file hash matches the signed record",
    "foot_h": "What this record can and can't tell you.",
    "foot_p": "The camera's report, the schedule, the worker's account, and the household's account are kept separate — this page shows them side by side rather than picking one. A signature proves the record hasn't been altered since it was signed — not identity, attendance, or time worked. No reported activity is not proof nobody came.",
    "foot_verify": "Anyone can check this record without trusting us: ask the service for the export pack and open it in a browser — it verifies itself.",
    "err_incomplete": "Your account needs both parts — pick what happened and write it in your own words (2000 characters max).",
    "err_limit": "This record has reached its statement limit — the view link still works, but no further accounts can be added. Contact the coordinator if something needs correcting.",
    "lang_toggle": "Español",
    "tl_window": "scheduled window",
    "tl_watched": "watched",
    "tl_gap": "gap",
    "tl_obs": "observation",
    "tl_checkin": "self-reported check-in",
    "tl_live": "live view — stream established, never viewership",
    "counter": {
        "acknowledged": "Agrees with this record",
        "contested": "Disputes this record",
        "corrected": "Submitted a correction",
        "resolved": "Concluded by a coordinator",
        "inconclusive": "Responded inconclusively",
        "pending": "Not recorded yet",
    },
    "counter_see": " — see their words below",
    "outcome": {
        "record_upheld": "the signed record stands",
        "account_accepted": "the worker's account was accepted",
        "inconclusive": "it could not be settled either way",
    },
    "interrupt_kind": {
        "device_offline": "it went offline",
        "device_removed": "it was removed",
        "subscription_deactivated": "its subscription ended",
        "subscription_expired": "its subscription ended",
        "app_integration_removed": "its link to this service was removed",
    },
    "perception": {
        "saw_someone": "someone was seen",
        "no_one_seen": "nobody was seen",
        "unsure": "not sure",
    },
}

_ES = {
    "brand": "Attest · registro de observaciones",
    "page_title": "registro de visita",
    "og_desc": "Un registro a prueba de manipulaciones de una visita programada. Ábrelo para revisar qué observó la cámara, qué reportó el trabajador y qué sigue siendo incierto.",
    "scheduled": "programada",
    "unscheduled": "Registro sin horario programado",
    "hero_open_h": "Esta visita sigue en curso",
    "hero_open_p": "Este registro aún no se ha cerrado y firmado: lo que ves abajo es lo recibido hasta ahora.",
    "hero_unmatched_h": "Se registró actividad fuera de cualquier visita programada",
    "hero_unmatched_p": "La cámara reportó actividad que no coincide con ninguna ventana programada; se marcó para que una persona la revise.",
    "hero_none_h": "No se reportó actividad",
    "cov_full": "Se consultó la cámara {polls} veces durante toda la ventana y no reportó nada.",
    "cov_part": "Se consultó la cámara durante el {pct}% de la ventana y no reportó nada",
    "cov_part_gap": " — parte de la ventana no fue supervisada",
    "cov_none": "La cámara no reportó actividad durante esta ventana.",
    "cov_interrupt": "La propia cámara reportó que dejó de informar durante parte de ese tiempo ({reason}); ese intervalo tiene una causa registrada.",
    "none_not_proof": "La ausencia de actividad no prueba que nadie haya venido; solo significa que la cámara no reportó nada.",
    "hero_ok_h": "Se observó actividad",
    "hero_ok_p": "La cámara reportó actividad entre las {a} y las {b}",
    "hero_ok_span": " — unos {m} minutos entre el primer y el último reporte",
    "k_first": "Primera observación",
    "k_last": "Última observación",
    "k_worker": "Persona programada",
    "k_checkin": "Registro de llegada",
    "checkin_self": " — autodeclarado desde su enlace; el registro en sí no verifica la identidad.",
    "checkin_none": "No recibido",
    "k_account": "Versión del trabajador",
    "k_conclusion": "Conclusión",
    "conclusion": "Un coordinador concluyó que {outcome} — firmado por el coordinador. La declaración del trabajador permanece en el registro sin cambios.",
    "k_integrity": "Integridad",
    "integrity": "Registro firmado n.º {n} — cualquier alteración posterior a la firma es detectable.",
    "full_record": "Registro completo",
    "k_liveview": "Vista en vivo",
    "liveview_open": "El servicio abrió una vista en vivo de la cámara a las {t}.",
    "liveview_limit": "El registro muestra que se abrió la transmisión; no puede mostrar lo que una persona vio a través de ella.",
    "worker_words": "En palabras del trabajador",
    "worker_words_resolved": "En palabras del trabajador — concluido, conservado en el registro",
    "worker_attr": "— {name}, añadido al registro firmado (nunca editado después)",
    "worker_attr_resolved": "; concluido por el coordinador: {stmt}",
    "hh_words": "En palabras de la familia — {perception}",
    "hh_attr": "— relato de la familia a través del enlace familiar, añadido al registro firmado. Es autodeclarado; no cambia las observaciones de la cámara ni la versión del trabajador.",
    "flash_posted": "Tu relato se añadió al registro firmado: ahora figura junto a las observaciones de la cámara y el reporte del trabajador. No puede editarse ni eliminarse.",
    "form_legend": "¿Qué viste u oíste en torno a esta visita?",
    "choice_saw": "Vi u oí a alguien allí",
    "choice_saw_d": " — una persona en la puerta",
    "choice_none": "No vi ni oí a nadie",
    "choice_none_d": " — que sepas, nadie vino",
    "choice_unsure": "No lo sé",
    "choice_unsure_d": " — no puedes afirmar ni una cosa ni la otra",
    "own_words": "Con tus propias palabras",
    "own_words_ph": "Lo que viste, oíste o sabes — por ejemplo: «Estaba en casa y el timbre nunca sonó» o «Mi vecino vio a alguien a las 10:15».",
    "submit": "Añade tu relato al registro",
    "form_note": "Se añade al registro firmado como el relato propio de la familia — igual que la declaración del trabajador, es autodeclarado. No es una prueba por sí solo y nunca cambia lo que la cámara reportó; un coordinador pondera las tres fuentes por separado. Puedes volver a esta página hasta que el enlace caduque.",
    "snap_title": "Capturas de la cámara",
    "snap_alt": "Captura {t}",
    "snap_cap": "el hash del archivo coincide con el registro firmado",
    "foot_h": "Lo que este registro puede y no puede decirte.",
    "foot_p": "El reporte de la cámara, el horario, la versión del trabajador y el relato de la familia se conservan por separado — esta página los muestra lado a lado en lugar de elegir uno. Una firma prueba que el registro no se ha alterado desde que se firmó; no prueba identidad, asistencia ni tiempo trabajado. Que no se haya reportado actividad no prueba que nadie haya venido.",
    "foot_verify": "Cualquiera puede comprobar este registro sin confiar en nosotros: pide al servicio el paquete de exportación y ábrelo en un navegador — se verifica a sí mismo.",
    "err_incomplete": "Tu relato necesita ambas partes: elige qué pasó y escríbelo con tus propias palabras (2000 caracteres como máximo).",
    "err_limit": "Este registro alcanzó su límite de relatos — el enlace de consulta sigue funcionando, pero no se pueden añadir más. Contacta al coordinador si algo necesita corrección.",
    "lang_toggle": "English",
    "tl_window": "ventana programada",
    "tl_watched": "supervisada",
    "tl_gap": "brecha",
    "tl_obs": "observación",
    "tl_checkin": "registro autodeclarado",
    "tl_live": "vista en vivo — transmisión establecida, nunca audiencia",
    "counter": {
        "acknowledged": "Está de acuerdo con este registro",
        "contested": "Cuestiona este registro",
        "corrected": "Envió una corrección",
        "resolved": "Concluido por un coordinador",
        "inconclusive": "Respondió de forma no concluyente",
        "pending": "Aún no registrada",
    },
    "counter_see": " — lee sus palabras abajo",
    "outcome": {
        "record_upheld": "el registro firmado se mantiene",
        "account_accepted": "se aceptó la versión del trabajador",
        "inconclusive": "no pudo resolverse en ningún sentido",
    },
    "interrupt_kind": {
        "device_offline": "se desconectó",
        "device_removed": "fue retirada",
        "subscription_deactivated": "su suscripción terminó",
        "subscription_expired": "su suscripción terminó",
        "app_integration_removed": "su vínculo con este servicio fue retirado",
    },
    "perception": {
        "saw_someone": "alguien fue visto",
        "no_one_seen": "no se vio a nadie",
        "unsure": "no está claro",
    },
}

_WEEKDAYS = {
    "en": None,  # strftime %A is already English
    "es": ["lunes", "martes", "miércoles", "jueves", "viernes", "sábado", "domingo"],
}

_MONTHS = {
    "en": None,  # strftime %B is already English
    "es": [
        "enero",
        "febrero",
        "marzo",
        "abril",
        "mayo",
        "junio",
        "julio",
        "agosto",
        "septiembre",
        "octubre",
        "noviembre",
        "diciembre",
    ],
}


def strings(lang: str | None) -> dict:
    """The full string table for one language, English-filled for any key a
    translation misses — a partial translation degrades gracefully."""
    code = pick(lang)
    merged = dict(_EN)
    merged.update(_ES if code == "es" else {})
    merged["lang"] = code
    merged["time_fmt"] = "%H:%M" if code == "es" else None
    merged["weekdays"] = _WEEKDAYS[code]
    merged["months"] = _MONTHS[code]
    return merged
