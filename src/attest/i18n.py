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


def negotiate(lang_param: str | None, accept_language: str | None) -> str:
    """Language for a public surface: an explicit ?lang= always wins; absent
    that, the browser's Accept-Language picks Spanish only when it is strictly
    preferred over English. A link texted to an aide or family opens in the
    handset's language without anyone having to find the toggle."""
    if lang_param is not None:
        return pick(lang_param)
    q_en = q_es = 0.0
    for part in (accept_language or "").split(","):
        bits = part.strip().split(";")
        code = bits[0].strip().lower()
        weight = 1.0
        for b in bits[1:]:
            b = b.strip()
            if b.startswith("q="):
                try:
                    weight = float(b[2:])
                except ValueError:
                    pass
        if code == "es" or code.startswith("es-"):
            q_es = max(q_es, weight)
        elif code == "en" or code.startswith("en-") or code == "*":
            q_en = max(q_en, weight)
        # Unrelated codes (fr, de, …) weigh on neither side — we cannot
        # serve them, and counting them for English would beat a real
        # secondary Spanish preference.
    return "es" if q_es > q_en else "en"


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
    "tl_aria_prefix": "Timeline — ",
    "tl_title_window": "scheduled window",
    "tl_title_watched": "watched by polling",
    "tl_title_gap": "coverage gap — not watched",
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
    # Dead-link surface — the only page a family member sees when a link fails.
    "dead_title": "Link unavailable",
    "dead_heading": "This link is no longer usable",
    "dead_family_detail": "This family view link is invalid or expired.",
    "dead_family_mechanics": "Family view links are visit-scoped and expire after 7 days — the link itself is the authorization to view that one record.",
    "dead_cta": "If you need a new link, ask the agency that issued it to send a fresh one.",
    "dead_gates_family": "Nothing about the underlying record changed: links gate reading the record, never the signed record itself.",
    "dead_checkin_detail": "This check-in link is invalid, expired, or already used.",
    "dead_review_detail": "This review link is invalid, expired, or already used.",
    "dead_worker_mechanics": "Worker check-in and review links are visit-scoped, expire, and are single-use — a link that was already used or has expired cannot be reopened.",
    "dead_gates_checkin": "Nothing about the underlying record changed: links gate checking in, never the signed record itself.",
    "dead_gates_review": "Nothing about the underlying record changed: links gate adding a statement, never the signed record itself.",
    # Timeline strip — SVG titles + the aria-label prose a screen reader speaks.
    # Kind names stay neutral ('departure cue', never 'departure').
    "tl_kind_arrival_motion": "motion",
    "tl_kind_doorbell": "doorbell",
    "tl_kind_door_opened": "door opened",
    "tl_kind_door_closed": "door closed",
    "tl_kind_activity": "activity",
    "tl_kind_departure_motion": "departure cue",
    "tl_kind_on_demand": "on-demand media",
    "tl_kind_snapshot": "snapshot",
    "tl_kind_checkin": "worker check-in",
    "tl_kind_late": "late-arriving event",
    "tl_kind_liveview": "live view",
    "tl_aria_scheduled": "scheduled {a}–{b}",
    "tl_aria_coverage": "{watched} watched interval(s), {gaps} coverage gap(s)",
    "tl_aria_live": "{n} live-view session(s) (provenance only)",
    "tl_aria_empty": "empty timeline",
    "tl_title_live_band": "live view — a stream was established {a} -> {b}; viewership not shown",
    "tl_title_live_open": "live view opened {at} — still open; attests a session, never viewership",
    "tl_title_late": "late-arriving event — {at}",
    # Worker surfaces — check-in and review links. The worker is the third
    # audience that may not read English first; the signed words still render
    # verbatim, only the chrome translates.
    "wk_checkin_brand": "Attest check-in",
    "wk_hi": "Hi {name}.",
    "wk_checked_in": "✓ You're checked in{at}.",
    "wk_checked_in_at": " at {t}",
    "wk_checkin_done": "Your self-report has been recorded. This link is now used and cannot submit again. You can close this page.",
    "wk_checkin_q": "Activity was observed at {site} at {t}. Are you there now?",
    "wk_checkin_disclaimer": "This records your self-report at the current time, not the time of the camera event. It does not independently verify identity or location. Submit only for yourself.",
    "wk_checkin_yes": "Yes, I'm here",
    "wk_review_title": "Worker's account",
    "wk_review_h": "Your account of the visit",
    "wk_done_h": "Statement recorded",
    "wk_done_p": "Your statement was appended and signed without changing the original observation record. This link has been consumed.",
    "wk_issued": "This link was issued to {name} for the record at {site}. It expires 24 hours after issue and works once.",
    "wk_first": "First observation",
    "wk_last": "Last observation",
    "wk_none": "None received",
    "wk_honest": "A short observation interval does not mean you left or stopped working. You can explain missing context, dispute an interpretation, or report your own times.",
    "wk_replay": "Local replay: event times use a simulated clock. This is not a live visit.",
    "wk_submit": "Submit my statement once",
    "wk_link_scope": "The link authorizes a statement for this record only. It does not independently verify the submitter's identity.",
    "rf_assessment": "Assessment",
    "rf_opt_inconclusive": "Inconclusive — more context needed",
    "rf_opt_confirm_coord": "Confirm the recorded account",
    "rf_opt_confirm_worker": "Confirm my account of the visit",
    "rf_opt_dispute": "Dispute the interpretation",
    "rf_opt_correction": "Add a correction or missing context",
    "rf_reason": "Reason code",
    "rf_reason_opt_coord": "optional — the coded explanation you are stating",
    "rf_reason_opt_worker": "optional — what best explains the exception, in your view",
    "rf_reason_never": "never a verified cause",
    "rf_reason_none": "No coded reason — statement carries it",
    "rf_statement": "Statement",
    "rf_statement_ph": "Explain what you know and what should be corrected.",
    "rf_start": "Reported start (optional, include UTC offset)",
    "rf_end": "Reported end (optional, include UTC offset)",
    "rf_times_note": "Supply both times or neither. These are reported times, not independently measured work duration. Original observations will not change.",
    "wk_err_invalid": "Your statement didn't submit — check that it's not empty and that either both reported times or neither are filled, each with a UTC offset like 2026-09-15T09:00:00-07:00.",
    "wk_err_full": "This record's review chain is full — no further statements can be appended. Ask the coordinator to export the case pack.",
    "wk_err_precedes": "Your check-in didn't record — the record has no observation yet to check in against.",
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
    "tl_aria_prefix": "Línea de tiempo — ",
    "tl_title_window": "ventana programada",
    "tl_title_watched": "observada por sondeo",
    "tl_title_gap": "brecha de cobertura — no observada",
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
    "dead_title": "Enlace no disponible",
    "dead_heading": "Este enlace ya no se puede usar",
    "dead_family_detail": "Este enlace familiar ya no es válido o ha caducado.",
    "dead_family_mechanics": "Los enlaces familiares están limitados a una visita y caducan a los 7 días — el propio enlace es la autorización para ver ese registro.",
    "dead_cta": "Si necesita un enlace nuevo, pida a la agencia que lo emitió que envíe uno nuevo.",
    "dead_gates_family": "Nada del registro ha cambiado: los enlaces solo controlan la lectura, nunca el registro firmado.",
    "dead_checkin_detail": "Este enlace de registro de llegada no es válido, caducó o ya se usó.",
    "dead_review_detail": "Este enlace de revisión no es válido, caducó o ya se usó.",
    "dead_worker_mechanics": "Los enlaces de registro y revisión están limitados a una visita, caducan y son de un solo uso — un enlace usado o caducado no se puede reabrir.",
    "dead_gates_checkin": "Nada del registro ha cambiado: los enlaces solo controlan el registro de llegada, nunca el registro firmado.",
    "dead_gates_review": "Nada del registro ha cambiado: los enlaces solo controlan añadir una declaración, nunca el registro firmado.",
    # Timeline strip — títulos SVG y la prosa del aria-label.
    "tl_kind_arrival_motion": "movimiento",
    "tl_kind_doorbell": "timbre",
    "tl_kind_door_opened": "puerta abierta",
    "tl_kind_door_closed": "puerta cerrada",
    "tl_kind_activity": "actividad",
    "tl_kind_departure_motion": "señal de salida",
    "tl_kind_on_demand": "contenido a pedido",
    "tl_kind_snapshot": "captura",
    "tl_kind_checkin": "registro del trabajador",
    "tl_kind_late": "evento tardío",
    "tl_kind_liveview": "vista en vivo",
    "tl_aria_scheduled": "programado {a}–{b}",
    "tl_aria_coverage": "{watched} intervalo(s) observado(s), {gaps} brecha(s) de cobertura",
    "tl_aria_live": "{n} sesión(es) de vista en vivo (solo procedencia)",
    "tl_aria_empty": "línea de tiempo vacía",
    "tl_title_live_band": "vista en vivo — se estableció una transmisión {a} -> {b}; no se muestra quién la vio",
    "tl_title_live_open": "vista en vivo abierta {at} — aún abierta; certifica una sesión, nunca la visualización",
    "tl_title_late": "evento tardío — {at}",
    # Worker surfaces — check-in and review links. El trabajador es la tercera
    # audiencia que puede no leer inglés primero; las palabras firmadas siguen
    # verbatim, solo se traduce la interfaz.
    "wk_checkin_brand": "Registro de llegada · Attest",
    "wk_hi": "Hola, {name}.",
    "wk_checked_in": "✓ Llegada registrada{at}.",
    "wk_checked_in_at": " a las {t}",
    "wk_checkin_done": "Tu reporte quedó registrado. Este enlace ya se usó y no puede enviarse de nuevo. Puedes cerrar esta página.",
    "wk_checkin_q": "Se observó actividad en {site} a las {t}. ¿Estás ahí ahora?",
    "wk_checkin_disclaimer": "Esto registra tu propio reporte a la hora actual, no la hora del evento de la cámara. No verifica identidad ni ubicación. Úsalo solo para ti.",
    "wk_checkin_yes": "Sí, estoy aquí",
    "wk_review_title": "Versión del trabajador",
    "wk_review_h": "Tu versión de la visita",
    "wk_done_h": "Relato registrado",
    "wk_done_p": "Tu relato se añadió y firmó sin cambiar el registro de observación original. Este enlace quedó consumido.",
    "wk_issued": "Este enlace se emitió para {name} y el registro en {site}. Caduca 24 horas después de emitirse y funciona una sola vez.",
    "wk_first": "Primera observación",
    "wk_last": "Última observación",
    "wk_none": "No se recibió ninguna",
    "wk_honest": "Un intervalo de observación corto no significa que te hayas ido ni que hayas dejado de trabajar. Puedes explicar el contexto que falte, cuestionar una interpretación o reportar tus propios horarios.",
    "wk_replay": "Repetición local: las horas de los eventos usan un reloj simulado. Esta no es una visita en vivo.",
    "wk_submit": "Enviar mi relato una sola vez",
    "wk_link_scope": "El enlace autoriza un relato solo para este registro. No verifica de forma independiente la identidad de quien lo envía.",
    "rf_assessment": "Valoración",
    "rf_opt_inconclusive": "No concluyente — hace falta más contexto",
    "rf_opt_confirm_coord": "Confirmar la versión registrada",
    "rf_opt_confirm_worker": "Confirmar mi versión de la visita",
    "rf_opt_dispute": "Cuestionar la interpretación",
    "rf_opt_correction": "Añadir una corrección o contexto que falta",
    "rf_reason": "Código de motivo",
    "rf_reason_opt_coord": "opcional — la explicación codificada que declaras",
    "rf_reason_opt_worker": "opcional — qué explica mejor la excepción, según tu criterio",
    "rf_reason_never": "nunca una causa verificada",
    "rf_reason_none": "Sin código de motivo — el relato lo explica",
    "rf_statement": "Relato",
    "rf_statement_ph": "Explica lo que sabes y qué debe corregirse.",
    "rf_start": "Hora declarada de inicio (opcional, incluye el huso UTC)",
    "rf_end": "Hora declarada de fin (opcional, incluye el huso UTC)",
    "rf_times_note": "Indica ambas horas o ninguna. Son horas declaradas, no una medición independiente del tiempo trabajado. Las observaciones originales no cambiarán.",
    "wk_err_invalid": "Tu relato no se envió: comprueba que no esté vacío y que declares ambas horas o ninguna, cada una con huso UTC como 2026-09-15T09:00:00-07:00.",
    "wk_err_full": "La cadena de revisiones de este registro está llena — no se pueden añadir más relatos. Pide al coordinador que exporte el paquete del caso.",
    "wk_err_precedes": "Tu llegada no se registró: el registro aún no tiene ninguna observación con la que cotejarla.",
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
