# Friction log — Ring Partner API + AWS

Real friction hit while building Attest and ring-sandbox. Each entry follows
the required shape: task → steps → expected vs. actual → severity → workaround
→ suggestion.

## 1. Playground access tokens expire in ~30 minutes

- **Task:** Exercise `users/me`, devices, Event History, and media download
  end-to-end from a local runtime.
- **Steps:** Mint a Playground token, configure `ATTEST_RING_ACCESS_TOKEN`,
  poll history on a schedule, come back later.
- **Expected:** A sandbox token lasts the length of a working session.
- **Actual:** ~30-minute lifetime; the runtime began 401ing mid-session with
  no obvious signal except failed polls.
- **Severity:** Medium — every long test session needed a fresh token.
- **Workaround:** Re-minted tokens per session; built the OAuth refresh grant
  path (`ATTEST_RING_REFRESH_TOKEN`) so a real deployment survives rotation —
  verified against the emulator only, since Playground has no refresh flow.
- **Suggestion:** A longer-lived Playground token (or an offline-device mode
  that doesn't expire) would make sustained integration testing practical.

## 2. Media download rides an undocumented redirect chain

- **Task:** Download the snapshot a history event references.
- **Steps:** GET the event's media URL from Event History.
- **Expected:** Media bytes on the documented endpoint.
- **Actual:** A redirect to `phoenix.devices.amazon.dev` — a different host
  than the API surface, so a naive client either fails or follows blindly.
- **Severity:** Medium — undocumented behavior, and a security-relevant one:
  blindly forwarding the bearer token to the redirect target would leak it.
- **Workaround:** Manual redirect handling with an explicit allowlist — JSON
  endpoints never follow redirects, media redirects only reach same-origin or
  allowlisted HTTPS hosts, never carrying credentials.
- **Suggestion:** Document the redirect in the Event History reference and in
  the helloworld sample's download path.

## 3. Webhooks can't be verified end-to-end without a public URL

- **Task:** Confirm HMAC-signed webhook delivery.
- **Steps:** Register a webhook target, generate an event, watch the inbox.
- **Expected:** Deliveries reach the handler.
- **Actual:** Playground cannot reach `localhost` — there is no local-loopback
  delivery path — so the intake path stayed unverified until we built the
  emulator. This is the single largest verification gap for a local-first
  build.
- **Severity:** High for local development.
- **Workaround:** ring-sandbox emulates the signed webhook surface
  (same `X-Signature` HMAC scheme, `meta.request_id` dedupe), and Attest's
  durable inbox was verified against that.
- **Suggestion:** A Playground "deliver to log" mode — enqueue the signed
  delivery and expose it via polling — would let a localhost client verify
  the real signature format end-to-end.

## 4. Playground only surfaces `on_demand` event types

- **Task:** Observe real `ding`/`motion` events in Event History.
- **Steps:** Trigger the simulated device, poll history.
- **Expected:** Simulated events appear with realistic types.
- **Actual:** Only `on_demand` events surface; ding/motion semantics stay
  unverified against the real API shape.
- **Severity:** Medium — a receiver coded to the documented event names has no
  live confirmation they arrive as documented.
- **Workaround:** Emulator scenarios replay the documented event types;
  the ingestion path is keyed off `event_type`/`sub_type` strings matching
  the published docs.
- **Suggestion:** Let the event simulator emit the real production event
  names into history.

## 5. Third-party access requires pausing TAKE

- **Task:** Understand what a partner integration can read.
- **Steps:** Read the TAKE/encryption docs against the API surface.
- **Expected:** Clear statement of what a partner token can reach.
- **Actual:** Third-party integrations require a "temporary pause in TAKE" and
  E2EE-enrolled devices restrict partner access further — the boundary
  between "works" and "blocked by encryption" isn't obvious from the API
  errors themselves.
- **Severity:** Low-Medium — a real product needs to explain this to users.
- **Workaround:** Documented in the README; Attest treats "no events" as
  unknown rather than absent precisely because ingestion gaps are real.
- **Suggestion:** Surface TAKE/scope state in `users/me` or device status so
  an integration can tell "device silent" from "device unreachable to me".

## 6. No SDK and no local simulator — every test needs live tokens

- **Task:** Test the integration in CI.
- **Expected:** An official client or local sandbox for offline iteration.
- **Actual:** Ring ships neither — the only official test path is Playground
  tokens or a real device, both network-bound and time-limited.
- **Severity:** Medium-high — this is why `ring-sandbox` exists at all; it is
  the gap our Open Source entry fills.
- **Workaround:** Built ring-sandbox (typed client + offline emulator +
  webhook signer + scenario replay + chaos mode), published to PyPI.
- **Suggestion:** An official emulator — even a static JSON replay of the
  documented shapes — would remove the largest onboarding cost for every
  developer after us.

## 7. AWS Bedrock: model availability is not model access — or quota

- **Task:** Wire Bedrock Converse summaries + a Strands triage agent.
- **Expected:** A listed model ID can be invoked.
- **Actual:** Three distinct failure layers, none documented together:
  Anthropic models need a separate use-case form; Nova is authorized but the
  daily free-tier token cap returns `ThrottlingException`; and `aws login`
  sessions expire, surfacing as `LoginRefreshRequired` inside boto3 —
  not as a credential error at config time.
- **Severity:** Medium — any hackathon/demo build hits all three.
- **Workaround:** Attest labels every generated artifact with its real source
  (`summary_source` + `summary_fallback_reason`; the triage brief labels
  `strands-agent` vs `deterministic` + reason). The deterministic path is the
  same computation the dashboard renders, so nothing blocks on model access.
- **Suggestion:** Distinguish "model exists", "account permitted", and
  "quota remaining" in the model-access API; one opaque 403 costs real debug time.

## 8. JSON canonicalization is not portable across runtimes

- **Task:** Verify signed receipts in dependency-free JavaScript.
- **Expected:** `JSON.parse` + re-serialize reproduces the signed bytes.
- **Actual:** Python's `json.dumps(ensure_ascii=False)` writes raw UTF-8
  (`—`), while any file spelling `\u2014` canonicalizes differently if the
  verifier copies literals verbatim — and float spellings (`34.0` vs `34.00`)
  break naive re-serialization the other direction. Our signed export
  manifest (an em-dash in its boundary text) verified in Python and silently
  failed in the browser verifier. Separately, the JS media check looked for
  `media/<sha256>` filenames while packs store
  `media/<vid>/<label>.<digest-prefix>.png` — every media file falsely
  reported "missing".
- **Severity:** Medium — invisible until real non-ASCII data + real filenames
  meet the verifier; the Python side passed, so nothing complained.
- **Workaround:** The JS canonicalizer now re-serializes decoded strings
  (matching Python's canonical spelling) while copying non-string literals
  verbatim (preserving float spellings); media is matched by content hash.
  Packs are written `ensure_ascii=False`.
- **Suggestion:** If a signed-artifact spec is language-neutral, publish a
  reference canonicalizer — every team will otherwise re-find this the hard way.
