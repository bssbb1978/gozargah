# Workers AI advisor: bounded application and limits

Workers AI recommendations remain advisory unless an operator explicitly opts in from the authenticated panel dashboard. The stored default is off.

## What can be applied

Only the validated `transport` enum can become a preference in the live adaptive protocol scorer. It receives a bounded `+6` score hint, and only when the matching capability is currently marked ready by the Worker/origin-engine catalog. It does not bypass measured policy, client compatibility checks, or the adaptive guard. The model's profile, entry, SNI, fragmentation, and retry values remain advice; the strict response parser still rejects extra fields and clamps numeric values.

This preference affects the Worker-generated adaptive policy bundle only. It does not change the AXR Go client's transport list: that client remains WebSocket-only. Origin-engine templates remain separately declared and must not be treated as live-verified merely because a template can be generated.

## Baseline and automatic rollback

Application requires a `network_state` success-rate baseline updated within the preceding 30 minutes. The applied preference is rolled back to its previous preference (or local scoring if there was none) when a later observation, at least five minutes after application, shows a success-rate drop of at least 15 percentage points. Rollback is evaluated when the adaptive bundle is generated; it is not a background monitor.

The signal is the Worker's aggregate configured-egress health estimate. It is **not** an end-user connection success rate, an inside-Iran measurement, or evidence of DPI/filtering. If the Worker has no fresh baseline, the advice remains unapplied.

## Kill switch

- Use **Kill AI application now** in the panel to clear the active preference immediately. Use the adjacent control to clear that operator kill switch.
- Setting Worker variable `AI_ADVISOR_KILL_SWITCH=true` disables application regardless of D1/panel settings. On the next adaptive-bundle request it also latches the D1 kill state and clears the active preference; after removing the Worker variable, explicitly clear the panel kill switch before opting in again.
- Turning off the opt-in checkbox also clears the active AI preference.

## Model catalog behavior

With `AI_CATALOG_ACCOUNT_ID` and `AI_CATALOG_API_TOKEN` configured and no explicit `AI_MODELS` list, model candidates are selected from Cloudflare's live text-model catalog. A successful result is cached per Worker isolate for six hours. If a refresh fails or returns no usable model rows, an expired cached catalog is used; after isolate eviction, the built-in model list is the fallback. The catalog token is only sent to Cloudflare's fixed model-search endpoint and is never included in the prompt or API response.

## Validation

Malformed, oversized, fenced/prose, or extra-key model output is rejected. Only validated enum/numeric fields are rendered. An invalid response degrades to deterministic local diagnostics; raw model text is not returned or executed.
