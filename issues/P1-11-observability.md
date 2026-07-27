# P1-11 — Observability: metrics & dashboards

- **Phase:** P1 — MVP
- **Status:** Done
- **PRD refs:** FR-28, §14 (success metrics)
- **Depends on:** P1-02
- **Blocks:** —

## Goal
Expose metrics and dashboards for auth volume, decision latency, denial reasons, revocation events, and anomalies so operators can run the gateway and we can validate the NFRs.

## Scope (in)
- Prometheus-style metrics from the gateway/STS: auth volume, decision latency histograms (hot vs. cold path), denial reasons, passport issuance rate, revocation events.
- Reference dashboards (Grafana or equivalent).
- Latency instrumentation aligned to NFR-1 targets (p95 hot ≤50ms, cold ≤200ms) so they're measurable from day one.
- Basic anomaly signals (e.g., denial-rate spike, issuance spike).

## Out of scope
- Full SIEM event streaming (that's P1-08); ML-based anomaly detection.

## Acceptance criteria
- Metrics endpoint exposes the listed series with useful labels (server, decision, reason).
- A reference dashboard renders latency, volume, denials, and revocations.
- Hot/cold path latency is observable and compared against NFR-1 targets.

## Open questions
- Metrics stack assumption (Prometheus/Grafana) — confirm vs. design-partner observability.
