# Compliance mapping

This table maps controls implemented (or planned) in this repository to external
compliance frameworks. Status is marked honestly:

- **implemented** — the control exists in code/config in this repo and is exercised
  by a test or PoC.
- **partial** — some of the control exists, but not the full scope the framework
  expects (e.g. logic exists but is not wired to live infrastructure).
- **documented-only** — this repo describes the control or the gap in documentation
  (threat model, ADRs, README limitations) but does not implement it.

A reference implementation with every row marked "implemented" would not be
credible. Several rows here are intentionally partial or documented-only.

| Control (this repo) | EU AI Act | DORA | ISO/IEC 42001 | NIST AI RMF | BAIT/MaRisk | Status |
|---|---|---|---|---|---|---|
| Default-deny egress + allowlist (`control/policy_engine.py`) | Art. 9 risk management (technical mitigations) | ICT risk management (network controls) | A.8 operational planning and control | GOVERN 1, MANAGE 2 | AT 7.2 (IT security) | implemented |
| Zone enforcement (policy layer) | Art. 9 risk management | ICT risk management | A.8 | MANAGE 2 | AT 7.2 | implemented |
| Zone enforcement (network layer, Cilium NetworkPolicy) | Art. 9 | ICT risk management | A.8 | MANAGE 2 | AT 7.2 | documented-only (Phase 2 planned, see `docs/adr/0001-cilium-over-calico.md`) |
| AND-gate delegated identity (`capabilities` intersection) | Art. 14 human oversight | Third-party/ICT risk (accountable delegation) | A.6.2 roles and responsibilities | GOVERN 1.1 | AT 4.3 (accountable ownership) | implemented |
| Short-lived capability tokens (`control/token_issuer.py`) | Art. 9 risk management | ICT risk management (access control) | A.8 | MANAGE 2 | AT 7.2 | implemented, single-process revocation only |
| Append-only audit trail (`control/audit.py`) | Art. 12 record-keeping | ICT risk management (traceability) | A.8, A.9 monitoring | MEASURE 2, MANAGE 4 | AT 7.2, documentation obligations | implemented, local JSONL backend only |
| Response chain (`control/response.py`) | Art. 9 risk management | Incident management / ICT third-party risk | A.8, A.10 incident response | MANAGE 4 | AT 8 (incident management) | partial (logic implemented, not wired to a live cluster) |
| Detection rules mapped to ATLAS/OWASP ASI (`detection/`) | Art. 9 risk management | ICT risk management (monitoring) | A.9 monitoring | MEASURE 2 | AT 7.2 | partial (evaluated against synthetic events only; no live ingestion) |
| Agent registry with accountable owner (`registry/agents.yaml`) | Art. 14 human oversight, Art. 4 AI literacy (org readiness) | Third-party risk (accountable sponsor) | A.6.2 | GOVERN 1.1, GOVERN 3 | AT 4.3 | implemented |
| Data-scope boundary for RAG agents (`policy/examples/rag-agent.yaml`) | Art. 10 data governance | Data protection under ICT risk | A.7.2 data classification | MAP 2, MANAGE 2 | AT 7.2, data classification | implemented at the policy-declaration level; not enforced by a running document store in this repo |
| No TLS payload inspection (documented limitation) | — | — | — | — | — | documented-only limitation, not a control |
| No tool-output sanitisation (documented limitation, non-goal) | — | — | — | — | — | documented-only limitation, not a control |
| Compliance mapping itself (this document) | Art. 12 record-keeping | Regulatory reporting support | A.9 | GOVERN 1, MEASURE 4 | Documentation obligations | documented-only |

Framework references dated: mapping reflects the EU AI Act as generally understood
in 2026, DORA ICT risk management provisions, ISO/IEC 42001:2023 clauses, the NIST
AI RMF 1.0 functions (Govern/Map/Measure/Manage), and German BAIT/MaRisk IT
security requirements (AT 4.3, AT 7.2, AT 8) as commonly cited for third-party/IT
risk. This is not a legal opinion and has not been reviewed by counsel or an
auditor — treat it as an engineering starting point for a real compliance
exercise, not as evidence of compliance.
