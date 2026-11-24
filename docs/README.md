# ntod-scan documentation

| Document | Audience | Contents |
|---|---|---|
| [BRD.md](BRD.md) | Stakeholders, decision-makers | Business case, objectives, MoSCoW requirements, KPIs, risks |
| [PRD.md](PRD.md) | Product, engineering | Vision, personas, numbered user stories, acceptance criteria |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Engineers | Crate topology, runtime models, data flows, concurrency, bounds, security model |
| [SDD.md](SDD.md) | Engineers | Component design, data models, state management, error handling |
| [TSD.md](TSD.md) | Engineers, integrators | Library APIs, REST/WS specs, CLI grammar, testing, build notes |

Related, outside this directory:

- [../DESIGN.md](../DESIGN.md) — design system (shared with ntok-scan; ntod deltas only)
- [../AGENTS.md](../AGENTS.md) — agent/contributor conventions, verify commands
- [../CONTRIBUTING.md](../CONTRIBUTING.md) — how to contribute, layout rules
- [../SECURITY.md](../SECURITY.md) — responsible use and vulnerability reporting

Reading order for a newcomer: [../README.md](../README.md) →
ARCHITECTURE → SDD → TSD. Decision-makers can stop at BRD + PRD.
