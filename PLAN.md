# PLAN.md

## Repo
- Name: `SASE-SDWAN`
- Vertical: `Core Platform`
- Core language: `Rust`
- Benchmark targets: `Atlassian, ServiceNow`

## Audit Summary (2026-02-20)
- Pulsar references found: `0`
- Quickwit references found: `0`
- REST/polling indicators found: `84`

## Engineering Plan
1. Standardize event boundaries on Apache Pulsar topics and remove high-frequency REST polling paths.
2. Standardize observability through Quickwit with a shared log schema and index strategy.
3. Align Kubernetes manifests for Harvester HCI with Mayastor/Vitastor compatible storage classes.
4. Add compliance and API contracts as code artifacts.

## Tech Stack Evolution
- Recommendation: Current core stack acceptable; prioritize Pulsar-native async boundaries and Quickwit ingestion.

## Autonomous Feature Expansion
- Proposed capability: Cross-domain policy orchestration with event-sourced audit graph

## Figma Make Prompt
Task:
Build a premium enterprise dashboard for this repository with real-time Pulsar health and Quickwit global search.
Output:
Desktop + mobile-ready information architecture and component specification in Figma Make TOKEN format.
Key Elements:
Tenant-aware navigation, live event stream indicators, compliance evidence timeline, global search with filters.
Expected Behaviors:
Low-latency updates, resilient loading states, actionable alerts, and audit-first interactions.
Notable Constraints:
Use the repository's actual domain model, preserve existing design language, and keep performance-first rendering.

## Phase 2 Sovereign Execution

### Deep Audit Findings
- Risk score: 200 (high)
- Polling refs: 138
- N+1 refs: 6
- Sync IO refs: 26
- CPU hot refs: 30

### Tech Stack Evolution
- Proposed best stack: Optimize existing stack with OTel + Pulsar + Quickwit contracts
- Build baseline command: `manual`
- Benchmark baseline command: `manual profile`

### X+1 Feature Expansion
- Tenant-aware autonomous operations assistant with policy recommendations

### Quality Gate Upgrades
1. Enforce perf profile execution in CI (`scripts/perf/profile.sh`).
2. Add language-appropriate security/dependency checks in CI.
3. Maintain docs-as-code synchronization and architecture drift checks.

### Rollout Strategy
1. Optimize top hotspots without API/event contract breaks.
2. Stage migration for only critical high-concurrency paths first.
3. Validate via benchmark deltas and rollback-safe deploys.

