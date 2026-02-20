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
