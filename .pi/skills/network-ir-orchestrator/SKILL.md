---
name: network-ir-orchestrator
description: Runs a defensive network incident response pipeline with parallel collection, ML-style classification, MITRE mapping, and containment reporting.
---

## Workflow

1. Normalize the alert.
2. Run recon, log collection, and PCAP feature extraction in parallel.
3. Run incident classification and embedding-style profile scoring in parallel.
4. Map the incident to MITRE ATT&CK.
5. Produce JSON, Markdown, DOCX, and ZIP artifacts for submission.
