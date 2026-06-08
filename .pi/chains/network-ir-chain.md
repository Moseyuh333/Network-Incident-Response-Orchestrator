---
name: network-ir-chain
description: Alert-triggered chain for Topic 09 Network Incident Response Orchestrator.
---

alert -> parallel(recon, logs, pcap_features) -> parallel(classify, embedding_score)
-> mitre_mapping -> containment_plan -> structured_ir_report
