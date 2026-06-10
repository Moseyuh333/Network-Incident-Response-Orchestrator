---
name: report-generation
description: >
  Generate the final incident report (Markdown and JSON formats) summarizing evidence, findings, actions, and verification.
triggers:
  - report
  - generate report
  - summary report
inputs:
  - incident_id
outputs:
  - markdown_report_path: str
  - json_report_path: str
safety: read-only
---

# Report Generation Skill

## Purpose
Assemble all incident facts, actions, and verification metrics into structured files for compliance and historical tracking.
