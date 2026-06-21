---
name: report-generation
description: >
  Generate the final incident report in Markdown, JSON, plain text (.txt), and Word (.docx) formats summarizing evidence, findings, actions, and verification.
triggers:
  - report
  - generate report
  - summary report
inputs:
  - incident_id
outputs:
  - markdown_report_path: str
  - json_report_path: str
  - text_report_path: str
  - docx_report_path: str
safety: read-only
---

# Report Generation Skill

## Purpose
Assemble all incident facts, actions, and verification metrics into structured files for compliance, historical tracking, and downstream consumption (SIEM, ops handoff, executive review).

## Output Formats
| Format | File             | Purpose                                          |
|--------|------------------|--------------------------------------------------|
| JSON   | `<id>.json`      | Machine-readable structured artefact             |
| Markdown | `<id>.md`      | Human-readable technical narrative               |
| Plain text | `<id>.txt`   | Plain-text fallback (log-friendly, no formatting)|
| Word   | `<id>.docx`      | Formatted document for review/print/hand-off     |

All four files are produced from the same incident state in one invocation so
the artefacts stay in lock-step. The Markdown content is the source of truth —
JSON / TXT / DOCX are derived from it (JSON re-parses the structured fields;
TXT strips Markdown; DOCX renders headings/paragraphs via python-docx).
