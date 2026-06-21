---
name: report-generation
description: >
  Generate the final incident report in Markdown, JSON, plain text (.txt), Word (.docx), and PDF formats summarizing evidence, findings, actions, and verification.
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
  - pdf_report_path: str
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
| PDF    | `<id>.pdf`       | Universal document for print, email, archival    |

All five files are produced from the same incident state in one invocation so
the artefacts stay in lock-step. The Markdown content is the source of truth —
JSON / TXT / DOCX / PDF are derived from it (JSON re-parses the structured
fields; TXT strips Markdown; DOCX renders headings/paragraphs via python-docx;
PDF renders via reportlab with the same field layout).

The ``.docx`` and ``.pdf`` outputs are best-effort: if the corresponding
library is missing the other formats are still produced and a non-fatal
warning is logged.
