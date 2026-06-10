# UI / UX Design Specification

This document details the visual design system, layouts, and interactive components of the **Network Incident Response Operations (N.I.R.O.)** console.

---

## 1. Visual Brand adaptation

Inspired by cybersecurity command centers, N.I.R.O. utilizes a cyber-tactical dark design focusing on data-density, minimal spacing, and readability:
- **Product Branding**: `[ N.I.R.O. ] - NETWORK INCIDENT RESPONSE OPERATIONS`
- **Theme**: 100% Dark Mode. Glowing red elements are restricted to critical alerts, failed actions, and items awaiting operator approval.

---

## 2. Color System

- **Background Layer 1**: `#0A0B0E` (Deep black-grey)
- **Background Layer 2**: `#161B22` (Panel dark grey)
- **Borders**: `#30363D` (Medium slate border)
- **Primary Alert / Danger**: `#E53935` / `#FF3333` (Restrained neon-red)
- **Success / Live**: `#00FF41` (Terminal green)
- **Warning**: `#FFB300` (Amber)
- **Informational**: `#58A6FF` (Terminal blue)
- **Primary Text**: `#E6EDF3` (Off-white)
- **Secondary Text**: `#8B949E` (Muted grey)

---

## 3. Operations Layout (Three-Column Design)

The primary Operations view uses a strict three-column layout split as follows:

```
+------------------+------------------------------+--------------------+
|   Left Panel     |         Center Panel         |    Right Panel     |
|     (25%)        |            (45%)             |       (30%)        |
|                  |                              |                    |
| - Case Selection | - Cytoscape.js Node Graph    | - Live Terminal    |
| - Incident Locks | - Assets & IPs Relationship  |   Stream           |
| - Agent Dispatch | - Interactive Zoom & Pan     | - Entity Summaries |
| - Rules of       | - Status Indicators          | - Action Queue     |
|   Engagement     | - Expandable nodes           | - PDF / JSON       |
| - Pipeline Queue |                              |   Export controls  |
+------------------+------------------------------+--------------------+
```

---

## 4. Routed Views

The client utilizes frontend routing for the following pages:
- `/operations`: The three-column command console.
- `/incidents`: Detailed list of historical incidents and state transitions.
- `/events`: Filterable table of raw ingested events.
- `/approvals`: List of pending, executed, and rolled back containment actions.
- `/agents`: Agent profiles loaded from `.pi/agents/*.md`.
- `/skills`: Pi skills frontmatter editor and validator.
- `/extensions`: TypeScript extensions listing and compiler metrics.
- `/chains`: YAML DAG visualizer.
- `/models`: ML Model parameters, scaling features, and version metadata.
- `/settings`: Global configurations (log levels, database URL, timeouts).
- `/audit`: Live audit logs query page.

---

## 5. Micro-Animations

- **Live Pulse**: The green live status indicator pulses while the SSE client stream is connected.
- **Node Pop-in**: Newly ingested nodes scale from 0 to 1 and emit a short ripple animation on the canvas.
- **Typewriter Effect**: Applied to newly streaming terminal messages and new findings.
- **Glitch Hover**: Adds a subtle glitch offset to primary lock and approval buttons.
