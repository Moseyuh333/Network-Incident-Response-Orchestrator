"""Run the N.I.R.O. incident response agent loop on a specific incident."""

from __future__ import annotations

import argparse
from sqlmodel import Session, select
from app.db.session import engine
from app.models.incident import Incident
from app.services.agent_runs import run_agent_for_incident
from app.core.paths import PI_DIR


def main() -> None:
    parser = argparse.ArgumentParser(description="Run N.I.R.O. agent loop on an incident.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--latest", action="store_true", help="Run on the latest incident")
    group.add_argument("--incident", help="Public ID of the incident to run on (e.g. INC-000001)")
    args = parser.parse_args()

    with Session(engine) as session:
        if args.latest:
            statement = select(Incident).order_by(Incident.id.desc()).limit(1)
            incident = session.exec(statement).first()
            if not incident:
                print("[-] No incidents found in the database. Load a scenario first.")
                return
        else:
            statement = select(Incident).where(Incident.public_id == args.incident)
            incident = session.exec(statement).first()
            if not incident:
                print(f"[-] Incident {args.incident} not found in the database.")
                return

        print(f"[*] Running agent on Incident {incident.public_id} (ID: {incident.id})...")
        print(f"    Type: {incident.incident_type}")
        print(f"    Severity: {incident.severity}")

        task = "Analyze this incident and recommend safe response actions."
        
        try:
            agent_run = run_agent_for_incident(session, incident.id, task, PI_DIR)
            print(f"[+] Agent run completed successfully. Run ID: {agent_run.id}")
            print(f"    Provider: {agent_run.provider}")
            print(f"    Model: {agent_run.model}")
            print(f"    Status: {agent_run.status}")
            
            # Refresh incident state
            session.refresh(incident)
            print("\n[+] Incident Details:")
            print(f"    LLM Summary: {incident.llm_summary}")
            print(f"    MITRE Mapping: {incident.mitre_mapping}")
            print(f"    Recommended Actions: {incident.recommended_actions}")
        except Exception as e:
            print(f"[-] Failed to run agent: {e}")


if __name__ == "__main__":
    main()
