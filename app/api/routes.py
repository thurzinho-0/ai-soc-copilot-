from fastapi import APIRouter
from app.models.alert_model import AlertInput
from app.models.event_model import EventBatchInput
from app.ai.llm_client import analyze_alert, analyze_incident
from app.context.risk_engine import calculate_risk
from app.correlation.correlator import correlate_events
from app.soar.playbook_engine import generate_playbook

router = APIRouter()


@router.get("/")
def home():
    return {"status": "SOC Copilot online"}


@router.post("/analyze")
def analyze(data: AlertInput):
    alert = data.model_dump()
    risk = calculate_risk(alert)
    ai_analysis = analyze_alert(alert)

    risk_class = (risk.get("classification") or "").lower()
    ai_text = (ai_analysis or "").lower()

    decision_conflict = False
    final_decision = risk.get("classification", "Inconclusivo")

    if "true positive" in ai_text and "false positive" in risk_class:
        decision_conflict = True
        final_decision = "Revisão manual recomendada"

    elif "false positive" in ai_text and "true positive" in risk_class:
        decision_conflict = True
        final_decision = "Revisão manual recomendada"

    elif "true positive" in ai_text:
        final_decision = "True Positive provável"

    elif "false positive" in ai_text:
        final_decision = "Possível False Positive"

    return {
        "risk_analysis": risk,
        "ai_analysis": ai_analysis,
        "decision_conflict": decision_conflict,
        "final_decision": final_decision
    }


@router.post("/correlate")
def correlate(data: EventBatchInput):
    events = [event.model_dump() for event in data.events]
    incidents = correlate_events(events)

    enriched_incidents = []
    for incident in incidents:
        playbook = generate_playbook(incident)
        incident_analysis = analyze_incident(incident)

        enriched_incidents.append({
            **incident,
            "playbook": playbook,
            "incident_analysis": incident_analysis
        })

    return {
        "incident_count": len(enriched_incidents),
        "incidents": enriched_incidents
    }