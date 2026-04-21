from app.correlation.correlator import correlate_events

test_events = [
    {"event_type": "failed_login", "user": "admin"},
    {"event_type": "successful_login", "user": "admin"},
    {"event_type": "process_creation", "raw_log": "powershell -enc abc"}
]

incidents = correlate_events(test_events)

print("\n🚨 INCIDENTES DETECTADOS:\n")
print(incidents)