def correlate_events(events: list) -> list:
    incidents = []

    for i in range(len(events)):
        sequence = []
        current = events[i]

        if current.get("event_type") == "failed_login":
            sequence.append(current)

            found_success = False
            found_execution = False

            for j in range(i + 1, len(events)):
                next_event = events[j]

                if next_event.get("event_type") == "successful_login":
                    sequence.append(next_event)
                    found_success = True
                    continue

                if found_success and next_event.get("event_type") == "process_creation":
                    raw = (next_event.get("raw_log") or "").lower()
                    if "powershell" in raw:
                        sequence.append(next_event)
                        found_execution = True

                if found_success and found_execution:
                    incidents.append({
                        "type": "Possible Account Compromise + Execution",
                        "severity": "high",
                        "mitre_chain": ["T1110", "T1078", "T1059.001"],
                        "event_count": len(sequence),
                        "events": sequence
                    })
                    break

    return incidents