def calculate_risk(alert: dict) -> dict:
    score = 0
    reasons = []

    severity = (alert.get("severity") or "").lower()
    title = (alert.get("title") or "").lower()
    raw_log = (alert.get("raw_log") or "").lower()
    description = (alert.get("description") or "").lower()
    event_type = (alert.get("event_type") or "").lower()
    mitre = alert.get("mitre_technique")
    source = (alert.get("source") or "").lower()
    user = (alert.get("user") or "").lower()

    full_text = f"{title} {description} {raw_log} {event_type} {source} {user}"

    # Severidade base
    if severity == "low":
        score += 10
        reasons.append("Severidade baixa")
    elif severity == "medium":
        score += 30
        reasons.append("Severidade média")
    elif severity == "high":
        score += 60
        reasons.append("Severidade alta")
    elif severity == "critical":
        score += 90
        reasons.append("Severidade crítica")

    # PowerShell / execução
    if "powershell" in full_text:
        score += 20
        reasons.append("Uso de PowerShell")

    if "-enc" in raw_log or " -enc " in full_text:
        score += 30
        reasons.append("PowerShell codificado (Base64)")

    # Directory Traversal / LFI
    if "../" in raw_log or "..\\" in raw_log:
        score += 35
        reasons.append("Indicador de path traversal")

    if "/etc/passwd" in raw_log or "win.ini" in raw_log:
        score += 25
        reasons.append("Tentativa de acesso a arquivo sensível")

    # Exposição .git
    if ".git/config" in raw_log:
        score += 35
        reasons.append("Acesso a arquivo sensível .git/config")

    # SQL Injection
    sqli_patterns = [
        "' or '1'='1",
        "\" or \"1\"=\"1",
        "union select",
        "sqlmap",
        "sleep(",
        "benchmark(",
        "information_schema",
    ]
    if any(p in raw_log for p in sqli_patterns):
        score += 35
        reasons.append("Indicador de SQL Injection")

    # Ferramentas suspeitas
    if "curl/" in raw_log or "sqlmap" in raw_log or "python-requests" in raw_log:
        score += 10
        reasons.append("User-Agent/ferramenta suspeita")

    # Evento web
    if event_type == "web_request":
        score += 10
        reasons.append("Evento de aplicação web")

    # ── AUTENTICAÇÃO / BRUTE FORCE ─────────────────────

    failed_login_patterns = [
        "failed password",
        "authentication failure",
        "invalid user",
        "failed_login",
        "login failed",
    ]
    success_login_patterns = [
        "accepted password",
        "login successful",
        "successful_login",
        "session opened",
    ]

    if any(p in full_text for p in failed_login_patterns):
        score += 20
        reasons.append("Falha de autenticação detectada")

    if any(p in full_text for p in success_login_patterns):
        score += 20
        reasons.append("Login bem-sucedido detectado")

    # Se o texto tiver falha + sucesso, assume possível brute force seguido de acesso
    if (
        any(p in full_text for p in failed_login_patterns)
        and any(p in full_text for p in success_login_patterns)
    ):
        score += 40
        reasons.append("Possível brute force seguido de sucesso")

    # Conta privilegiada
    privileged_users = ["admin", "administrator", "root", "domain admin", "adm"]
    if any(pu in full_text for pu in privileged_users):
        score += 20
        reasons.append("Conta privilegiada envolvida")

    # Comandos de enumeração / recon local
    recon_cmds = [
        "whoami",
        "ipconfig",
        "net user",
        "nltest",
        "quser",
        "tasklist",
        "systeminfo",
    ]
    if any(cmd in raw_log for cmd in recon_cmds):
        score += 15
        reasons.append("Possível enumeração de sistema")

    # Port scan / reconhecimento
    if "port scan" in full_text or "multiple connection attempts" in full_text:
        score += 20
        reasons.append("Possível varredura de portas")

    # MITRE informado
    if mitre:
        score += 10
        reasons.append(f"Técnica MITRE informada: {mitre}")

    # Limite superior para evitar score absurdo
    score = min(score, 100)

    # Classificação final
    if score >= 90:
        level = "Crítico"
        classification = "True Positive provável"
    elif score >= 70:
        level = "Alto"
        classification = "True Positive provável"
    elif score >= 40:
        level = "Médio"
        classification = "Inconclusivo"
    else:
        level = "Baixo"
        classification = "Possível False Positive"

    return {
        "score": score,
        "risk_level": level,
        "classification": classification,
        "reasons": reasons
    }