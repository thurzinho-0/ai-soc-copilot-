def generate_playbook(incident: dict) -> dict:
    incident_type = incident.get("type", "").lower()
    severity = incident.get("severity", "medium")

    actions = []
    containment = []
    recovery = []

    if "account compromise" in incident_type:
        actions = [
            "Validar origem dos eventos de autenticação",
            "Confirmar se a conta impactada possui privilégios elevados",
            "Revisar a linha do tempo de autenticação e execução"
        ]
        containment = [
            "Resetar a senha da conta afetada",
            "Revogar sessões ativas",
            "Bloquear execução de PowerShell codificado no host afetado"
        ]
        recovery = [
            "Revisar persistência no host",
            "Executar varredura antimalware/EDR",
            "Revalidar políticas de MFA"
        ]

    else:
        actions = [
            "Validar contexto do incidente",
            "Coletar evidências adicionais",
            "Classificar impacto e escopo"
        ]
        containment = [
            "Aplicar contenção proporcional ao risco"
        ]
        recovery = [
            "Monitorar recorrência",
            "Documentar lições aprendidas"
        ]

    return {
        "severity": severity,
        "actions": actions,
        "containment": containment,
        "recovery": recovery
    }