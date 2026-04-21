import os
from dotenv import load_dotenv
from openai import OpenAI

from app.utils.prompt_loader import load_prompt

load_dotenv()


def analyze_alert(alert: dict) -> str:
    api_key = os.getenv("OPENAI_API_KEY")

    if not api_key:
        return "IA não configurada (sem API KEY)"

    client = OpenAI(api_key=api_key)
    prompt_base = load_prompt("prompts/alert_analysis.txt")

    full_prompt = f"{prompt_base}\n\nAlerta:\n{alert}"

    try:
        response = client.responses.create(
            model="gpt-4.1-mini",
            input=full_prompt
        )
        return response.output[0].content[0].text

    except Exception as e:
        return f"Erro ao analisar alerta: {str(e)}"


def analyze_incident(incident: dict) -> str:
    api_key = os.getenv("OPENAI_API_KEY")

    if not api_key:
        return "IA não configurada (sem API KEY)"

    client = OpenAI(api_key=api_key)
    prompt_base = load_prompt("prompts/incident_analysis.txt")

    full_prompt = f"{prompt_base}\n\nIncidente:\n{incident}"

    try:
        response = client.responses.create(
            model="gpt-4.1-mini",
            input=full_prompt
        )
        return response.output[0].content[0].text

    except Exception as e:
        return f"Erro ao analisar incidente: {str(e)}"