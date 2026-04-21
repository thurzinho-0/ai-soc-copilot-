<img width="886" height="445" alt="image" src="https://github.com/user-attachments/assets/fd1055fe-4e46-4dba-89fc-686961ae3635" />

## 📚 Objetivo

Criei este projeto com o objetivo de evoluir meus conhecimentos em Segurança da Informação, utilizando IA na análise de alertas e detecção de ameaças.

Montei grande parte da solução com o apoio de um agente de IA que configurei, o que me proporcionou uma base muito sólida em desenvolvimento com APIs e automação.

Durante aproximadamente 9 horas de desenvolvimento, consegui aprender bastante sobre:

- Integração com APIs  
- Análise de eventos de segurança  
- Lógica de detecção (Blue Team)  
- Uso de IA para suporte à decisão em SOC  

Esse projeto foi muito importante para o meu crescimento técnico e me ajudou a me destacar, mostrando na prática como é possível construir soluções reais de segurança com apoio de IA.

Recomendo fortemente que outros profissionais e iniciantes pratiquem com IA em cenários de SOC — o aprendizado é rápido e muito prático.

# 🔵 AI SOC Copilot

Ferramenta de análise de alertas de segurança com IA + heurística, simulando um Security Operations Center (SOC).

---

## 🚀 Funcionalidades

- 🔍 Análise de alertas com IA (OpenAI)
- ⚠️ Detecção de ataques:
  - Brute Force (T1110)
  - Valid Accounts (T1078)
  - PowerShell Execution (T1059.001)
  - SQL Injection (T1190)
- 🔗 Correlação de eventos (SIEM-like)
- 🧠 Geração de playbooks (SOAR)
- 📊 Dashboard Web interativo

---

## 🧠 Arquitetura

Dashboard (Flask)
↓
API (FastAPI)
↓
Risk Engine + IA
↓
Detecção + Resposta


---

## 🛠️ Stack

- Python
- FastAPI (backend)
- Flask (dashboard)
- OpenAI API
- JavaScript (frontend)

---

## 🛡️ Detecção (MITRE ATT&CK)

- T1110 – Brute Force  
- T1078 – Valid Accounts  
- T1059.001 – PowerShell  
- T1190 – Exploit Public-Facing Application  
- T1082 – System Discovery  
- T1087 – Account Discovery  

---

## ▶️ Como rodar

```bash
# criar ambiente
python -m venv venv

# ativar (Windows)
venv\Scripts\activate

# instalar dependências
pip install -r requirements.txt

# rodar backend
python -m uvicorn main:app --reload

python app/dashboard/app.py

Exemplos de detecção

🔴 Brute Force + acesso
múltiplas falhas + login bem-sucedido
possível comprometimento de conta
🟠 PowerShell encoded
execução suspeita com base64
possível evasão
🔴 SQL Injection
payload malicioso detectado
tentativa de exploração web
