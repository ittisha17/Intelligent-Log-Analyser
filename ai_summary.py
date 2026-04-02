import google.generativeai as genai

genai.configure(api_key="AIzaSyDfNH4SdNWc8oOITJ3EJCKQSG2Q8mYaZW0")

model = genai.GenerativeModel("gemini-pro")

import requests

def check_ip_reputation(ip: str, api_key: str) -> dict:
    resp = requests.get(
        "https://api.abuseipdb.com/api/v2/check",
        headers={"Key": api_key, "Accept": "application/json"},
        params={"ipAddress": ip, "maxAgeInDays": 90}
    )
    data = resp.json()["data"]
    return {"score": data["abuseConfidenceScore"], "country": data["countryCode"]}



def generate_summary(df):
    if df.empty:
        return "No threats detected."

    data = df.to_dict(orient="records")

    prompt = f"""
    You are a senior SOC analyst. Analyze this threat and reason step by step.

    Threat: {threat['type']} from IP {threat['ip']}
   Raw log evidence: {threat['raw_logs'][:5]} 
  Known IP reputation: {abuseipdb_score}/100
   Country of origin: {geo_country}

Step 1 - What is the attacker likely trying to accomplish?
Step 2 - What is the blast radius if this succeeds?
Step 3 - What is your confidence level (low/medium/high) and why?
Step 4 - Immediate remediation (within 1 hour)
Step 5 - Long-term hardening recommendation
"""

    try:
        response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        return f"AI Error: {str(e)}"