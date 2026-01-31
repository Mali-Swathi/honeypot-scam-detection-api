from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel
import re

app = FastAPI(title="Honeypot Scam Detection API", version="1.0")

API_KEY = "honeypot_0524"

class HoneypotRequest(BaseModel):
    message: str
    conversation_id: str | None = None

def is_scam_message(message: str):
    scam_keywords = [
        "kyc", "otp", "account blocked", "urgent",
        "click", "verify", "bank", "upi"
    ]
    message_lower = message.lower()
    return any(word in message_lower for word in scam_keywords)

def extract_intelligence(text: str):
    bank_accounts = re.findall(r"\b\d{9,18}\b", text)
    upi_ids = re.findall(r"\b[\w.-]+@[\w.-]+\b", text)
    phishing_links = re.findall(r"https?://\S+", text)
    return {
        "bank_accounts": bank_accounts,
        "upi_ids": upi_ids,
        "phishing_links": phishing_links
    }

def agent_reply():
    return "I am not good with phones. Can you explain again?"

@app.get("/")
def root():
    return {"message": "Honeypot API is running. Use POST /honeypot with API key."}

@app.post("/honeypot")
def honeypot_api(
    data: HoneypotRequest,
    x_api_key: str = Header(None)
):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API Key")

    scam = is_scam_message(data.message)
    extracted_data = extract_intelligence(data.message)

    response = {
        "is_scam": scam,
        "risk_score": 0.9 if scam else 0.1,
        "persona_used": "Elderly User",
        "agent_reply": agent_reply() if scam else "Thank you.",
        "extracted_data": extracted_data
    }

    return response
