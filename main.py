from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel
import requests
import re

app = FastAPI(title="Honeypot Scam Detection API", version="1.0")

API_KEY = "honeypot_0524"

# ------------------ Models ------------------

class Message(BaseModel):
    sender: str
    text: str
    timestamp: int

class HoneypotRequest(BaseModel):
    sessionId: str
    message: Message
    conversationHistory: list = []
    metadata: dict = {}

# ------------------ Utils ------------------

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
        "bankAccounts": bank_accounts,
        "upiIds": upi_ids,
        "phishingLinks": phishing_links,
        "phoneNumbers": [],
        "suspiciousKeywords": ["bank", "verify", "urgent"]
    }

def send_final_callback(session_id, intelligence, total_messages):
    payload = {
        "sessionId": session_id,
        "scamDetected": True,
        "totalMessagesExchanged": total_messages,
        "extractedIntelligence": intelligence,
        "agentNotes": "Scammer used urgency and fake bank threat"
    }

    try:
        requests.post(
            "https://hackathon.guvi.in/api/updateHoneyPotFinalResult",
            json=payload,
            timeout=5
        )
    except:
        pass  # Never block main API

# ------------------ Routes ------------------

@app.get("/")
def root():
    return {"message": "Honeypot API is running"}

@app.post("/")
def honeypot_api(
    data: HoneypotRequest,
    x_api_key: str = Header(None)
):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API Key")

    text = data.message.text
    scam = is_scam_message(text)

    if scam:
        reply = "Why is my account being suspended?"

        intelligence = extract_intelligence(text)
        total_messages = len(data.conversationHistory) + 1

        # Fire & forget callback
        send_final_callback(
            data.sessionId,
            intelligence,
            total_messages
        )
    else:
        reply = "Okay, please continue."

    # EXACT response format required by hackathon
    return {
        "status": "success",
        "reply": reply
    }
