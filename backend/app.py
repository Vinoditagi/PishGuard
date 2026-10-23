from flask import Flask, request, jsonify
from flask_cors import CORS
from urllib.parse import urlparse
import re
import ipaddress

app = Flask(__name__)
CORS(app)

# ============================================================
# PISHGUARD: RULE-BASED SCAM AND PHISHING DETECTION
# These rules identify risk indicators, not guaranteed scams.
# ============================================================

# Each phrase contributes to the risk score.
# Similar phrases are grouped into categories below to prevent
# excessive scoring from many variations of the same warning sign.

SUSPICIOUS_PHRASES = {
    # Account and identity security
    "verify your account": 20,
    "verify your identity": 20,
    "verify immediately": 20,
    "account suspended": 25,
    "account blocked": 25,
    "account will be blocked": 25,
    "account will be suspended": 25,
    "confirm your identity": 20,
    "update your bank details": 25,
    "login immediately": 20,
    "reset your password": 15,
    "unusual activity": 15,
    "unauthorized login": 20,

    # OTP and confidential information
    "send your otp": 30,
    "share your otp": 30,
    "enter your otp": 25,
    "otp verification": 15,
    "share your password": 35,
    "send your password": 35,
    "share your pin": 35,
    "provide your card details": 30,
    "bank details": 15,
    "credit card details": 20,
    "debit card details": 20,

    # Suspicious links and calls to action
    "click here": 10,
    "click this link": 15,
    "click the link": 15,
    "open this link": 10,
    "tap here": 10,
    "visit this link": 10,
    "verify through this link": 20,
    "login through this link": 20,

    # Rewards and prizes
    "claim your reward": 20,
    "claim your prize": 20,
    "claim now": 10,
    "free money": 20,
    "won a prize": 20,
    "you have won": 15,
    "you won": 15,
    "lottery winner": 25,
    "lucky winner": 15,
    "cashback": 5,
    "free gift": 10,
    "prize money": 15,
    "reward points": 5,

    # Urgency and threats
    "urgent action required": 20,
    "act immediately": 15,
    "immediate action": 15,
    "limited time": 10,
    "offer expires today": 15,
    "last chance": 10,
    "within 24 hours": 10,
    "avoid account closure": 20,
    "final warning": 15,

    # Payments and fees
    "send money": 15,
    "pay a fee": 15,
    "processing fee": 15,
    "registration fee": 20,
    "security deposit": 20,
    "advance payment": 20,
    "pay now": 15,
    "transfer money": 15,
    "refundable fee": 15,
    "pay to receive": 20,
    "payment failed": 10,

    # Job and employment scams
    "work from home": 10,
    "work-from-home": 10,
    "job offer": 10,
    "you got the job": 15,
    "you have got a job": 15,
    "you have been selected": 10,
    "selected for a job": 15,
    "selected for the job": 15,
    "job opportunity": 10,
    "part time job": 10,
    "part-time job": 10,
    "online job": 10,
    "remote job": 10,
    "earn money from home": 15,
    "earn from home": 10,
    "daily income": 10,
    "guaranteed income": 15,
    "no experience required": 5,
    "job confirmation": 10,
    "confirm your position": 15,
    "accept your offer": 10,
    "claim your offer": 15,
    "interview fee": 25,
    "job placement fee": 25,
    "training fee": 15,
    "recruitment fee": 15,
    "salary advance": 10,
    "instant hiring": 10,

    # Parcel and delivery scams
    "parcel is on hold": 15,
    "package is on hold": 15,
    "delivery failed": 10,
    "pay to release": 20,
    "customs fee": 10,
    "delivery fee": 10,
    "track your parcel": 5,

    # Investment and financial scams
    "guaranteed returns": 25,
    "double your money": 25,
    "risk free investment": 20,
    "risk-free investment": 20,
    "investment opportunity": 10,
    "make profit": 10,
    "daily profit": 15,
    "crypto investment": 10,
    "act as an investor": 10,

    # Impersonation and support
    "customer support": 5,
    "your account has a problem": 15,
    "government grant": 10,
    "government subsidy": 10,
    "verify your kyc": 20,
    "kyc update": 15,
    "electricity connection will be disconnected": 25,
    "sim card will be blocked": 20,
}

SHORTENED_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "is.gd",
    "cutt.ly",
    "rb.gy",
    "shorturl.at",
    "rebrand.ly",
    "ow.ly",
    "buff.ly",
    "soo.gd",
}

SUSPICIOUS_URL_PATTERNS = [
    "login-verify",
    "secure-account",
    "account-verification",
    "free-gift",
    "claim-prize",
    "verify-account",
    "update-kyc",
    "confirm-password",
    "banking-verify",
]


def contains_phrase(text, phrase):
    """
    Match a phrase without accidentally matching it inside
    a larger word. Whitespace in phrases can match multiple spaces.
    """
    escaped = re.escape(phrase)
    escaped = escaped.replace(r"\ ", r"\s+")

    pattern = r"(?<!\w)" + escaped + r"(?!\w)"
    return re.search(pattern, text, flags=re.IGNORECASE) is not None


def check_url(url):
    reasons = []
    suspicious = False

    if not url:
        return suspicious, reasons

    candidate = url.strip()

    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", candidate):
        candidate = "https://" + candidate

    try:
        parsed = urlparse(candidate)
        domain = (parsed.hostname or "").lower()

        if not domain or "." not in domain:
            suspicious = True
            reasons.append("The URL has an unusual or invalid domain.")

        if parsed.username is not None or parsed.password is not None:
            suspicious = True
            reasons.append("The URL contains embedded login information.")

        if domain:
            try:
                ipaddress.ip_address(domain)
                suspicious = True
                reasons.append(
                    "The URL uses an IP address instead of a domain name."
                )
            except ValueError:
                pass

            if domain in SHORTENED_DOMAINS:
                suspicious = True
                reasons.append(
                    "The URL uses a link-shortening service. "
                    "Its final destination should be checked."
                )

        full_url = candidate.lower()

        if any(pattern in full_url for pattern in SUSPICIOUS_URL_PATTERNS):
            suspicious = True
            reasons.append(
                "The URL contains a suspicious-looking pattern."
            )

        if parsed.scheme.lower() not in ("http", "https"):
            suspicious = True
            reasons.append("The URL uses an unusual protocol.")

    except (ValueError, UnicodeError):
        suspicious = True
        reasons.append("The URL could not be parsed correctly.")

    return suspicious, reasons


def analyze_message(message):
    """
    Identify risk indicators using phrase rules and combinations
    of related indicators. This is not a trained ML model.
    """
    text = message.lower()
    matched_phrases = []
    score = 0

    for phrase, weight in SUSPICIOUS_PHRASES.items():
        if contains_phrase(text, phrase):
            matched_phrases.append(phrase)
            score += weight

    # Extra context for employment-related messages.
    job_terms = [
        "job", "employment", "hiring", "recruitment",
        "work from home", "work-from-home",
        "part time", "part-time", "salary", "vacancy"
    ]

    job_context = any(term in text for term in job_terms)

    payment_terms = [
        "registration fee", "processing fee", "security deposit",
        "advance payment", "interview fee", "job placement fee",
        "training fee", "recruitment fee", "pay a fee",
        "pay now", "send money", "transfer money", "refundable fee"
    ]

    payment_context = any(term in text for term in payment_terms)

    link_context = bool(
        re.search(
            r"https?://|www\.|click\s+(?:here|this|the link)|"
            r"open\s+this\s+link|tap\s+here|"
            r"visit\s+this\s+link|claim\s+your\s+offer",
            text
        )
    )

    urgency_context = any(
        term in text
        for term in [
            "immediately", "right now", "urgent",
            "within 24 hours", "today only", "act now",
            "limited time", "last chance"
        ]
    )

    # A job offer asking for money is a strong warning sign.
    if job_context and payment_context:
        score += 25
        matched_phrases.append(
            "job-related message requesting payment"
        )

    # An unexpected job message directing a user to a link
    # deserves further review, but is not automatically a scam.
    if job_context and link_context:
        score += 10
        matched_phrases.append(
            "job-related message directing the recipient to a link"
        )

    # Payment pressure or urgency can make a request more concerning.
    if payment_context and urgency_context:
        score += 10
        matched_phrases.append(
            "payment request combined with urgency"
        )

    # Requests for credentials or OTPs are especially concerning.
    credential_terms = [
        "otp", "one-time password", "one time password",
        "password", "bank details", "card details",
        "pin", "cvv"
    ]

    credential_request_terms = [
        "share", "send", "provide", "enter",
        "tell me", "give me", "submit"
    ]

    if (
        any(term in text for term in credential_terms)
        and any(term in text for term in credential_request_terms)
    ):
        score += 20
        matched_phrases.append(
            "request to provide sensitive information"
        )

    # Multiple independent warning signs increase risk.
    if len(set(matched_phrases)) >= 3:
        score += 10

    # Prevent scores above 100.
    return min(score, 100), list(dict.fromkeys(matched_phrases))


@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "status": "success",
        "message": "PishGuard AI backend is running."
    })


@app.route("/api/detect", methods=["POST"])
def detect_scam():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({
            "error": "Please send valid JSON data."
        }), 400

    message = str(data.get("message") or "").strip()
    url = str(data.get("url") or "").strip()

    if not message and not url:
        return jsonify({
            "error": "Please enter a message or URL to scan."
        }), 400

    risk_score, matched_phrases = analyze_message(message)

    suspicious_url, url_reasons = check_url(url)

    # Add URL risk separately.
    if suspicious_url:
        risk_score = min(risk_score + 25, 100)

    if len(url_reasons) >= 2:
        risk_score = min(risk_score + 10, 100)

    # Classification thresholds.
    if risk_score >= 50:
        result = "Suspicious"
        risk_level = "High"
    elif risk_score >= 25:
        result = "Review Carefully"
        risk_level = "Medium"
    else:
        result = "No obvious scam signs detected"
        risk_level = "Low"

    is_suspicious = risk_score >= 25

    reasons = []

    if matched_phrases:
        reasons.append(
            "Potential warning signs detected: "
            + ", ".join(matched_phrases)
            + "."
        )

    reasons.extend(url_reasons)

    if not reasons:
        reasons.append(
            "No known suspicious phrases or URL patterns were detected. "
            "This does not guarantee that the message is safe."
        )

    return jsonify({
        "message": message,
        "url": url,
        "result": result,
        "is_suspicious": is_suspicious,
        "risk_level": risk_level,
        "reasons": reasons,
        "spam_probability": risk_score,
        "score_type": "rule_based_risk_score",
        "note": (
            "This score is based on predefined message and URL rules. "
            "It is a risk indicator, not a calibrated probability."
        ),
        "safety_note": (
            "Verify unexpected messages independently. Never share "
            "your OTP, PIN, password, or banking details with others."
        )
    })


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5001,
        debug=False
    )