
from pathlib import Path
import ipaddress
import re
import sys
from urllib.parse import urlparse

from flask import Flask, request, jsonify
from flask_cors import CORS


# --------------------------------------------------
# 1. PROJECT AND MODEL SETUP
# --------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent.parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from ml.predictor import predict_message
from backend.ai_analyzer import analyze_with_ai


app = Flask(__name__)
CORS(app)

# Prevent excessively large requests.
app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024  # 1 MB


# --------------------------------------------------
# 2. SCAM PHRASE DETECTION
# --------------------------------------------------

SCAM_PATTERNS = [
    # Prize and reward scams
    (
        r"\bcongratulations\b.{0,60}\b(?:won|winner|prize|reward)\b",
        "Prize or reward claim",
    ),
    (r"\byou\s+(?:have\s+)?won\b", "Prize-winning claim"),
    (
        r"\bclaim\s+(?:your\s+)?(?:prize|reward|gift|money)\b",
        "Prize or reward claim",
    ),
    (r"\bclaim\s+now\b", "Urgent claim request"),
    (r"\bfree\s+money\b", "Free-money offer"),

    # OTP and credential theft
    (
        r"\b(?:send|share|tell|give)\s+(?:me\s+)?(?:your\s+)?otp\b",
        "Request to share an OTP",
    ),
    (
        r"\b(?:send|share|tell|give)\s+(?:me\s+)?(?:your\s+)?password\b",
        "Request to share a password",
    ),
    (
        r"\b(?:verify|confirm)\s+your\s+(?:bank\s+)?account\b",
        "Account verification request",
    ),
    (r"\bconfirm\s+your\s+identity\b", "Identity verification request"),
    (
        r"\b(?:account|bank\s+account)\s+(?:will\s+be\s+)?(?:blocked|suspended|closed)\b",
        "Account-blocking threat",
    ),
    (
        r"\b(?:account|card)\s+(?:is\s+)?(?:blocked|suspended)\b",
        "Account-blocking warning",
    ),

    # Job and work-from-home scams
    (r"\bregistration\s+fee\b", "Job or offer registration fee"),
    (r"\b(?:upfront|advance)\s+fee\b", "Upfront payment request"),
    (
        r"\bpay\s+(?:a|the)\s+(?:registration\s+)?fee\b",
        "Request for an upfront fee",
    ),
    (
        r"\bpay\s+to\s+(?:get|secure|start)\s+(?:a\s+)?job\b",
        "Payment requested for a job",
    ),
    (
        r"\bjob\s+offer\b.{0,60}\bfee\b",
        "Job offer involving a fee",
    ),
    (
        r"\bearn\s+money\s+from\s+home\b",
        "Work-from-home earning claim",
    ),
    (
        r"\bguaranteed\s+(?:income|earnings|returns)\b",
        "Guaranteed income claim",
    ),

    # Payment and pressure tactics
    (
        r"\b(?:send|transfer|pay)\s+(?:the\s+)?money\s+(?:now|immediately|urgently)\b",
        "Urgent money transfer request",
    ),
    (r"\blimited\s+time\s+offer\b", "Limited-time pressure tactic"),
    (
        r"\b(?:urgent|immediately)\b.{0,60}\b(?:click|verify|pay|transfer)\b",
        "Urgent action request",
    ),
    (r"\bclick\s+(?:here|this\s+link)\b", "Request to click a link"),
]


def find_scam_indicators(text):
    """Return distinct warning indicators found in supplied text."""
    found = []

    for pattern, description in SCAM_PATTERNS:
        if re.search(pattern, text, flags=re.IGNORECASE | re.DOTALL):
            if description not in found:
                found.append(description)

    return found


# --------------------------------------------------
# 3. BASIC URL STRUCTURE CHECKS
# --------------------------------------------------

def check_url_structure(raw_url):
    """
    Check URL structure only. Does not visit the URL
    or check its reputation.

    Returns (is_suspicious, reasons).
    """
    if not raw_url:
        return False, []

    candidate = raw_url.strip()

    if "://" not in candidate:
        candidate = "https://" + candidate

    reasons = []

    try:
        parsed = urlparse(candidate)
        hostname = parsed.hostname

        if parsed.scheme.lower() not in ("http", "https"):
            return True, ["Unsupported URL scheme"]

        if not hostname:
            return True, ["Invalid URL: hostname is missing"]

        # Embedded credentials may disguise a destination.
        if parsed.username is not None or parsed.password is not None:
            reasons.append(
                "URL contains embedded username or password"
            )

        hostname = hostname.rstrip(".").lower()

        # Punycode domains deserve additional scrutiny.
        if any(label.startswith("xn--") for label in hostname.split(".")):
            reasons.append(
                "URL contains an encoded internationalized domain"
            )

        # IP addresses and incomplete-looking domains are warning signals.
        try:
            ipaddress.ip_address(hostname)
            reasons.append(
                "URL uses an IP address instead of a domain name"
            )
        except ValueError:
            if "." not in hostname and hostname != "localhost":
                reasons.append(
                    "URL does not appear to contain a complete domain"
                )

        if parsed.scheme.lower() == "http":
            reasons.append(
                "URL uses HTTP rather than encrypted HTTPS"
            )

    except (ValueError, UnicodeError):
        return True, ["Invalid URL structure"]

    return bool(reasons), reasons


# --------------------------------------------------
# 4. HOME / HEALTH CHECK
# --------------------------------------------------

@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "status": "running",
        "application": "PishGuard",
        "message": "PishGuard backend is working.",
    }), 200


@app.route("/api/health", methods=["GET"])
def health():
    """Simple backend health check."""
    return jsonify({
        "status": "running",
        "application": "PishGuard",
    }), 200


# --------------------------------------------------
# 5. SCAM DETECTION API
# --------------------------------------------------

@app.route("/api/detect", methods=["POST"])
def detect_scam():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({
            "error": (
                "Send a valid JSON object containing message and/or url."
            )
        }), 400

    message_value = data.get("message", "")
    url_value = data.get("url", "")

    if not isinstance(message_value, str) or not isinstance(url_value, str):
        return jsonify({
            "error": "Message and URL must be strings."
        }), 400

    message = message_value.strip()
    url = url_value.strip()

    if not message and not url:
        return jsonify({
            "error": "Please enter a message, a URL, or both."
        }), 400

    if len(message) > 20000:
        return jsonify({
            "error": (
                "Message is too long. Please use fewer than "
                "20,000 characters."
            )
        }), 400

    if len(url) > 2048:
        return jsonify({
            "error": "URL is too long."
        }), 400

    # ----------------------------------------------
    # A. Rule-based message indicators
    # ----------------------------------------------

    combined_text = f"{message}\n{url}"
    reasons = find_scam_indicators(combined_text)

    # ----------------------------------------------
    # B. Basic URL analysis
    # ----------------------------------------------

    suspicious_url, url_reasons = check_url_structure(url)

    for reason in url_reasons:
        if reason not in reasons:
            reasons.append(reason)

    # ----------------------------------------------
    # C. Machine-learning prediction
    # ----------------------------------------------

    ml_prediction = None

    if message:
        try:
            ml_prediction = predict_message(message)

            if not isinstance(ml_prediction, dict):
                app.logger.error(
                    "ML predictor returned an unexpected result."
                )
                return jsonify({
                    "error": (
                        "The message analysis returned an invalid result."
                    )
                }), 500

        except (ValueError, TypeError) as exc:
            app.logger.warning("ML input could not be analyzed: %s", exc)
            return jsonify({
                "error": "Could not analyze the message. Check the input."
            }), 400

        except Exception:
            app.logger.exception("ML prediction failed.")
            return jsonify({
                "error": "Message analysis is temporarily unavailable."
            }), 500

    ml_flagged = (
        ml_prediction is not None
        and ml_prediction.get("label") == "scam"
    )

    if ml_flagged and not reasons:
        reasons.append("Machine-learning model flagged the message")

    # ----------------------------------------------
    # D. Gemini AI analysis
    # ----------------------------------------------

    # The AI analyzer handles its own API errors and returns
    # available=False if Gemini cannot complete the analysis.
    ai_analysis = analyze_with_ai(message=message, url=url)

    if not isinstance(ai_analysis, dict):
        app.logger.error("AI analyzer returned an unexpected result.")
        ai_analysis = {
            "available": False,
            "verdict": "uncertain",
            "confidence": 0,
            "summary": "AI analysis returned an invalid result.",
            "reasons": [],
        }

    ai_available = ai_analysis.get("available") is True
    ai_verdict = ai_analysis.get("verdict", "uncertain")

    # Only a successful Gemini response with a suspicious verdict
    # contributes the AI verdict signal to the combined decision.
    ai_flagged = ai_available and ai_verdict == "suspicious"

    if ai_available:
        for reason in ai_analysis.get("reasons", []):
            if isinstance(reason, str) and reason not in reasons:
                reasons.append(reason)

    # ----------------------------------------------
    # E. Combine detection signals
    # ----------------------------------------------

    is_suspicious = (
        bool(find_scam_indicators(combined_text))
        or suspicious_url
        or ml_flagged
        or ai_flagged
    )

    if is_suspicious:
        result = "Suspicious"
    else:
        result = "No obvious scam signs detected"

    # ----------------------------------------------
    # F. Response expected by the frontend
    # ----------------------------------------------

    return jsonify({
        # Existing response fields: retained for compatibility.
        "message": message,
        "url": url,
        "result": result,
        "is_suspicious": is_suspicious,
        "reasons": reasons,
        "ml_prediction": ml_prediction,
        "url_check_performed": bool(url),
        "message_model_performed": bool(message),

        # New Gemini AI fields.
        "ai_analysis": ai_analysis,
        "ai_model_performed": bool(message or url) and ai_available,
        "ai_verdict": ai_verdict,

        "note": (
            "PishGuard combines rule-based indicators, basic URL structure "
            "checks, a baseline message classifier, and Gemini AI analysis. "
            "A warning is not proof of fraud, and no obvious warning signs "
            "do not prove that a message or website is safe. URL reputation "
            "and website content are not checked."
        ),
    }), 200


# --------------------------------------------------
# 6. START THE LOCAL DEVELOPMENT SERVER
# --------------------------------------------------

if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False,
    )
