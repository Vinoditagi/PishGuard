from flask import Flask, request, jsonify
from flask_cors import CORS
from urllib.parse import urlparse

app = Flask(__name__)

CORS(app)


@app.route("/", methods=["GET"])
def home():
    return "AI Scam and Phishing Detector Backend is Working!"


@app.route("/api/detect", methods=["POST"])
def detect_scam():
    data = request.get_json(silent=True) or {}

    message = str(data.get("message", "")).strip()
    url = str(data.get("url", "")).strip()

    if not message and not url:
        return jsonify({"error": "Please provide a message or URL."}), 400

    text = (message + " " + url).lower()

    suspicious_words = [
    "urgent",
    "verify your account",
    "password",
    "otp",
    "prize",
    "winner",
    "click here",
    "click this link",
    "won 10000",
    "you won",
    "you have won",
    "bank details",
    "send money",
    "claim now",
    "claim your reward",
    "free money",
    "limited time",
    "account suspended",
    "confirm your identity"
]

    reasons = [
        word for word in suspicious_words if word in text
    ]

    suspicious_url = False

    if url:
        parsed_url = urlparse(
            url if "://" in url else "https://" + url
        )
        domain = parsed_url.hostname or ""

        if (
            not domain
            or "." not in domain
            or domain.startswith("xn--")
            or parsed_url.username is not None
        ):
            suspicious_url = True

    is_suspicious = bool(reasons) or suspicious_url

    return jsonify({
        "message": message,
        "url": url,
        "result": (
            "Suspicious" if is_suspicious
            else "No obvious scam signs detected"
        ),
        "is_suspicious": is_suspicious,
        "reasons": reasons,
        "note": "Basic rule-based demo, not a trained AI model."
    })


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)