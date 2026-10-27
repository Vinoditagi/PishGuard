# 🛡️ PishGuard — AI-Powered Scam & Phishing Detector

**Detect suspicious messages and URLs using Machine Learning, Generative AI, and live website evidence.**

PishGuard is an AI-powered scam and phishing detection project designed to help users identify potentially fraudulent messages and suspicious URLs. It combines machine-learning predictions, rule-based detection, Gemini AI analysis, and website evidence collected through the Model Context Protocol (MCP).

The goal is to make scam detection easier to understand by presenting a verdict, risk level, reasons for concern, and available supporting evidence in a user-friendly interface.

> **Project status:** Working prototype under development. Detection results are advisory and should not be treated as a guarantee that a message or website is safe or fraudulent.

---

## 📌 Table of Contents

- [Overview](#-overview)
- [Problem Statement](#-problem-statement)
- [Objectives](#-objectives)
- [Key Features](#-key-features)
- [Technology Stack](#-technology-stack)
- [System Architecture](#-system-architecture)
- [How It Works](#-how-it-works)
- [Machine Learning Model](#-machine-learning-model)
- [MCP Integration](#-mcp-integration)
- [Project Structure](#-project-structure)
- [Installation and Setup](#-installation-and-setup)
- [Running the Application](#-running-the-application)
- [API Documentation](#-api-documentation)
- [Testing](#-testing)
- [Limitations](#-limitations)
- [Security and Privacy](#-security-and-privacy)
- [Future Enhancements](#-future-enhancements)
- [Contributors](#-contributors)
- [License](#-license)

---

## 🔍 Overview

Online scams and phishing attacks frequently use urgency, impersonation, fake rewards, account suspension warnings, and deceptive links to trick people into sharing sensitive information.

PishGuard combines multiple detection approaches to help identify these warning signs.

Users can submit a suspicious message, a URL, or both through the frontend. The Flask backend processes the input, runs the applicable detection components, and returns the available results to the interface.

The system combines:

- Machine Learning for message classification.
- Rule-based checks for suspicious wording and URL indicators.
- Google Gemini for AI-assisted analysis when available.
- MCP tools for collecting domain-age and DNS/IP resolution evidence.
- A web interface for presenting detection results.

## 🎯 Problem Statement

Many users struggle to distinguish legitimate communications from fraudulent messages, especially when scammers impersonate banks, delivery services, employers, government organizations, or familiar brands.

Traditional keyword-based detection can miss unfamiliar scam patterns, while an AI-generated explanation alone may not provide sufficient supporting evidence.

PishGuard addresses this challenge by combining several detection methods and presenting their results in a single interface.

## 🎯 Objectives

1. Identify potentially fraudulent messages using a trained machine-learning model.
2. Detect suspicious phrases and common scam indicators.
3. Analyze URLs for potentially suspicious characteristics.
4. Use Generative AI to provide additional context and analysis.
5. Gather supporting website evidence using MCP tools.
6. Present results in a simple, understandable format.
7. Encourage safer online behavior without making unsupported guarantees.

## ✨ Key Features

### 1. Message Scam Detection

- Accepts user-provided message text.
- Uses a trained TF-IDF and Logistic Regression pipeline.
- Identifies messages that resemble scam or spam examples learned during training.
- Returns the predicted label and available model score.

### 2. Rule-Based Detection

Checks for suspicious indicators such as:

- Prize and reward claims.
- Urgent requests for action.
- Threats of account suspension.
- Requests to click links or verify accounts.
- Other configured scam-related phrases.

These indicators provide additional context but do not independently prove that a message is fraudulent.

### 3. URL Analysis

- Accepts a URL for analysis.
- Checks configured URL-related indicators.
- Collects available domain-age and DNS/IP evidence through MCP tools.
- Combines available evidence with the other detection results.

### 4. Gemini AI Analysis

PishGuard can use Google Gemini to analyze the submitted message or URL and provide an additional assessment.

When available, the AI response can contribute a verdict, confidence information, and explanatory context to the overall result.

AI output is not guaranteed to be correct. Its assessment should be considered alongside the other available signals.

### 5. MCP-Based Website Evidence

The project integrates the Model Context Protocol (MCP) to make external lookup tools available to the backend.

The implemented tools include:

- **Domain age:** Retrieves available domain registration-age information.
- **DNS/IP resolution:** Attempts to resolve a domain to its IP address.

This evidence can provide useful context when evaluating a URL. Domain age and successful DNS resolution alone cannot establish whether a website is trustworthy.

### 6. Combined Risk Assessment

The backend combines the results of applicable detection components and returns information such as:

- Overall result.
- Suspicion indicator.
- Risk level.
- Machine-learning prediction.
- Detection reasons and signals.
- AI analysis, when available.
- Website evidence, when available.

The exact output depends on the input and which components successfully return results.

### 7. User-Friendly Results

The frontend communicates the detection results in a format intended to help users understand why an input may be suspicious.

The backend also provides a safety note reminding users not to disclose passwords, OTPs, PINs, or banking details and to verify suspicious communications through official channels.

---

## 🧰 Technology Stack

| Component | Technology |
|---|---|
| Frontend | HTML, CSS, JavaScript |
| Backend | Python, Flask |
| Machine Learning | Scikit-learn |
| Text processing | TF-IDF |
| Classification algorithm | Logistic Regression |
| Generative AI | Google Gemini API |
| Tool integration | Model Context Protocol (MCP) |
| Domain evidence | Domain-age lookup |
| Network evidence | DNS/IP resolution |
| Model persistence | Joblib |
| Version control | Git and GitHub |

---

## 🏗️ System Architecture

```text
                 USER
                   |
                   v
          FRONTEND INTERFACE
            HTML / CSS / JS
                   |
                   v
             FLASK BACKEND
            /      |       \
           /       |        \
          v        v         v
     Rule-Based   Machine   Gemini AI
      Checks      Learning  Analysis
                    |
                    v
              ML Prediction

                   |
                   v
             MCP Integration
                   |
             +-----+------+
             |            |
             v            v
         Domain Age    DNS/IP Lookup
             |            |
             +------+-----+
                    |
                    v
          COMBINED DETECTION RESULT
                    |
                    v
           FRONTEND RESULTS VIEW
```

The backend coordinates the applicable checks and returns the available results through the detection API. The diagram represents the logical components; it does not imply that every check must execute successfully for every request.

---

## ⚙️ How It Works

1. **Input:** The user enters a message, a URL, or both.
2. **Request:** The frontend sends the input to the Flask API.
3. **Rule-based checks:** The backend evaluates configured suspicious indicators.
4. **Machine-learning prediction:** Message text is processed by the trained classifier when applicable.
5. **AI analysis:** Gemini provides additional analysis when configured and available.
6. **MCP evidence collection:** The backend requests domain-age and DNS/IP evidence for applicable URLs.
7. **Result generation:** The backend assembles the available predictions, reasons, evidence, and risk assessment.
8. **Display:** The frontend presents the response to the user.

Some checks may be unavailable because of missing configuration, network problems, or external service failures. An unavailable check should not be interpreted as proof that an input is safe.

---

## 🤖 Machine Learning Model

PishGuard uses a supervised text-classification baseline built with TF-IDF and Logistic Regression.

### Training dataset

The initial model was trained using the `SMSSpamCollection` dataset.

| Dataset statistic | Value |
|---|---:|
| Usable messages | 5,158 |
| Legitimate messages | 4,516 |
| Scam/spam messages | 642 |
| Training samples | 4,126 |
| Test samples | 1,032 |

### Model performance

The recorded evaluation produced the following results:

| Metric | Result |
|---|---:|
| Accuracy | 97.67% |
| Scam precision | 0.88 |
| Scam recall | 0.94 |
| Scam F1-score | 0.91 |

These metrics describe performance on the recorded test split, not guaranteed performance on real-world messages. Real scam messages can differ significantly from the training data.

### Model pipeline

1. Convert message text into numerical TF-IDF features.
2. Pass the features to the Logistic Regression classifier.
3. Obtain the predicted class and available score.
4. Return the prediction to the backend for integration with other detection signals.

The trained model artifact is stored at:

`ml/artifacts/scam_text_model.joblib`

The model version recorded in the predictor is `baseline-v1`.

**Important:** The model was trained on SMS spam/scam examples. It is a baseline classifier, not a specialized detector for every phishing technique, language, URL, or messaging platform.

---

## 🔌 MCP Integration

The Model Context Protocol allows the backend to communicate with tools through a defined interface.

PishGuard uses an MCP server implemented in:

- `backend/scam_tools.py`
- `backend/mcp_evidence.py`

The evidence collector starts the configured MCP server using standard input/output communication and requests the available tools.

### Available tools

| Tool | Purpose |
|---|---|
| `domain_age` | Retrieves available domain registration-age evidence |
| `resolve_ip` | Attempts DNS resolution and returns available IP information |

The evidence collector extracts relevant domains from the submitted input and gathers the available results.

MCP provides supporting evidence; it does not independently certify that a domain is malicious or legitimate. The checks also do not constitute a full website content scan, malware scan, or vulnerability assessment.

---

## 📁 Project Structure

The following is the logical project layout. Confirm the exact filenames against your current repository before relying on the tree as an exhaustive file listing.

```text
PishGuard/
│
├── backend/
│   ├── app.py
│   ├── ai_analyzer.py
│   ├── mcp_evidence.py
│   ├── scam_tools.py
│   └── requirements.txt
│
├── frontend/
│   ├── index.html
│   ├── style.css
│   └── script.js
│
├── ml/
│   ├── data/
│   │   └── SMSSpamCollection
│   ├── artifacts/
│   │   └── scam_text_model.joblib
│   ├── predictor.py
│   └── train.py
│
├── .gitignore
├── .env.example
└── README.md
```

### Important files

- `backend/app.py` — Flask API and detection workflow.
- `backend/ai_analyzer.py` — Gemini analysis and integration with evidence collection.
- `backend/mcp_evidence.py` — Collects evidence through MCP tools.
- `backend/scam_tools.py` — Implements the domain-age and DNS/IP tools.
- `ml/predictor.py` — Loads the trained model and predicts message classes.
- `ml/train.py` — Training script for the baseline classifier.
- `frontend/script.js` — Sends scan requests and displays API results.
- `ml/artifacts/scam_text_model.joblib` — Saved model artifact.

---

## 🚀 Installation and Setup

### Prerequisites

Install or prepare:

- Python 3.12 or another Python version supported by the project's dependencies.
- Git.
- A modern web browser.
- A Google Gemini API key if AI analysis is required.
- Network access for applicable external lookups.

### 1. Clone the repository

```bash
git clone <YOUR_GITHUB_REPOSITORY_URL>
cd PishGuard
```

Replace the placeholder with your actual repository URL.

### 2. Create a virtual environment

**Windows PowerShell:**

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

If PowerShell blocks activation, use the appropriate execution policy for your environment or run the virtual environment's Python executable directly.

### 3. Install dependencies

From the project root:

```powershell
python -m pip install -r backend/requirements.txt
```

The requirements file should include the packages used by the current backend, ML pipeline, and MCP integration. If any dependency is missing, add the appropriate compatible package to the requirements file and reinstall.

### 4. Configure Gemini

Create a `.env` file in the project root if that is the location expected by your current configuration.

For example:

```dotenv
GEMINI_API_KEY=your_gemini_api_key_here
```

Use the exact environment variable name expected by `backend/ai_analyzer.py`. If your code uses a different name, configure that name instead.

Never commit your real API key to GitHub.

### 5. Check the model artifact

Confirm that the trained model exists:

```text
ml/artifacts/scam_text_model.joblib
```

If the artifact is missing, train the model using the repository's training script and ensure the dataset is available in the location expected by that script.

Do not retrain the model unnecessarily if the existing artifact is already available and compatible.

---

## ▶️ Running the Application

### Start the backend

Run the command from the project root:

```powershell
python -m backend.app
```

The Flask development server should display a local address similar to:

```text
http://https://pishguard-ca4x.onrender.com
```

You can check the health endpoint in your browser:

```text
http://https://pishguard-ca4x.onrender.com/
```

The current health endpoint is expected to return a response identifying PishGuard and its running status.

Keep the backend terminal open while testing the application.

### Start the frontend

Open the `frontend` directory and launch `index.html` in your browser. If your setup uses Visual Studio Code, you can use the Live Server extension.

Ensure the frontend API URL points to the running backend:

```javascript
const API_URL = "http://https://pishguard-ca4x.onrender.com/api/detect";
```

The frontend variable name must match the name actually used in your current `script.js`.

If requests fail, check the browser console, the backend terminal, the configured API URL, and any applicable CORS settings.

---

## 🔗 API Documentation

### Detection endpoint

`POST /api/detect`

**Content type:** `application/json`

The endpoint accepts a message, a URL, or both.

### Example: Message scan

Request:

```json
{
  "message": "Congratulations! You won a prize. Click this link immediately to claim your reward."
}
```

### Example: URL scan

Request:

```json
{
  "url": "https://example.com"
}
```

### Example: Message and URL

Request:

```json
{
  "message": "Your account will be blocked. Verify your details immediately.",
  "url": "https://example.com"
}
```

These are example requests for testing, not claims about a particular API response.

### Response fields

Depending on the input and the availability of the detection components, the backend can return fields such as:

| Field | Description |
|---|---|
| `result` | Overall result label |
| `is_suspicious` | Boolean suspicion indicator |
| `reasons` | Reasons identified by configured checks |
| `ml_prediction` | Available message-model prediction |
| `spam_probability` | Numerical model score expressed as a percentage when available |
| `ai_analysis` | Gemini analysis information |
| `ai_verdict` | AI-generated assessment when available |
| `risk_level` | Overall risk category |
| `signals` | Detection signals used by the backend |
| `live_red_flags` | Additional indicators identified by the checks |
| `evidence` | Available website and domain evidence |
| `safety_note` | User-facing safety advice |

Not every field will contain meaningful data for every request. Refer to the current `backend/app.py` implementation for the exact response schema.

A numerical model score is not necessarily a calibrated probability of real-world fraud. It should not be presented as a guarantee or used as the only basis for a decision.

---

## 🧪 Testing

Use harmless test inputs to evaluate the detector.

### Test 1: Prize scam simulation

```text
Congratulations! You won a prize. Click this link immediately to claim your reward.
```

Expected behavior: the detector should identify configured prize/reward language and urgency indicators. The final classification depends on the model and other checks.

### Test 2: Fake bank KYC simulation

```text
Dear Customer, Your bank account will be blocked today due to incomplete KYC verification. Update your KYC immediately to avoid service interruption. Click the link below to verify your account.
```

Expected behavior: the detector should look for account-suspension threats, urgency, and requests to click a link or verify an account.

This is fabricated test content, not an authentic bank communication.

### Test 3: Ordinary message

```text
Hi, our class meeting is scheduled for tomorrow at 10 AM. Please bring your notes.
```

Expected behavior: the detector should evaluate the message without assuming that every message is suspicious.

### Test 4: URL evidence

```text
https://example.com
```

Expected behavior: the backend should attempt the configured URL-related checks and return available evidence. A successful DNS lookup or an old domain registration date does not guarantee that a website is safe.

### Testing checklist

- [ ] Backend starts without Python errors.
- [ ] Health endpoint responds.
- [ ] Frontend can reach the backend.
- [ ] Message-only requests work.
- [ ] URL-only requests work.
- [ ] Model predictions are returned when available.
- [ ] Gemini failures do not get mistaken for successful AI analysis.
- [ ] MCP evidence is returned when the tools succeed.
- [ ] Missing evidence or model scores are handled gracefully.
- [ ] Results are displayed correctly in the frontend.

---

## ⚠️ Limitations

PishGuard is a developing prototype and has several limitations:

1. **Model coverage:** The baseline classifier was trained on an SMS spam dataset and may not generalize to all modern phishing attacks.
2. **False positives:** Legitimate messages containing urgency, rewards, or account-verification language may be flagged.
3. **False negatives:** Sophisticated or previously unseen scams may evade detection.
4. **AI reliability:** Gemini may produce incomplete or inaccurate assessments.
5. **External dependencies:** AI and live lookup features can fail because of network problems, API limits, missing configuration, or service changes.
6. **Website inspection:** Domain-age and DNS/IP evidence do not amount to a complete website security scan.
7. **Risk interpretation:** Risk categories and model scores are indicators, not guarantees.
8. **Dataset limitations:** Performance on the original test split does not establish real-world detection performance.

PishGuard should be used as a supporting security tool, not as a replacement for independent verification or professional security analysis.

---

## 🔐 Security and Privacy

When developing, testing, and deploying PishGuard:

- Never commit `.env`, API keys, or other secrets.
- Keep `.venv`, temporary files, and unnecessary local artifacts out of version control.
- Do not include real passwords, OTPs, banking details, or other sensitive personal information in test messages.
- Use HTTPS and appropriate authentication if the application is deployed publicly.
- Apply request validation, rate limiting, and suitable error handling before production deployment.
- Avoid logging sensitive message contents unnecessarily.
- Treat externally supplied messages, URLs, AI output, and lookup results as untrusted input.
- Do not automatically open suspicious links or submit sensitive information to them.

The current Flask development server is intended for local development and testing, not production hosting.

---

## 🔮 Future Enhancements

Potential future improvements include:

- Training and evaluating on more diverse phishing and scam datasets.
- Expanding multilingual scam detection, including Indian-language messages.
- Improving URL reputation checks using trustworthy threat-intelligence sources.
- Adding explainable model predictions and clearer evidence attribution.
- Improving the combination and calibration of risk scores.
- Adding automated unit and integration tests.
- Improving error handling and resilience when external tools are unavailable.
- Adding a scan history and reporting interface with privacy safeguards.
- Deploying through a production-ready server with appropriate security controls.
- Evaluating performance against unseen, realistic scam examples.

These are proposed enhancements, not claims about existing functionality.

---

## 👥 Contributors

PishGuard was developed as a collaborative team project.

The team has worked on the frontend, backend API, machine-learning model, and project integration. The implementation also includes Gemini AI analysis and MCP-based evidence collection.

Add the names, GitHub usernames, and specific responsibilities of all four team members here before publishing the final README.

---

## 📄 License

Choose and add a license before distributing the project publicly. If the repository does not yet contain a license, the project should not be described as being under a particular open-source license.

---

## 💡 Disclaimer

PishGuard is an educational and experimental cybersecurity project intended to help users recognize potentially suspicious messages and URLs.

Its results may be incomplete or incorrect. Always verify suspicious communications through official channels, never share sensitive authentication details, and avoid relying on a single automated verdict when making security decisions.
