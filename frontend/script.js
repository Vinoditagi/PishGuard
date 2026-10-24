
"use strict";

/* ==========================================
   PISHGUARD AI - FRONTEND JAVASCRIPT
   Flask backend: http://https://pishguard-ca4x.onrender.com
   ========================================== */

const API_URL = "http://https://pishguard-ca4x.onrender.com/api/detect";

/* ---------- HTML ELEMENTS ---------- */

const scanForm = document.getElementById("scanForm");
const messageInput = document.getElementById("message");
const urlInput = document.getElementById("url");

const detectBtn = document.getElementById("detectBtn");
const buttonText = document.getElementById("buttonText");
const errorMessage = document.getElementById("errorMessage");

const resultPanel = document.getElementById("result");
const resultTitle = document.getElementById("resultTitle");
const resultSummary = document.getElementById("resultSummary");
const resultBadge = document.getElementById("resultBadge");

const probabilityPanel = document.getElementById("probabilityPanel");
const scoreCircle = document.getElementById("scoreCircle");
const spamPercentage = document.getElementById("spamPercentage");
const scoreCaption = document.getElementById("scoreCaption");
const riskLevelElement = document.getElementById("riskLevel");
const scoreDescription = document.getElementById("scoreDescription");
const probabilityUnavailable =
    document.getElementById("probabilityUnavailable");

const resultNote = document.getElementById("resultNote");
const reasonsList = document.getElementById("reasonsList");
const safetyNote = document.getElementById("safetyNote");
const scanAgainBtn = document.getElementById("scanAgainBtn");

const charCount = document.getElementById("charCount");
const currentYear = document.getElementById("currentYear");


/* ---------- INITIALIZE ---------- */

if (currentYear) {
    currentYear.textContent = new Date().getFullYear();
}

clearError();
hideResults();
updateCharacterCount();

if (messageInput) {
    messageInput.addEventListener("input", updateCharacterCount);
}


/* ---------- CHARACTER COUNTER ---------- */

function updateCharacterCount() {
    if (!messageInput || !charCount) return;

    charCount.textContent = messageInput.value.length;
}


/* ---------- URL VALIDATION ---------- */

// This checks URL syntax only. It does not guarantee that
// the destination is legitimate or safe.

function validateURL(rawURL) {
    if (!rawURL) {
        return { valid: true, url: "" };
    }

    let candidate = rawURL.trim();

    if (candidate.length > 2048) {
        return {
            valid: false,
            error: "The URL must not exceed 2048 characters."
        };
    }

    if (/[\u0000-\u001F\u007F]/.test(candidate)) {
        return {
            valid: false,
            error: "The URL contains invalid control characters."
        };
    }

    // Support example.com as well as https://example.com.
    if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(candidate)) {
        candidate = "https://" + candidate;
    }

    let parsed;

    try {
        parsed = new URL(candidate);
    } catch {
        return {
            valid: false,
            error: "Please enter a valid website URL."
        };
    }

    if (!["http:", "https:"].includes(parsed.protocol)) {
        return {
            valid: false,
            error: "Only HTTP and HTTPS website URLs are supported."
        };
    }

    if (!parsed.hostname || !parsed.hostname.includes(".")) {
        return {
            valid: false,
            error: "Please enter a complete website domain, such as example.com."
        };
    }

    if (parsed.username || parsed.password) {
        return {
            valid: false,
            error: "Please remove embedded usernames or passwords from the URL."
        };
    }

    return {
        valid: true,
        url: candidate
    };
}


/* ---------- FORM SUBMISSION ---------- */

if (scanForm) {
    scanForm.addEventListener("submit", async function (event) {
        event.preventDefault();

        clearError();

        const message = messageInput
            ? messageInput.value.trim()
            : "";

        const rawURL = urlInput
            ? urlInput.value.trim()
            : "";

        if (!message && !rawURL) {
            showError("Please enter a message or URL to scan.");
            return;
        }

        if (message.length > 10000) {
            showError("The message must not exceed 10,000 characters.");
            return;
        }

        // Validate URL before sending it to Flask.
        const urlCheck = validateURL(rawURL);

        if (!urlCheck.valid) {
            showError(urlCheck.error);
            if (urlInput) urlInput.focus();
            return;
        }

        const url = urlCheck.url;

        setLoading(true);

        try {
            const response = await fetch(API_URL, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "Accept": "application/json"
                },
                body: JSON.stringify({
                    message: message,
                    url: url
                })
            });

            let data;

            try {
                data = await response.json();
            } catch {
                throw new Error(
                    "The backend returned an invalid response. Check the Flask terminal."
                );
            }

            if (!response.ok) {
                throw new Error(
                    data.error ||
                    (Array.isArray(data.reasons)
                        ? data.reasons.join(" ")
                        : "The scan could not be completed.")
                );
            }

            displayResults(data);

        } catch (error) {
            console.error("PishGuard scan error:", error);

            if (error instanceof TypeError) {
                showError(
                    "Cannot connect to the Flask backend. " +
                    "Make sure app.py is running on port 5000. " +
                    "Check https://pishguard-ca4x.onrender.com in your browser."
                );
            } else {
                showError(error.message || "An unexpected error occurred.");
            }

        } finally {
            setLoading(false);
        }
    });
}


/* ---------- LOADING BUTTON ---------- */

function setLoading(isLoading) {
    if (detectBtn) {
        detectBtn.disabled = isLoading;
        detectBtn.setAttribute(
            "aria-busy",
            String(isLoading)
        );
    }

    if (buttonText) {
        buttonText.textContent = isLoading
            ? "Analyzing..."
            : "Scan for Scams";
    }
}


/* ---------- DISPLAY RESULTS ---------- */

function displayResults(data) {
    if (!resultPanel) return;

    clearError();

    resultPanel.hidden = false;
    resultPanel.style.display = "block";

    const result = String(
        data.result || "Analysis completed"
    );

    // Backend supplies spam_probability as a percentage (0-100).
    // Do not interpret a missing score as 0%.
    const rawScore = data.spam_probability;

    const hasScore =
        rawScore !== null &&
        rawScore !== undefined &&
        rawScore !== "" &&
        Number.isFinite(Number(rawScore));

    const score = hasScore
        ? Math.max(0, Math.min(100, Number(rawScore)))
        : null;

    // Prefer the backend's risk level.
    // If unavailable, use the score as a fallback.
    const backendLevel = String(data.risk_level || "").toLowerCase();

    let level;

    if (["low", "medium", "high"].includes(backendLevel)) {
        level = backendLevel;
    } else if (score !== null) {
        level = determineRiskLevel(score).toLowerCase();
    } else if (data.is_suspicious === true ||
               result.toLowerCase().includes("suspicious")) {
        level = "medium";
    } else {
        level = "low";
    }

    const presentation = {
        high: {
            title: "⚠ Suspicious Indicators Detected",
            summary:
                "High-risk indicators were detected. Avoid clicking links " +
                "or sharing information until you verify the sender.",
            color: "#C62828",
            description: "Several warning signals may be present."
        },
        medium: {
            title: "⚠ Review This Result Carefully",
            summary:
                "Some warning signs were detected. Verify the sender " +
                "independently before taking action.",
            color: "#D97706",
            description: "Some warning indicators were found."
        },
        low: {
            title: "✓ No Obvious Scam Signs Detected",
            summary:
                "No strong scam indicators were detected. This does not " +
                "guarantee that the message or URL is safe.",
            color: "#218838",
            description: "Few warning indicators were found."
        }
    };

    const view = presentation[level];

    if (resultTitle) {
        resultTitle.textContent = view.title;
        resultTitle.style.color = view.color;

        resultTitle.classList.remove(
            "high-risk",
            "medium-risk",
            "low-risk"
        );
        resultTitle.classList.add(level + "-risk");
    }

    if (resultSummary) {
        resultSummary.textContent = view.summary;
        resultSummary.style.color = view.color;
    }

    updateRiskBadge(level, resultBadge);

    updateRiskScore(score, level, view.description);

    displayReasons(data.reasons);

    if (resultNote) {
        resultNote.textContent = data.note ||
            "This result is based on the available message and URL analysis checks.";
    }

    if (safetyNote) {
        safetyNote.textContent = data.safety_note ||
            "Never share passwords, OTPs, PINs, or banking details in response to an unexpected request.";
    }

    resultPanel.scrollIntoView({
        behavior: "smooth",
        block: "start"
    });
}


/* ---------- RISK SCORE ---------- */

function updateRiskScore(score, level, description) {
    const colors = {
        low: "#218838",
        medium: "#D97706",
        high: "#C62828"
    };

    const circleColor = colors[level] || colors.low;

    if (score === null) {
        if (probabilityPanel) {
            probabilityPanel.hidden = true;
        }

        if (probabilityUnavailable) {
            probabilityUnavailable.hidden = false;
            probabilityUnavailable.textContent =
                "A numerical risk score was not provided by the backend.";
        }

        return;
    }

    if (probabilityPanel) {
        probabilityPanel.hidden = false;
    }

    if (probabilityUnavailable) {
        probabilityUnavailable.hidden = true;
    }

    if (spamPercentage) {
        spamPercentage.textContent = Math.round(score) + "%";
    }

    if (scoreCircle) {
        scoreCircle.style.background = `conic-gradient(
            ${circleColor} 0%,
            ${circleColor} ${score}%,
            #E5E4E2 ${score}%,
            #E5E4E2 100%
        )`;

        scoreCircle.style.setProperty("--score", score + "%");
        scoreCircle.style.setProperty("--ring-color", circleColor);

        scoreCircle.setAttribute(
            "aria-label",
            `Risk score ${Math.round(score)} out of 100`
        );
    }

    if (riskLevelElement) {
        riskLevelElement.textContent =
            level.charAt(0).toUpperCase() + level.slice(1);

        riskLevelElement.style.color = circleColor;
    }

    if (scoreCaption) {
        scoreCaption.textContent =
            Math.round(score) + "% Risk Score";
        scoreCaption.style.color = circleColor;
    }

    if (scoreDescription) {
        scoreDescription.textContent =
            `${description} A low score does not guarantee safety.`;
    }
}


/* ---------- DETERMINE RISK LEVEL ---------- */

function determineRiskLevel(score) {
    if (!Number.isFinite(Number(score))) {
        return "Low";
    }

    if (Number(score) >= 50) return "High";
    if (Number(score) >= 25) return "Medium";

    return "Low";
}


/* ---------- RISK BADGE ---------- */

function updateRiskBadge(riskLevel, badge) {
    if (!badge) return;

    const level = String(riskLevel).toLowerCase();

    const styles = {
        high: {
            text: "HIGH RISK",
            background: "#FDE8E7",
            color: "#C62828"
        },
        medium: {
            text: "MEDIUM RISK",
            background: "#FFF0D5",
            color: "#B76500"
        },
        low: {
            text: "LOW RISK",
            background: "#DCFCE7",
            color: "#218838"
        }
    };

    const style = styles[level] || styles.low;

    badge.textContent = style.text;
    badge.style.backgroundColor = style.background;
    badge.style.color = style.color;

    badge.classList.remove(
        "high-risk",
        "medium-risk",
        "low-risk"
    );
    badge.classList.add(level + "-risk");
}


/* ---------- DETECTION REASONS ---------- */

function displayReasons(reasons) {
    if (!reasonsList) return;

    reasonsList.replaceChildren();

    if (!Array.isArray(reasons) || reasons.length === 0) {
        const item = document.createElement("li");
        item.textContent =
            "No specific detection details were provided by the backend.";
        reasonsList.appendChild(item);
        return;
    }

    reasons.forEach(function (reason) {
        const item = document.createElement("li");

        // textContent prevents returned strings from being treated as HTML.
        item.textContent = String(reason);

        reasonsList.appendChild(item);
    });
}


/* ---------- ERROR HANDLING ---------- */

function showError(message) {
    if (!errorMessage) {
        console.error(message);
        return;
    }

    errorMessage.textContent = message;
    errorMessage.hidden = false;
    errorMessage.style.display = "block";
}

function clearError() {
    if (!errorMessage) return;

    errorMessage.textContent = "";
    errorMessage.hidden = true;
    errorMessage.style.display = "none";
}


/* ---------- HIDE RESULTS ---------- */

function hideResults() {
    if (!resultPanel) return;

    resultPanel.hidden = true;
    resultPanel.style.display = "none";
}


/* ---------- SCAN ANOTHER MESSAGE ---------- */

if (scanAgainBtn) {
    scanAgainBtn.addEventListener("click", function () {
        hideResults();
        clearError();

        if (scanForm) {
            scanForm.reset();
        }

        updateCharacterCount();

        if (probabilityPanel) {
            probabilityPanel.hidden = false;
        }

        if (probabilityUnavailable) {
            probabilityUnavailable.hidden = true;
        }

        if (messageInput) {
            messageInput.focus();
        }

        if (scanForm) {
            scanForm.scrollIntoView({
                behavior: "smooth",
                block: "center"
            });
        }
    });
}


/* ---------- SMOOTH NAVIGATION ---------- */

document.querySelectorAll('a[href^="#"]').forEach(function (link) {
    link.addEventListener("click", function (event) {
        const targetId = link.getAttribute("href");

        if (!targetId || targetId === "#") return;

        const target = document.querySelector(targetId);

        if (target) {
            event.preventDefault();

            target.scrollIntoView({
                behavior: "smooth",
                block: "start"
            });
        }
    });
});


/* ---------- INITIALIZATION CONFIRMATION ---------- */

console.log("PishGuard AI frontend initialized.");
console.log("Flask API endpoint:", API_URL);