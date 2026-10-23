"use strict";

/* ==========================================
   PISHGUARD AI — COMPLETE FRONTEND JAVASCRIPT
   Backend: Flask at http://127.0.0.1:5001
   ========================================== */

const API_URL = "http://127.0.0.1:5001/api/detect";

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


/* ---------- INITIALIZE PAGE ---------- */

if (currentYear) {
    currentYear.textContent = new Date().getFullYear();
}

clearError();
hideResults();
updateCharacterCount();


/* ---------- CHARACTER COUNTER ---------- */

if (messageInput) {
    messageInput.addEventListener("input", updateCharacterCount);
}

function updateCharacterCount() {
    if (!messageInput || !charCount) return;

    charCount.textContent = messageInput.value.length;
}


/* ---------- FORM SUBMISSION ---------- */

if (scanForm) {
    scanForm.addEventListener("submit", async function (event) {
        event.preventDefault();

        clearError();

        const message = messageInput
            ? messageInput.value.trim()
            : "";

        const url = urlInput
            ? urlInput.value.trim()
            : "";

        // Validate user input.
        if (!message && !url) {
            showError("Please enter a message or URL to scan.");
            return;
        }

        setLoading(true);

        try {
            const response = await fetch(API_URL, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
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
                    "The server returned an invalid response."
                );
            }

            if (!response.ok) {
                throw new Error(
                    data.error || "The scan could not be completed."
                );
            }

            displayResults(data);

        } catch (error) {
            console.error("PishGuard error:", error);

            showError(
                "Unable to connect to the backend. " +
                "Check that Flask is running on port 5001. " +
                "Details: " + error.message
            );

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
            isLoading ? "true" : "false"
        );
    }

    if (buttonText) {
        buttonText.textContent = isLoading
            ? "Scanning..."
            : "Scan for Scams";
    }
}


/* ---------- DISPLAY RESULTS ---------- */

function displayResults(data) {
    if (!resultPanel) return;

    clearError();

    resultPanel.hidden = false;
    resultPanel.style.display = "block";

    const result = String(data.result || "Scan completed");

    const score = Number(data.spam_probability);

    const riskLevel = (
        data.risk_level &&
        ["low", "medium", "high"].includes(
            String(data.risk_level).toLowerCase()
        )
    )
        ? String(data.risk_level)
        : determineRiskLevel(score);

    const level = riskLevel.toLowerCase();

    // Set result heading and colour.
    if (resultTitle) {
        resultTitle.classList.remove(
            "high-risk",
            "medium-risk",
            "low-risk"
        );

        if (level === "high") {
            resultTitle.textContent =
                "⚠ Suspicious Message Detected";
            resultTitle.style.color = "#C62828";
            resultTitle.classList.add("high-risk");

        } else if (level === "medium") {
            resultTitle.textContent =
                "⚠ Review This Message Carefully";
            resultTitle.style.color = "#B76500";
            resultTitle.classList.add("medium-risk");

        } else {
            resultTitle.textContent =
                "✓ No Obvious Scam Signs Detected";
            resultTitle.style.color = "#218838";
            resultTitle.classList.add("low-risk");
        }
    }

    // Colour and update summary.
    if (resultSummary) {
        if (level === "high") {
            resultSummary.textContent =
                "High-risk indicators were detected. Avoid interacting " +
                "with this message until you verify the sender.";
            resultSummary.style.color = "#C62828";

        } else if (level === "medium") {
            resultSummary.textContent =
                "Some warning signs were detected. Verify the sender " +
                "independently before clicking links or sharing information.";
            resultSummary.style.color = "#B76500";

        } else {
            resultSummary.textContent =
                "No strong scam indicators were detected. This does not " +
                "guarantee that the message or URL is safe.";
            resultSummary.style.color = "#218838";
        }
    }

    // Update badge.
    updateRiskBadge(riskLevel, resultBadge);

    // Update risk score and circle.
    updateRiskScore(data, riskLevel);

    // Display detection reasons.
    displayReasons(data.reasons);

    // Display explanation.
    if (resultNote) {
        resultNote.textContent = data.note ||
            "This result is based on predefined message and URL checks.";
    }

    // Display security reminder.
    if (safetyNote) {
        safetyNote.textContent = data.safety_note ||
            "Verify unexpected messages independently. Never share " +
            "passwords, OTPs, PINs, or banking details.";
    }

    // Scroll to results.
    resultPanel.scrollIntoView({
        behavior: "smooth",
        block: "start"
    });
}


/* ---------- RISK SCORE CIRCLE ---------- */

function updateRiskScore(data, riskLevel) {
    const rawScore = Number(data.spam_probability);

    const hasValidScore =
        data.spam_probability !== null &&
        data.spam_probability !== undefined &&
        data.spam_probability !== "" &&
        Number.isFinite(rawScore);

    if (!hasValidScore) {
        if (probabilityPanel) {
            probabilityPanel.hidden = true;
        }

        if (probabilityUnavailable) {
            probabilityUnavailable.hidden = false;
            probabilityUnavailable.textContent =
                "A numerical risk score is unavailable.";
        }

        return;
    }

    const score = Math.max(0, Math.min(100, rawScore));
    const level = riskLevel.toLowerCase();

    if (probabilityPanel) {
        probabilityPanel.hidden = false;
    }

    if (probabilityUnavailable) {
        probabilityUnavailable.hidden = true;
    }

    // Percentage inside the circle.
    if (spamPercentage) {
        spamPercentage.textContent = `${Math.round(score)}%`;
    }

    // Choose the circle colour.
    let circleColor = "#218838";

    if (level === "high") {
        circleColor = "#C62828";
    } else if (level === "medium") {
        circleColor = "#D97706";
    }

    // Draw the circular progress indicator.
    if (scoreCircle) {
        scoreCircle.style.setProperty("--score", `${score}%`);

        scoreCircle.style.background = `
            conic-gradient(
                ${circleColor} 0%,
                ${circleColor} ${score}%,
                #E5E4E2 ${score}%,
                #E5E4E2 100%
            )
        `;

        scoreCircle.setAttribute(
            "aria-label",
            `Risk score ${Math.round(score)} out of 100`
        );
    }

    // Risk level text.
    if (riskLevelElement) {
        riskLevelElement.textContent =
            level.charAt(0).toUpperCase() + level.slice(1);

        riskLevelElement.style.color = circleColor;
        riskLevelElement.style.fontWeight = "700";
    }

    // Score caption.
    if (scoreCaption) {
        scoreCaption.textContent =
            `${Math.round(score)}% Risk Score`;
        scoreCaption.style.color = circleColor;
    }

    // Score explanation.
    if (scoreDescription) {
        if (score >= 50) {
            scoreDescription.textContent =
                "High risk: multiple warning indicators may be present. " +
                "Verify the message before taking action.";

        } else if (score >= 25) {
            scoreDescription.textContent =
                "Medium risk: some warning indicators were found. " +
                "Check the sender and verify the message independently.";

        } else {
            scoreDescription.textContent =
                "Low risk: few warning indicators were found. " +
                "A low score does not guarantee that a message is safe.";
        }
    }
}


/* ---------- DETERMINE RISK LEVEL ---------- */

function determineRiskLevel(scoreValue) {
    const score = Number(scoreValue);

    if (!Number.isFinite(score)) {
        return "Low";
    }

    if (score >= 50) {
        return "High";
    }

    if (score >= 25) {
        return "Medium";
    }

    return "Low";
}


/* ---------- RISK BADGE COLOURS ---------- */

function updateRiskBadge(riskLevel, badge) {
    if (!badge) return;

    const level = String(riskLevel).toLowerCase();

    badge.classList.remove(
        "high-risk",
        "medium-risk",
        "low-risk"
    );

    if (level === "high") {
        badge.textContent = "HIGH RISK";
        badge.style.backgroundColor = "#FDE8E7";
        badge.style.color = "#C62828";
        badge.classList.add("high-risk");

    } else if (level === "medium") {
        badge.textContent = "MEDIUM RISK";
        badge.style.backgroundColor = "#FFF0D5";
        badge.style.color = "#B76500";
        badge.classList.add("medium-risk");

    } else {
        badge.textContent = "LOW RISK";
        badge.style.backgroundColor = "#DCFCE7";
        badge.style.color = "#218838";
        badge.classList.add("low-risk");
    }
}


/* ---------- DETECTION REASONS ---------- */

function displayReasons(reasons) {
    if (!reasonsList) return;

    reasonsList.replaceChildren();

    if (!Array.isArray(reasons) || reasons.length === 0) {
        const item = document.createElement("li");
        item.textContent =
            "No specific detection details were provided.";
        reasonsList.appendChild(item);
        return;
    }

    reasons.forEach(function (reason) {
        const item = document.createElement("li");
        item.textContent = String(reason);
        reasonsList.appendChild(item);
    });
}


/* ---------- SHOW ERROR ---------- */

function showError(message) {
    if (!errorMessage) {
        console.error(message);
        return;
    }

    errorMessage.textContent = message;
    errorMessage.hidden = false;
    errorMessage.style.display = "block";
}


/* ---------- CLEAR ERROR ---------- */

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


/* ---------- NAVIGATION ---------- */

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


/* ---------- READY ---------- */

console.log("PishGuard AI frontend initialized.");
console.log("Backend endpoint:", API_URL);