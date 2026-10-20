/*
 * Replace this with your friend's deployed backend URL
 * after deployment is complete.
 */
const API_BASE_URL = "http://127.0.0.1:5000";

const form = document.getElementById("scanForm");
const messageInput = document.getElementById("message");
const urlInput = document.getElementById("url");
const detectButton = document.getElementById("detectBtn");
const buttonText = document.getElementById("buttonText");
const resultBox = document.getElementById("result");
const charCount = document.getElementById("charCount");

messageInput.addEventListener("input", () => {
  const count = messageInput.value.length;

  charCount.textContent =
    `${count} character${count === 1 ? "" : "s"}`;
});

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  await detectScam();
});

async function detectScam() {
  const message = messageInput.value.trim();
  const url = urlInput.value.trim();

  if (!message && !url) {
    showError("Please enter a message or URL before starting the analysis.");
    return;
  }

  detectButton.disabled = true;
  buttonText.textContent = "Analysing input...";

  resultBox.hidden = false;
  showLoading();

  try {
    const response = await fetch(`${API_BASE_URL}/api/detect`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        message: message,
        url: url
      })
    });

    const contentType = response.headers.get("content-type") || "";

    if (!contentType.includes("application/json")) {
      throw new Error(
        `Unexpected server response (HTTP ${response.status}).`
      );
    }

    const data = await response.json();

    if (!response.ok) {
      throw new Error(
        typeof data.note === "string"
          ? data.note
          : `The API request failed (HTTP ${response.status}).`
      );
    }

    displayResult(data);
  } catch (error) {
    console.error("Detection request failed:", error);

    showError(
      "We couldn't reach the detection service. Check the backend URL, " +
      "server status, and CORS settings, then try again."
    );
  } finally {
    detectButton.disabled = false;
    buttonText.textContent = "Analyse for scams";
  }
}

function showLoading() {
  resultBox.replaceChildren();

  const heading = document.createElement("h2");
  heading.textContent = "Analysis in progress";

  const paragraph = document.createElement("p");
  paragraph.textContent =
    "Waiting for the detection service to analyse your input...";

  resultBox.append(heading, paragraph);
}

function showError(message) {
  resultBox.hidden = false;
  resultBox.replaceChildren();

  const heading = document.createElement("h2");
  heading.textContent = "Unable to complete analysis";

  const paragraph = document.createElement("p");
  paragraph.className = "result-error";
  paragraph.textContent = message;

  resultBox.append(heading, paragraph);
}

function displayResult(data) {
  resultBox.replaceChildren();
  resultBox.hidden = false;

  const heading = document.createElement("h2");

  heading.textContent =
    typeof data.result === "string"
      ? data.result
      : "Analysis complete";

  resultBox.appendChild(heading);

  const status = document.createElement("p");
  status.className = "result-status";

  if (typeof data.is_suspicious === "boolean") {
    status.textContent = data.is_suspicious
      ? "⚠️ The detector flagged this input as suspicious."
      : "✓ The detector did not flag this input as suspicious.";

    status.style.color = data.is_suspicious
      ? "var(--danger)"
      : "var(--success)";
  } else {
    status.textContent =
      "Suspicious status was not provided as a Boolean value.";
  }

  resultBox.appendChild(status);

  const reasonsHeading = document.createElement("h3");
  reasonsHeading.textContent = "Why this result?";
  resultBox.appendChild(reasonsHeading);

  const reasonsList = document.createElement("ul");

  const reasons = Array.isArray(data.reasons)
    ? data.reasons
    : typeof data.reasons === "string" && data.reasons.trim()
      ? [data.reasons]
      : [];

  if (reasons.length > 0) {
    reasons.forEach((reason) => {
      const item = document.createElement("li");

      item.textContent =
        typeof reason === "string"
          ? reason
          : JSON.stringify(reason);

      reasonsList.appendChild(item);
    });
  } else {
    const item = document.createElement("li");
    item.textContent = "No specific reasons were returned by the API.";
    reasonsList.appendChild(item);
  }

  resultBox.appendChild(reasonsList);

  if (typeof data.note === "string" && data.note.trim()) {
    const note = document.createElement("p");
    note.className = "result-note";
    note.textContent = data.note;
    resultBox.appendChild(note);
  }

  const safetyNote = document.createElement("p");
  safetyNote.className = "result-note";
  safetyNote.textContent =
    "This result is not a guarantee. Verify unexpected requests " +
    "independently before sharing information or taking action.";

  resultBox.appendChild(safetyNote);

  resultBox.scrollIntoView({
    behavior: "smooth",
    block: "nearest"
  });
}
