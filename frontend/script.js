
/*
 * PishGuard - AI Scam and Phishing Detector
 * Simple, clear results for non-technical users.
 */

const API_BASE_URL = "http://127.0.0.1:5000";

const form = document.getElementById("scanForm");
const messageInput = document.getElementById("message");
const urlInput = document.getElementById("url");
const detectButton = document.getElementById("detectBtn");
const buttonText = document.getElementById("buttonText");
const resultBox = document.getElementById("result");
const charCount = document.getElementById("charCount");

// --------------------------------------------------
// 1. CHARACTER COUNTER
// --------------------------------------------------

messageInput.addEventListener("input", () => {
  const count = messageInput.value.length;

  charCount.textContent =
    `${count} character${count === 1 ? "" : "s"}`;
});

// --------------------------------------------------
// 2. FORM SUBMISSION
// --------------------------------------------------

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  await detectScam();
});

// --------------------------------------------------
// 3. SEND INPUT TO THE BACKEND
// --------------------------------------------------

async function detectScam() {
  const message = messageInput.value.trim();
  const url = urlInput.value.trim();

  if (!message && !url) {
    showError("Please enter a message or website address to check.");
    return;
  }

  detectButton.disabled = true;
  buttonText.textContent = "Checking...";
  resultBox.hidden = false;
  showLoading();

  try {
    const response = await fetch(`${API_BASE_URL}/api/detect`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ message, url })
    });

    const contentType = response.headers.get("content-type") || "";

    if (!contentType.includes("application/json")) {
      throw new Error("The server returned an unexpected response.");
    }

    const data = await response.json();

    if (!response.ok) {
      throw new Error(
        typeof data.error === "string"
          ? data.error
          : "The analysis could not be completed."
      );
    }

    displayResult(data);
  } catch (error) {
    console.error("PishGuard error:", error);

    showError(
      "Unable to connect to PishGuard. Make sure the backend is running, then try again."
    );
  } finally {
    detectButton.disabled = false;
    buttonText.textContent = "Analyse for scams";
  }
}

// --------------------------------------------------
// 4. MAP BACKEND AND GEMINI REASONS TO EXPLANATIONS
// --------------------------------------------------

function getExplanation(reason) {
  const text = String(reason || "").trim().toLowerCase();

  // Prize and reward claims
  if (
    text.includes("prize") ||
    text.includes("reward claim") ||
    text.includes("free-money") ||
    text.includes("free money") ||
    text.includes("winning a prize")
  ) {
    return {
      key: "prize",
      title: "Unexpected prize claim",
      explanation:
        "The message claims you have won a prize. Unexpected rewards can be used to trick people into paying fees or revealing personal information.",
      advice:
        "Verify the offer independently. Never pay a fee to claim an unexpected prize."
    };
  }

  // Urgency and pressure
  if (
    text.includes("urgency") ||
    text.includes("urgent") ||
    text.includes("claim it now") ||
    text.includes("act immediately") ||
    text.includes("limited-time") ||
    text.includes("limited time") ||
    text.includes("pressure to act") ||
    text.includes("immediate action")
  ) {
    return {
      key: "urgency",
      title: "Pressure to act quickly",
      explanation:
        "The wording encourages immediate action, which can make it harder to check whether the request is genuine.",
      advice:
        "Pause and verify the request before taking action."
    };
  }

  // Sender identity and missing context
  if (
    text.includes("lack of legitimate context") ||
    text.includes("sender identity") ||
    text.includes("contest details") ||
    text.includes("unverified sender") ||
    text.includes("sender is unknown") ||
    text.includes("no legitimate context")
  ) {
    return {
      key: "verification",
      title: "Offer details cannot be verified",
      explanation:
        "The message does not provide enough information to establish who sent it or whether the offer is genuine.",
      advice:
        "Verify the sender and offer using an independent, official source."
    };
  }

  // OTPs
  if (
    text.includes("otp") ||
    text.includes("one-time password") ||
    text.includes("one time password")
  ) {
    return {
      key: "otp",
      title: "Risk involving your OTP",
      explanation:
        "A request to reveal a one-time password may allow someone to access an account or approve a transaction.",
      advice:
        "Never share an OTP with another person."
    };
  }

  // Passwords and credentials
  if (
    text.includes("password") ||
    text.includes("login credential") ||
    text.includes("login details") ||
    text.includes("account credentials")
  ) {
    return {
      key: "password",
      title: "Risk involving your password",
      explanation:
        "A request for login details may be an attempt to gain unauthorised access to your account.",
      advice:
        "Never share your password. If you already disclosed it, change it through the official service."
    };
  }

  // Requests for money or payment
  if (
    text.includes("money transfer") ||
    text.includes("send money") ||
    text.includes("payment demand") ||
    text.includes("payment requested") ||
    text.includes("upfront fee") ||
    text.includes("registration fee") ||
    text.includes("pay first") ||
    text.includes("payment")
  ) {
    return {
      key: "payment",
      title: "Payment request needs verification",
      explanation:
        "Unexpected payment demands can be used to obtain money under false pretences.",
      advice:
        "Verify the recipient and the reason for payment independently before paying."
    };
  }

  // Job and earning claims
  if (
    text.includes("job") ||
    text.includes("work-from-home") ||
    text.includes("work from home") ||
    text.includes("guaranteed income") ||
    text.includes("earning claim") ||
    text.includes("recruiter")
  ) {
    return {
      key: "job",
      title: "Job or earning offer needs checking",
      explanation:
        "Fraudulent offers may promise easy income or request money before providing genuine work.",
      advice:
        "Verify the employer independently, and be cautious of requests for advance fees."
    };
  }

  // Account verification and threats
  if (
    text.includes("account verification") ||
    text.includes("identity verification") ||
    text.includes("verify your account") ||
    text.includes("account-blocking") ||
    text.includes("account blocked") ||
    text.includes("account will be blocked") ||
    text.includes("account suspension") ||
    text.includes("impersonation") ||
    text.includes("pretending to be")
  ) {
    return {
      key: "account",
      title: "Account warning or identity claim",
      explanation:
        "A message may imitate a trusted organisation or threaten account restrictions to make you respond without checking.",
      advice:
        "Check directly through the organisation's official app, website, or contact number."
    };
  }

  // Suspicious links
  if (
    text.includes("click a link") ||
    text.includes("deceptive link") ||
    text.includes("suspicious link") ||
    text.includes("phishing link") ||
    text.includes("fake website") ||
    text.includes("malicious link")
  ) {
    return {
      key: "link",
      title: "Link may lead to an unsafe website",
      explanation:
        "Unexpected or deceptive links can lead to pages designed to steal login details or personal information.",
      advice:
        "Avoid opening unexpected links. Visit the official website directly."
    };
  }

  // URL-related checks
  if (
    text.includes("embedded username") ||
    text.includes("embedded password")
  ) {
    return {
      key: "url-credentials",
      title: "Unusual website address",
      explanation:
        "The URL contains a username or password component, which can obscure the destination.",
      advice:
        "Avoid opening it and find the official website independently."
    };
  }

  if (
    text.includes("internationalized domain") ||
    text.includes("similar-looking") ||
    text.includes("lookalike domain") ||
    text.includes("look-alike domain")
  ) {
    return {
      key: "url-domain",
      title: "Website domain needs extra checking",
      explanation:
        "Some domains use characters that resemble those in familiar website names.",
      advice:
        "Check the exact spelling of the domain before entering information."
    };
  }

  if (
    text.includes("ip address") ||
    text.includes("numeric address")
  ) {
    return {
      key: "url-ip",
      title: "Website uses a numeric address",
      explanation:
        "The website uses an IP address instead of a familiar domain name. This is not proof of fraud, but it deserves checking.",
      advice:
        "Verify the destination before entering sensitive information."
    };
  }

  if (
    text.includes("http rather than") ||
    text.includes("not encrypted") ||
    text.includes("no https") ||
    text.includes("tls") ||
    text.includes("https")
  ) {
    return {
      key: "url-encryption",
      title: "Website security needs checking",
      explanation:
        "The website may not have a properly secured connection. Connection security alone does not establish whether a site is legitimate.",
      advice:
        "Do not enter passwords or payment details unless you have verified the site and its connection."
    };
  }

  if (
    text.includes("invalid url") ||
    text.includes("hostname is missing") ||
    text.includes("unsupported url scheme") ||
    text.includes("complete domain") ||
    text.includes("url structure")
  ) {
    return {
      key: "url-invalid",
      title: "Website address looks incorrect",
      explanation:
        "PishGuard could not recognise the address as a normal website address.",
      advice:
        "Check the spelling and obtain the correct address from an official source."
    };
  }

  // Machine-learning findings
  if (
    text.includes("machine-learning") ||
    text.includes("machine learning") ||
    text.includes("model flagged") ||
    text.includes("classifier")
  ) {
    return {
      key: "ml",
      title: "Message resembles suspicious examples",
      explanation:
        "The machine-learning model found patterns associated with suspicious messages. Models can make mistakes, so this is not proof of fraud.",
      advice:
        "Review the message and verify the sender before acting."
    };
  }

  // Generic AI findings: display the actual reason, not repeated filler.
  return {
    key: `other:${text}`,
    title: "Additional finding",
    explanation: String(reason),
    advice:
      "Check this finding independently before sharing information, clicking links, or sending money."
  };
}

// --------------------------------------------------
// 5. CREATE SAFE PAGE ELEMENTS
// --------------------------------------------------

function makeElement(tag, className = "", text = "") {
  const element = document.createElement(tag);

  if (className) {
    element.className = className;
  }

  // textContent prevents input or AI text from being interpreted as HTML.
  element.textContent = text;
  return element;
}

// --------------------------------------------------
// 6. LOADING AND ERROR MESSAGES
// --------------------------------------------------

function showLoading() {
  resultBox.replaceChildren();

  resultBox.append(
    makeElement("h2", "", "Checking your input..."),
    makeElement(
      "p",
      "",
      "PishGuard is looking for possible warning signs."
    )
  );
}

function showError(message) {
  resultBox.hidden = false;
  resultBox.replaceChildren();

  resultBox.append(
    makeElement("h2", "", "Analysis Unavailable"),
    makeElement("p", "result-error", message)
  );

  resultBox.scrollIntoView({
    behavior: "smooth",
    block: "nearest"
  });
}

// --------------------------------------------------
// 7. DISPLAY RESULTS WITHOUT DUPLICATE EXPLANATIONS
// --------------------------------------------------

function displayResult(data) {
  resultBox.replaceChildren();
  resultBox.hidden = false;

  const suspicious = data.is_suspicious === true;

  const backendReasons = Array.isArray(data.reasons)
    ? data.reasons.filter(
        (reason) =>
          typeof reason === "string" && reason.trim().length > 0
      )
    : [];

  const aiAnalysis =
    data.ai_analysis && typeof data.ai_analysis === "object"
      ? data.ai_analysis
      : {};

  const aiReasons = Array.isArray(aiAnalysis.reasons)
    ? aiAnalysis.reasons.filter(
        (reason) =>
          typeof reason === "string" && reason.trim().length > 0
      )
    : [];

  // Main result heading
  resultBox.appendChild(
    makeElement(
      "h2",
      suspicious
        ? "result-heading result-danger"
        : "result-heading result-safe",
      suspicious
        ? "⚠️ Possible Scam Detected"
        : "✓ No Obvious Scam Signs Found"
    )
  );

  resultBox.appendChild(
    makeElement(
      "p",
      "result-status",
      suspicious
        ? "PishGuard found warning signs. Review the evidence below."
        : "No clear warning signs were found. This does not guarantee the input is safe."
    )
  );

  // Combine backend and Gemini findings.
  // Deduplicate by explanation key so related rule labels become one card.
  const uniqueExplanations = new Map();

  [...backendReasons, ...aiReasons].forEach((reason) => {
    const explanation = getExplanation(reason);

    if (!uniqueExplanations.has(explanation.key)) {
      uniqueExplanations.set(explanation.key, explanation);
    }
  });

  resultBox.appendChild(
    makeElement("h3", "", "Why was it flagged?")
  );

  if (uniqueExplanations.size > 0) {
    const list = makeElement("ul", "explanation-list");

    uniqueExplanations.forEach((explanation) => {
      const item = makeElement("li", "explanation-item");

      item.appendChild(
        makeElement("strong", "", explanation.title)
      );

      item.appendChild(
        makeElement("p", "", explanation.explanation)
      );

      list.appendChild(item);
    });

    resultBox.appendChild(list);
  } else {
    resultBox.appendChild(
      makeElement(
        "p",
        "",
        "No specific warning signs were returned. Verify the message or website independently."
      )
    );
  }

  // Practical safety advice
  resultBox.appendChild(
    makeElement("h3", "", "What should you do?")
  );

  const adviceList = makeElement("ul", "safety-list");

  const safetyAdvice = suspicious
    ? [
        "Do not share OTPs, passwords, or bank details.",
        "Do not click unexpected links or send money before verification.",
        "Verify the request using official contact details."
      ]
    : [
        "Check the sender and website address.",
        "Never share OTPs or passwords.",
        "Verify unexpected requests before acting."
      ];

  safetyAdvice.forEach((advice) => {
    adviceList.appendChild(makeElement("li", "", advice));
  });

  resultBox.appendChild(adviceList);

  // State which checks actually ran
  const checks = [];

  if (data.message_model_performed) {
    checks.push("message analysis");
  }

  if (data.url_check_performed) {
    checks.push("basic URL structure check");
  }

  if (data.ai_model_performed || aiAnalysis.available === true) {
    checks.push("Gemini AI analysis");
  }

  if (checks.length > 0) {
    resultBox.appendChild(
      makeElement(
        "p",
        "result-note",
        `Checks performed: ${[...new Set(checks)].join(", ")}.`
      )
    );
  }

  // Explain AI availability without implying that unavailable means safe.
  if (aiAnalysis.available === false) {
    resultBox.appendChild(
      makeElement(
        "p",
        "result-note",
        "Gemini AI analysis was unavailable for this scan. The result may rely on other checks."
      )
    );
  }

  resultBox.appendChild(
    makeElement(
      "p",
      "result-note",
      "Important: This is an automated assessment, not proof of fraud. Website reputation and website content are not verified by these basic checks."
    )
  );

  resultBox.scrollIntoView({
    behavior: "smooth",
    block: "nearest"
  });
}
