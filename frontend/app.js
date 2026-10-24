// PhishGuard Frontend Controller (Stage 1 Core)

const SAMPLES = {
  vit_phish: {
    text: "URGENT: Your VIT Student Account will be suspended within 24 hours due to unverified KYC. Click here immediately to verify: http://vit-account-verify.info/login",
    sender: "admin@vit-support-desk.com"
  },
  vit_legit: {
    text: "Dear Student, The timetable for Winter Semester 2026-27 is now published on VTOP. Please review your slot allotments on the official portal.",
    sender: "academics@vit.ac.in"
  },
  gpay_phish: {
    text: "ALERT: Your Google Pay (GPay) account has been limited due to suspicious transactions. Click immediately to re-verify your UPI PIN: http://gpay-upi-verify.info/login",
    sender: "security@gpay-support-desk.com"
  },
  paypal_phish: {
    text: "ALERT: Your Google Pay (GPay) account has been limited due to suspicious transactions. Click immediately to re-verify your UPI PIN: http://gpay-upi-verify.info/login",
    sender: "security@gpay-support-desk.com"
  },
  peer_chat: {
    text: "Hi John, are we still meeting tomorrow at 10 AM in the library to discuss our compiler design assignment?",
    sender: "alex.dev@gmail.com"
  }
};

function loadSample(key) {
  const sample = SAMPLES[key];
  if (!sample) return;
  document.getElementById("msg-text").value = sample.text;
  document.getElementById("msg-sender").value = sample.sender;
}

// Allow Ctrl+Enter to submit
document.addEventListener("keydown", (e) => {
  if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
    const form = document.getElementById("analyse-form");
    if (form) form.requestSubmit();
  }
});

async function handleAnalyse(event) {
  event.preventDefault();
  const textInput = document.getElementById("msg-text").value.trim();
  const senderInput = document.getElementById("msg-sender").value.trim();
  const submitBtn = document.getElementById("btn-submit");

  if (!textInput) {
    alert("Please enter message content to analyse.");
    return;
  }

  submitBtn.disabled = true;
  submitBtn.innerText = "Analysing...";

  try {
    const response = await fetch("/api/analyse", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        text: textInput,
        sender: senderInput || null
      })
    });

    if (!response.ok) {
      const err = await response.json();
      throw new Error(err.detail || "Analysis request failed.");
    }

    const data = await response.json();
    renderResults(data);
  } catch (error) {
    console.error("Analysis Error:", error);
    alert("Analysis failed: " + error.message);
  } finally {
    submitBtn.disabled = false;
    submitBtn.innerHTML = "<span>Analyse Message</span> <span aria-hidden='true'>&rarr;</span>";
  }
}

function renderResults(data) {
  const card = document.getElementById("results-card");
  card.classList.remove("hidden");

  // 1. Verdict & Color
  const badge = document.getElementById("verdict-badge");
  badge.textContent = data.label;
  badge.className = "verdict-badge";
  if (data.badge_color === "red") {
    badge.classList.add("badge-red");
  } else if (data.badge_color === "amber") {
    badge.classList.add("badge-amber");
  } else {
    badge.classList.add("badge-emerald");
  }

  // 2. Score Meter
  const scoreNum = document.getElementById("score-num");
  const meterFill = document.getElementById("meter-fill");
  const pct = Math.round(data.composite_score * 100);
  scoreNum.textContent = (data.composite_score).toFixed(2);
  meterFill.style.width = pct + "%";
  if (pct >= 70) {
    meterFill.style.backgroundColor = "var(--color-danger)";
  } else if (pct >= 35) {
    meterFill.style.backgroundColor = "var(--color-warn)";
  } else {
    meterFill.style.backgroundColor = "var(--color-safe)";
  }

  // 3. Signals Breakdown
  const sigs = data.signals;
  updateSignalCard("sig-urgency", "sig-urgency-status", sigs.urgency.present ? "Detected (" + sigs.urgency.strength + ")" : "None", sigs.urgency.present ? "active" : "");
  updateSignalCard("sig-cred", "sig-cred-status", sigs.credential_request.present ? "Detected (" + sigs.credential_request.strength + ")" : "None", sigs.credential_request.present ? "active" : "");
  updateSignalCard("sig-url", "sig-url-status", sigs.suspicious_links.present ? "High Risk Structure" : (sigs.suspicious_links.extracted_urls.length > 0 ? "Standard URL" : "No Links"), sigs.suspicious_links.present ? "active" : "");
  
  const senderStatus = sigs.sender_mismatch.status;
  let senderClass = "";
  let senderText = "Not Provided";
  if (senderStatus === "lookalike_impersonation") {
    senderText = "Impersonation Warning!";
    senderClass = "active";
  } else if (senderStatus === "verified_official") {
    senderText = "Verified Official";
    senderClass = "verified";
  } else if (senderStatus === "verified_external") {
    senderText = "Verified External";
    senderClass = "verified";
  } else if (senderStatus === "unverified_external") {
    senderText = "Unverified External";
  }
  updateSignalCard("sig-sender", "sig-sender-status", senderText, senderClass);

  // 4. Recommendation Banner
  const recEl = document.getElementById("verdict-recommendation");
  if (recEl) {
    if (data.recommendation) {
      recEl.textContent = data.recommendation;
      recEl.classList.remove("hidden");
    } else {
      recEl.classList.add("hidden");
    }
  }

  // 5. Defanged URLs
  const defangedContainer = document.getElementById("defanged-container");
  const defangedList = document.getElementById("defanged-list");
  if (data.defanged_urls && data.defanged_urls.length > 0) {
    defangedContainer.classList.remove("hidden");
    defangedList.innerHTML = data.defanged_urls.map(u => `<div class="defanged-url">${escapeHtml(u)}</div>`).join("");
  } else {
    defangedContainer.classList.add("hidden");
  }

  // 6. Ranked Explanations
  const expContainer = document.getElementById("explanation-list");
  if (data.ranked_explanations && data.ranked_explanations.length > 0) {
    expContainer.innerHTML = data.ranked_explanations.map(exp => `
      <div class="exp-item ${exp.severity}">
        <div class="exp-title">${escapeHtml(exp.title)}</div>
        <div class="exp-desc">${escapeHtml(exp.description)}</div>
      </div>
    `).join("");
  } else {
    expContainer.innerHTML = `
      <div class="exp-item info">
        <div class="exp-title">Normal Message Characteristics</div>
        <div class="exp-desc">The message does not display structural indicators or language patterns common to credential harvesting or phishing scams.</div>
      </div>
    `;
  }

  // 7. Recommended Student Actions
  const actionList = document.getElementById("action-list");
  if (actionList && Array.isArray(data.what_to_do_now) && data.what_to_do_now.length > 0) {
    actionList.innerHTML = data.what_to_do_now.map(item => `<li>${escapeHtml(item)}</li>`).join("");
  }

  // 8. Reporting Contacts
  if (data.reporting_guidance) {
    const helpdeskEl = document.getElementById("contact-helpdesk");
    const portalEl = document.getElementById("contact-portal");
    if (helpdeskEl && data.reporting_guidance.institution_helpdesk) {
      helpdeskEl.textContent = data.reporting_guidance.institution_helpdesk;
    }
    if (portalEl && data.reporting_guidance.national_cyber_portal) {
      portalEl.textContent = data.reporting_guidance.national_cyber_portal;
    }
  }

  // Scroll to results smoothly
  card.scrollIntoView({ behavior: "smooth", block: "start" });
}

function updateSignalCard(cardId, statusId, text, statusClass) {
  const card = document.getElementById(cardId);
  const status = document.getElementById(statusId);
  card.className = "signal-card " + (statusClass || "");
  status.textContent = text;
}

function escapeHtml(str) {
  if (!str) return "";
  return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}
