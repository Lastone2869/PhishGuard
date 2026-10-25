// PhishGuard frontend controller.
// The UI treats the message as a specimen: plain text, defanged links, and
// highlighted evidence. No submitted link is ever opened.

const SAMPLES = {
  vit_phish: {
    text: "URGENT: Your VIT Student Account will be suspended within 24 hours due to unverified KYC. Click here immediately to verify: http://vit-account-verify.info/login",
    sender: "admin@vit-support-desk.com",
  },
  vit_legit: {
    text: "Dear Student, the timetable for Winter Semester 2026-27 is now published on VTOP. Please review your slot allotments on the official portal.",
    sender: "academics@vit.ac.in",
  },
  gpay_phish: {
    text: "ALERT: Your Google Pay (GPay) account has been limited due to suspicious transactions. Click immediately to re-verify your UPI PIN: http://gpay-upi-verify.info/login",
    sender: "security@gpay-support-desk.com",
  },
  peer_chat: {
    text: "Hi John, are we still meeting tomorrow at 10 AM in the library to discuss our compiler design assignment?",
    sender: "alex.dev@gmail.com",
  },
};

const EVIDENCE_TITLES = {
  sender_mismatch: "The sender does not match the claim",
  credential_request: "The message asks for credentials",
  urgency: "The message creates urgency",
  suspicious_links: "The link structure is suspicious",
  ml_keywords: "The wording matches known phishing",
};

let lastAnalysedText = "";

function loadSample(key) {
  const sample = SAMPLES[key];
  if (!sample) return;

  document.getElementById("msg-text").value = sample.text;
  document.getElementById("msg-sender").value = sample.sender;

  const status = document.getElementById("form-status");
  if (status) status.textContent = "";

  document.getElementById("msg-text").focus();
}

// Allow Ctrl+Enter / Cmd+Enter to analyse.
document.addEventListener("keydown", (event) => {
  if ((event.ctrlKey || event.metaKey) && event.key === "Enter") {
    const form = document.getElementById("analyse-form");
    if (form) form.requestSubmit();
  }
});

async function handleAnalyse(event) {
  event.preventDefault();

  const textInput = document.getElementById("msg-text").value.trim();
  const senderInput = document.getElementById("msg-sender").value.trim();
  const submitBtn = document.getElementById("btn-submit");
  const status = document.getElementById("form-status");

  if (!textInput) {
    status.textContent = "Paste a message to analyse.";
    return;
  }

  status.textContent = "";
  submitBtn.disabled = true;
  submitBtn.textContent = "Analysing...";
  submitBtn.setAttribute("aria-busy", "true");

  try {
    const response = await fetch("/api/analyse", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text: textInput, sender: senderInput || null }),
    });

    if (!response.ok) {
      let detail = "Analysis failed.";
      try {
        const errorBody = await response.json();
        detail = errorBody.detail || detail;
      } catch (parseError) {
        detail = response.statusText || detail;
      }
      throw new Error(detail);
    }

    const data = await response.json();
    lastAnalysedText = textInput;
    renderResults(data);
  } catch (error) {
    status.textContent = "Could not analyse that message. " + error.message;
  } finally {
    submitBtn.disabled = false;
    submitBtn.textContent = "Analyse message";
    submitBtn.removeAttribute("aria-busy");
  }
}

function renderResults(data) {
  const card = document.getElementById("results-card");
  card.classList.remove("hidden");
  card.classList.remove("is-revealed");
  void card.offsetWidth;
  card.classList.add("is-revealed");

  const empty = document.getElementById("results-empty");
  if (empty) empty.classList.add("hidden");

  const badge = document.getElementById("verdict-badge");
  badge.textContent = displayLabel(data.label);
  badge.className = "verdict-badge";
  if (data.badge_color === "red") {
    badge.classList.add("badge-red");
  } else if (data.badge_color === "amber") {
    badge.classList.add("badge-amber");
  } else {
    badge.classList.add("badge-emerald");
  }

  const scoreNum = document.getElementById("score-num");
  const meterFill = document.getElementById("meter-fill");
  const percent = Math.round(data.composite_score * 100);
  scoreNum.textContent = data.composite_score.toFixed(2);
  meterFill.style.width = percent + "%";
  if (percent >= 70) {
    meterFill.style.backgroundColor = "var(--color-danger)";
  } else if (percent >= 35) {
    meterFill.style.backgroundColor = "var(--color-warn)";
  } else {
    meterFill.style.backgroundColor = "var(--color-safe)";
  }

  const signals = data.signals || {};
  const urgency = signals.urgency || {};
  const credentials = signals.credential_request || {};
  const links = signals.suspicious_links || {};
  const sender = signals.sender_mismatch || {};

  updateSignalRow(
    "sig-urgency",
    "sig-urgency-status",
    urgency.present ? "Detected, " + urgency.strength + " strength" : "Not detected",
    urgency.present ? "is-on" : "is-off"
  );
  updateSignalRow(
    "sig-cred",
    "sig-cred-status",
    credentials.present
      ? "Detected, " + credentials.strength + " strength"
      : "Not detected",
    credentials.present ? "is-on" : "is-off"
  );

  const extracted = Array.isArray(links.extracted_urls) ? links.extracted_urls : [];
  updateSignalRow(
    "sig-url",
    "sig-url-status",
    links.present
      ? "Suspicious structure"
      : extracted.length
        ? "Links found, no obvious trick"
        : "No links",
    links.present ? "is-on" : "is-off"
  );

  let senderText = "Not provided";
  let senderClass = "is-off";
  if (sender.status === "lookalike_impersonation") {
    senderText = "Impersonation warning";
    senderClass = "is-on";
  } else if (sender.status === "verified_official") {
    senderText = "Verified official";
    senderClass = "is-verified";
  } else if (sender.status === "verified_external") {
    senderText = "Verified external";
    senderClass = "is-verified";
  } else if (sender.status === "unverified_external") {
    senderText = "Unverified external";
    senderClass = "is-off";
  }
  updateSignalRow("sig-sender", "sig-sender-status", senderText, senderClass);

  const recEl = document.getElementById("verdict-recommendation");
  if (recEl) {
    if (data.recommendation) {
      recEl.textContent = data.recommendation;
      recEl.classList.remove("hidden");
    } else {
      recEl.classList.add("hidden");
    }
  }

  const defangedContainer = document.getElementById("defanged-container");
  const defangedList = document.getElementById("defanged-list");
  if (data.defanged_urls && data.defanged_urls.length > 0) {
    defangedContainer.classList.remove("hidden");
    defangedList.innerHTML = data.defanged_urls
      .map((url) => `<div class="defanged-url">${escapeHtml(url)}</div>`)
      .join("");
  } else {
    defangedContainer.classList.add("hidden");
  }

  const expContainer = document.getElementById("explanation-list");
  if (data.ranked_explanations && data.ranked_explanations.length > 0) {
    expContainer.innerHTML = data.ranked_explanations
      .map(
        (exp) => `
      <li class="exp-item ${escapeHtml(exp.severity || "info")}">
        <div>
          <p class="exp-title">${escapeHtml(EVIDENCE_TITLES[exp.type] || exp.title)}</p>
          <p class="exp-desc">${escapeHtml(exp.description)}</p>
        </div>
      </li>`
      )
      .join("");
  } else {
    expContainer.innerHTML = `
      <li class="exp-item info">
        <div>
          <p class="exp-title">No strong signals found</p>
          <p class="exp-desc">The message does not show the pressure tactics, credential requests, or link patterns this tool checks for.</p>
        </div>
      </li>`;
  }

  const annotated = document.getElementById("annotated-message");
  if (annotated) annotated.innerHTML = annotateMessage(lastAnalysedText, data);

  const specimen = document.querySelector(".specimen");
  if (specimen) specimen.open = true;

  const actionList = document.getElementById("action-list");
  if (actionList && Array.isArray(data.what_to_do_now) && data.what_to_do_now.length > 0) {
    actionList.innerHTML = data.what_to_do_now
      .map((item) => `<li>${escapeHtml(item)}</li>`)
      .join("");
  }

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

  const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  card.scrollIntoView({ behavior: reduceMotion ? "auto" : "smooth", block: "start" });
}

function updateSignalRow(cardId, statusId, text, statusClass) {
  const card = document.getElementById(cardId);
  const status = document.getElementById(statusId);
  if (!card || !status) return;
  card.className = "signal-row " + (statusClass || "is-off");
  status.textContent = text;
}

function displayLabel(label) {
  if (label === "High Risk") return "High risk";
  if (label === "Low Risk") return "Low risk";
  if (label === "Uncertain / Review Manually") return "Uncertain, review manually";
  return label || "Assessment";
}

function annotateMessage(text, data) {
  if (!text) return "";

  const defanged = defangText(text);
  const signals = data.signals || {};
  const urgency = (signals.urgency && signals.urgency.matches) || [];
  const credentials =
    (signals.credential_request && signals.credential_request.matches) || [];

  const spans = [
    ...findSpans(defanged, urgency, "urgency"),
    ...findSpans(defanged, credentials, "credential"),
    ...findSpans(defanged, data.defanged_urls || [], "link"),
  ];
  const merged = mergeSpans(spans);

  if (merged.length === 0) return escapeHtml(defanged);

  let html = "";
  let cursor = 0;
  for (const span of merged) {
    html += escapeHtml(defanged.slice(cursor, span.start));
    html += `<mark class="mark-${span.type}">${escapeHtml(
      defanged.slice(span.start, span.end)
    )}</mark>`;
    cursor = span.end;
  }
  html += escapeHtml(defanged.slice(cursor));
  return html;
}

function findSpans(text, phrases, type) {
  const spans = [];
  const seen = new Set();
  const lower = text.toLowerCase();

  for (const phrase of phrases) {
    if (!phrase || String(phrase).length < 3) continue;
    const needle = String(phrase).toLowerCase();
    if (seen.has(needle)) continue;
    seen.add(needle);

    let from = 0;
    while (from < lower.length) {
      const index = lower.indexOf(needle, from);
      if (index === -1) break;
      spans.push({ start: index, end: index + needle.length, type });
      from = index + needle.length;
      if (spans.length > 80) return spans;
    }
  }
  return spans;
}

function mergeSpans(spans) {
  spans.sort(
    (a, b) => a.start - b.start || b.end - b.start - (a.end - a.start)
  );

  const merged = [];
  let cursor = 0;
  for (const span of spans) {
    if (span.start < cursor) continue;
    merged.push(span);
    cursor = span.end;
  }
  return merged;
}

function defangText(text) {
  return text.replace(/https?:\/\/[^\s<>"']+|www\.[^\s<>"']+/gi, (raw) => {
    const trailingMatch = raw.match(/[.,;:!?)]+$/);
    const trailing = trailingMatch ? trailingMatch[0] : "";
    const core = trailing ? raw.slice(0, -trailing.length) : raw;
    return defangUrl(core) + trailing;
  });
}

function defangUrl(raw) {
  let url = raw
    .replace(/^https:\/\//i, "hxxps://")
    .replace(/^http:\/\//i, "hxxp://");

  const hostMatch = url.match(/^(?:hxxps?:\/\/)?([^/?#]+)/i);
  if (hostMatch) {
    const host = hostMatch[1];
    url = url.replace(host, host.replace(/\./g, "[.]"));
  }
  return url;
}

function escapeHtml(value) {
  return String(value == null ? "" : value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}
