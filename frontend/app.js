const api = "/api/v1";

let currentUser = null;
let socket = null;

const el = (id) => document.getElementById(id);


/* =========================
   HELPERS
========================= */

function pretty(data) {
  return JSON.stringify(data, null, 2);
}


function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}


function showToast(message) {
  const toast = el("toast");

  if (!toast) return;

  toast.innerText = message;
  toast.classList.add("show");

  setTimeout(() => {
    toast.classList.remove("show");
  }, 2500);
}


function addAlert(title, message, severity = "Info") {

  const container = el("alerts");

  if (!container) return;

  const empty = container.querySelector(".alert-empty");

  if (empty) {
    empty.remove();
  }

  const node = document.createElement("div");

  node.className = "alert-item";

  node.innerHTML = `
    <strong>${escapeHtml(severity)}: ${escapeHtml(title)}</strong>
    <span>${escapeHtml(message)}</span>
  `;

  container.prepend(node);
}


/* =========================
   API
========================= */

async function get(path) {

  const resp = await fetch(`${api}${path}`);

  if (!resp.ok) {
    throw new Error(await resp.text());
  }

  return resp.json();
}


async function post(path, body) {

  const resp = await fetch(`${api}${path}`, {

    method: "POST",

    headers: {
      "Content-Type": "application/json"
    },

    body: JSON.stringify(body)

  });

  if (!resp.ok) {
    throw new Error(await resp.text());
  }

  return resp.json();
}


/* =========================
   HEALTH CHECK
========================= */

async function checkHealth() {

  const pill = el("connectionPill");

  try {

    const resp = await fetch("/health");

    if (!resp.ok) {
      throw new Error("Backend unavailable");
    }

    const data = await resp.json();

    if (pill) {

      pill.innerHTML = `
        <span class="status-dot"></span>
        <span>System Online</span>
      `;

    }

    return data;

  } catch (error) {

    if (pill) {

      pill.innerHTML = `
        <span class="status-dot"
              style="background:#ef4444;box-shadow:none"></span>
        <span>Offline</span>
      `;

    }

    return null;
  }
}


/* =========================
   SESSION
========================= */

async function initializeSession() {

  const email = el("userEmail").value.trim();

  const name =
    el("userName").value.trim() ||
    "Demo User";


  if (!email) {

    el("sessionStatus").innerText =
      "Email is required";

    showToast("Enter your email first");

    return;
  }


  const user = await post(
    "/auth/register",
    {
      email,
      name
    }
  );


  currentUser = user;


  el("sessionStatus").innerHTML = `
    <span class="status-dot"></span>
    Connected as ${escapeHtml(user.email)}
  `;


  showToast("Secure session initialized");


  /* =========================
     WEBSOCKET
  ========================= */

  if (socket) {
    socket.close();
  }


  const wsProtocol =
    location.protocol === "https:"
      ? "wss"
      : "ws";


  socket = new WebSocket(
    `${wsProtocol}://${location.host}${api}/alerts/ws/${currentUser.id}`
  );


  socket.onopen = () => {

    socket.send("ready");

    addAlert(
      "WebSocket",
      "Real-time alert monitoring connected",
      "Info"
    );

  };


  socket.onmessage = (event) => {

    try {

      const payload =
        JSON.parse(event.data);

      addAlert(
        payload.title,
        payload.message,
        payload.severity
      );

    } catch {
      console.log(event.data);
    }

  };


  socket.onclose = () => {

    addAlert(
      "Socket Closed",
      "Real-time alerts disconnected",
      "Warn"
    );

  };


  await refreshDashboard();
}


/* =========================
   TEXT SCAN
========================= */

async function runTextScan() {

  if (!currentUser) {

    addAlert(
      "Session",
      "Start session first",
      "Warn"
    );

    return;
  }


  const content =
    el("scanText").value.trim();


  if (!content) {

    showToast("Enter text to scan");

    return;
  }


  const output = el("scanOutput");


  output.innerHTML = `
    <div class="result-placeholder">
      <span>⟳</span>
      <p>Scanning text...</p>
    </div>
  `;


  const result = await post(
    "/scan/text",
    {
      user_email: currentUser.email,
      user_name: currentUser.name,
      content
    }
  );


  renderScanResult(result);

  updateMetrics(result);

  showToast("PII scan completed");
}


/* =========================
   TEXT RESULT
========================= */

function renderScanResult(result) {

  const output = el("scanOutput");

  const findings =
    result.findings || [];


  const riskScore =
    Number(result.risk_score || 0);


  const riskLevel =
    result.risk_level || "Unknown";


  let findingsHtml = "";


  if (findings.length === 0) {

    findingsHtml = `
      <div class="alert-item">
        <strong>✓ No PII detected</strong>
        <span>
          No supported sensitive information was found.
        </span>
      </div>
    `;

  } else {

    findingsHtml =
      findings.map((item) => `

        <div class="alert-item">

          <strong>
            ${escapeHtml(item.entity_type)}
          </strong>

          <span>
            Detected:
            ${escapeHtml(item.original)}
          </span>

          <br>

          <span>
            Redacted:
            ${escapeHtml(item.redacted)}
          </span>

          <br>

          <span>
            Confidence:
            ${Number(item.confidence || 0).toFixed(2)}
          </span>

        </div>

      `).join("");
  }


  output.innerHTML = `

    <div class="section-number">
      SCAN RESULT
    </div>

    <h3 style="margin:8px 0">
      ✓ Scan Complete
    </h3>

    <div class="alert-item">

      <strong>
        Protected Output
      </strong>

      <span>
        ${escapeHtml(result.redacted_text || "")}
      </span>

    </div>

    <div style="margin-top:14px">

      <div class="metric-label">
        RISK SCORE
      </div>

      <div style="font-size:26px;font-weight:800">
        ${riskScore.toFixed(2)}
      </div>

      <div class="metric-sub">
        Risk Level: ${escapeHtml(riskLevel)}
      </div>

    </div>

    <div style="margin-top:16px">

      <div class="section-number">
        DETECTED INFORMATION
      </div>

      <div style="margin-top:10px">

        ${findingsHtml}

      </div>

    </div>

  `;
}


/* =========================
   IMAGE SCAN
========================= */

async function runImageScan() {

  if (!currentUser) {

    addAlert(
      "Session",
      "Start session first",
      "Warn"
    );

    return;
  }


  const file =
    el("scanImage").files[0];


  if (!file) {

    showToast("Select an image first");

    return;
  }


  const output =
    el("imageOutput");


  output.innerHTML = `
    <div class="result-placeholder">
      <span>⟳</span>
      <p>Running OCR and scanning image...</p>
    </div>
  `;


  const form =
    new FormData();


  form.append(
    "user_email",
    currentUser.email
  );

  form.append(
    "user_name",
    currentUser.name
  );

  form.append(
    "image",
    file
  );


  const resp =
    await fetch(
      `${api}/scan/image`,
      {
        method: "POST",
        body: form
      }
    );


  if (!resp.ok) {
    throw new Error(await resp.text());
  }


  const data =
    await resp.json();


  renderImageResult(data);

  updateMetrics(data);

  showToast("Image scan completed");
}


/* =========================
   IMAGE RESULT
========================= */

function renderImageResult(data) {

  const output =
    el("imageOutput");


  const findings =
    data.findings || [];


  output.innerHTML = `

    <div class="section-number">
      OCR SCAN RESULT
    </div>

    <h3 style="margin:8px 0">
      ✓ Image Processed
    </h3>

    <div class="alert-item">

      <strong>
        Protected Output
      </strong>

      <span>
        ${escapeHtml(data.redacted_text || "")}
      </span>

    </div>

    <div style="margin-top:14px">

      <div class="metric-label">
        PII ENTITIES DETECTED
      </div>

      <div style="font-size:28px;font-weight:800">
        ${findings.length}
      </div>

    </div>

  `;
}


/* =========================
   BREACH CHECK
========================= */

async function checkBreach() {

  if (!currentUser) {

    addAlert(
      "Session",
      "Start session first",
      "Warn"
    );

    return;
  }


  const output =
    el("breachOutput");


  output.innerHTML = `
    <div class="result-placeholder">
      <span>⟳</span>
      <p>Checking breach exposure...</p>
    </div>
  `;


  const data =
    await post(
      "/breach/check-email",
      {
        user_email:
          currentUser.email
      }
    );


  renderBreachResult(data);

  updateBreachMetrics(data);

  showToast("Breach check completed");
}


/* =========================
   BREACH RESULT
========================= */

function renderBreachResult(data) {

  const output =
    el("breachOutput");


  const count =
    Number(data.breach_count || 0);


  const score =
    Number(data.exposure_score || 0);


  const events =
    data.events || [];


  let eventsHtml = "";


  if (events.length === 0) {

    eventsHtml = `
      <div class="alert-item">

        <strong>
          ✓ No breach events found
        </strong>

        <span>
          No matching breach exposure was returned.
        </span>

      </div>
    `;

  } else {

    eventsHtml =
      events.map((event) => `

        <div class="alert-item">

          <strong>
            ${escapeHtml(
              event.name ||
              event.title ||
              "Breach Event"
            )}
          </strong>

          <span>
            ${escapeHtml(
              event.date ||
              event.breach_date ||
              ""
            )}
          </span>

        </div>

      `).join("");
  }


  output.innerHTML = `

    <div class="section-number">
      BREACH RESULT
    </div>

    <h3 style="margin:8px 0">
      Exposure Analysis
    </h3>

    <div class="metrics"
         style="padding:0;margin:12px 0;grid-template-columns:repeat(2,1fr)">

      <div class="metric-card">

        <div class="metric-label">
          BREACH COUNT
        </div>

        <div class="metric-value">
          ${count}
        </div>

      </div>

      <div class="metric-card">

        <div class="metric-label">
          EXPOSURE SCORE
        </div>

        <div class="metric-value">
          ${score}
        </div>

      </div>

    </div>

    <div class="section-number">
      EVENTS
    </div>

    <div style="margin-top:10px">
      ${eventsHtml}
    </div>

  `;
}


/* =========================
   DASHBOARD
========================= */

async function refreshDashboard() {

  if (!currentUser) {

    addAlert(
      "Session",
      "Start session first",
      "Warn"
    );

    return;
  }


  const [
    summaryResp,
    alertsResp
  ] = await Promise.all([

    fetch(
      `${api}/dashboard/summary?email=${encodeURIComponent(currentUser.email)}`
    ),

    fetch(
      `${api}/alerts?email=${encodeURIComponent(currentUser.email)}`
    )

  ]);


  if (!summaryResp.ok) {
    throw new Error(
      await summaryResp.text()
    );
  }


  if (!alertsResp.ok) {
    throw new Error(
      await alertsResp.text()
    );
  }


  const summary =
    await summaryResp.json();


  const alerts =
    await alertsResp.json();


  renderDashboard(summary);

  alerts
    .slice(0, 5)
    .forEach((item) => {

      addAlert(
        item.title,
        item.message,
        item.severity
      );

    });
}


/* =========================
   DASHBOARD RESULT
========================= */

function renderDashboard(summary) {

  const totalPii =
    Number(summary.total_pii_found || 0);


  const avgRisk =
    Number(summary.avg_risk_score || 0);


  const breaches =
    Number(summary.breach_exposure_total || 0);


  const files =
    Number(summary.total_files_scanned || 0);


  const compliance =
    summary.compliance_indicator ??
    "N/A";


  el("metricPii").innerText =
    totalPii;


  el("metricRisk").innerText =
    avgRisk.toFixed(2);


  el("metricRiskLabel").innerText =
    getRiskLabel(avgRisk);


  el("metricBreaches").innerText =
    breaches;


  el("metricProtection").innerText =
    compliance;


  el("gaugeScore").innerText =
    avgRisk.toFixed(2);


  el("riskTitle").innerText =
    getRiskLabel(avgRisk);


  el("riskBadge").innerText =
    getRiskLabel(avgRisk);


  el("historyHint").innerText =
    `${files} file(s) scanned • ${totalPii} PII finding(s)`;


  updateGauge(avgRisk);


  el("dashboardOutput").innerHTML = `

    <div class="section-number">
      DASHBOARD SUMMARY
    </div>

    <div style="margin-top:12px">

      <div class="alert-item">

        <strong>
          Files Scanned
        </strong>

        <span>
          ${files}
        </span>

      </div>

      <div class="alert-item">

        <strong>
          Total PII Found
        </strong>

        <span>
          ${totalPii}
        </span>

      </div>

      <div class="alert-item">

        <strong>
          Average Risk Score
        </strong>

        <span>
          ${avgRisk.toFixed(2)}
        </span>

      </div>

      <div class="alert-item">

        <strong>
          Breach Exposure
        </strong>

        <span>
          ${breaches}
        </span>

      </div>

      <div class="alert-item">

        <strong>
          Compliance
        </strong>

        <span>
          ${escapeHtml(compliance)}
        </span>

      </div>

    </div>

  `;
}


/* =========================
   GAUGE
========================= */

function updateGauge(score) {

  const gauge =
    el("gaugeFill");


  if (!gauge) return;


  const max =
    100;


  const percent =
    Math.max(
      0,
      Math.min(
        Number(score) / max,
        1
      )
    );


  const circumference =
    236;


  gauge.style.strokeDashoffset =
    circumference -
    (circumference * percent);
}


/* =========================
   RISK
========================= */

function getRiskLabel(score) {

  score = Number(score);


  if (score <= 20)
    return "Low Risk";


  if (score <= 50)
    return "Moderate Risk";


  if (score <= 75)
    return "High Risk";


  return "Critical Risk";
}


/* =========================
   METRICS
========================= */

function updateMetrics(result) {

  const findings =
    result.findings || [];


  el("metricPii").innerText =
    findings.length;


  const score =
    Number(result.risk_score || 0);


  el("metricRisk").innerText =
    score.toFixed(2);


  el("metricRiskLabel").innerText =
    result.risk_level ||
    getRiskLabel(score);


  el("gaugeScore").innerText =
    score.toFixed(2);


  el("riskTitle").innerText =
    result.risk_level ||
    getRiskLabel(score);


  el("riskBadge").innerText =
    result.risk_level ||
    getRiskLabel(score);


  updateGauge(score);
}


function updateBreachMetrics(data) {

  el("metricBreaches").innerText =
    Number(data.breach_count || 0);
}


/* =========================
   CLEAR ALERTS
========================= */

function clearAlerts() {

  const container =
    el("alerts");


  container.innerHTML = `

    <div class="alert-empty">

      <span>✓</span>

      <p>No active alerts</p>

    </div>

  `;


  showToast("Alerts cleared");
}


/* =========================
   THEME
========================= */

function toggleTheme() {

  const current =
    document.body.dataset.theme;


  if (current === "light") {

    document.body.dataset.theme =
      "dark";

  } else {

    document.body.dataset.theme =
      "light";

  }

}


/* =========================
   EVENT LISTENERS
========================= */

el("initSession")
  ?.addEventListener(
    "click",
    () =>
      initializeSession()
        .catch(
          (e) =>
            addAlert(
              "Error",
              e.message,
              "Error"
            )
        )
  );


el("runTextScan")
  ?.addEventListener(
    "click",
    () =>
      runTextScan()
        .catch(
          (e) =>
            addAlert(
              "Error",
              e.message,
              "Error"
            )
        )
  );


el("runImageScan")
  ?.addEventListener(
    "click",
    () =>
      runImageScan()
        .catch(
          (e) =>
            addAlert(
              "Error",
              e.message,
              "Error"
            )
        )
  );


el("checkBreach")
  ?.addEventListener(
    "click",
    () =>
      checkBreach()
        .catch(
          (e) =>
            addAlert(
              "Error",
              e.message,
              "Error"
            )
        )
  );


el("refreshDashboard")
  ?.addEventListener(
    "click",
    () =>
      refreshDashboard()
        .catch(
          (e) =>
            addAlert(
              "Error",
              e.message,
              "Error"
            )
        )
  );


el("clearAlerts")
  ?.addEventListener(
    "click",
    clearAlerts
  );


el("themeToggle")
  ?.addEventListener(
    "click",
    toggleTheme
  );


el("heroStart")
  ?.addEventListener(
    "click",
    () => {

      el("workspace")
        ?.scrollIntoView({
          behavior: "smooth"
        });

      el("userEmail")?.focus();

    }
  );


el("heroStatus")
  ?.addEventListener(
    "click",
    () => {

      checkHealth();

      showToast(
        "Checking backend status..."
      );

    }
  );


/* =========================
   STARTUP
========================= */

document.addEventListener(
  "DOMContentLoaded",
  () => {

    checkHealth();

  }
);