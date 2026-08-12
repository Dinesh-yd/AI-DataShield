const api = "/api/v1";
let currentUser = null;
let socket = null;

const el = (id) => document.getElementById(id);

function pretty(data) {
  return JSON.stringify(data, null, 2);
}

function addAlert(title, message, severity = "Info") {
  const container = el("alerts");
  const node = document.createElement("div");
  node.className = "alert-item";
  node.innerHTML = `<strong>${severity}: ${title}</strong><span>${message}</span>`;
  container.prepend(node);
}

async function post(path, body) {
  const resp = await fetch(`${api}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!resp.ok) throw new Error(await resp.text());
  return resp.json();
}

async function initializeSession() {
  const email = el("userEmail").value.trim();
  const name = el("userName").value.trim() || "Demo User";
  if (!email) {
    el("sessionStatus").innerText = "Email is required";
    return;
  }

  currentUser = await post("/auth/register", { email, name });
  el("sessionStatus").innerText = `Connected as ${currentUser.email} (id: ${currentUser.id})`;

  if (socket) socket.close();
  const wsProtocol = location.protocol === "https:" ? "wss" : "ws";
  socket = new WebSocket(`${wsProtocol}://${location.host}${api}/alerts/ws/${currentUser.id}`);

  socket.onopen = () => socket.send("ready");
  socket.onmessage = (event) => {
    const payload = JSON.parse(event.data);
    addAlert(payload.title, payload.message, payload.severity);
  };
  socket.onclose = () => addAlert("Socket Closed", "Real-time alerts disconnected", "Warn");
}

async function runTextScan() {
  if (!currentUser) return addAlert("Session", "Start session first", "Warn");
  const content = el("scanText").value;
  const result = await post("/scan/text", {
    user_email: currentUser.email,
    user_name: currentUser.name,
    content,
  });
  el("scanOutput").innerText = pretty(result);
}

async function runImageScan() {
  if (!currentUser) return addAlert("Session", "Start session first", "Warn");
  const file = el("scanImage").files[0];
  if (!file) return;

  const form = new FormData();
  form.append("user_email", currentUser.email);
  form.append("user_name", currentUser.name);
  form.append("image", file);

  const resp = await fetch(`${api}/scan/image`, { method: "POST", body: form });
  if (!resp.ok) throw new Error(await resp.text());
  const data = await resp.json();
  el("imageOutput").innerText = pretty(data);
}

async function checkBreach() {
  if (!currentUser) return addAlert("Session", "Start session first", "Warn");
  const data = await post("/breach/check-email", { user_email: currentUser.email });
  el("breachOutput").innerText = pretty(data);
}

async function refreshDashboard() {
  if (!currentUser) return addAlert("Session", "Start session first", "Warn");
  const [summaryResp, alertsResp] = await Promise.all([
    fetch(`${api}/dashboard/summary?email=${encodeURIComponent(currentUser.email)}`),
    fetch(`${api}/alerts?email=${encodeURIComponent(currentUser.email)}`),
  ]);
  const summary = await summaryResp.json();
  const alerts = await alertsResp.json();
  el("dashboardOutput").innerText = pretty({ summary, alerts_count: alerts.length });
  alerts.slice(0, 5).forEach((item) => addAlert(item.title, item.message, item.severity));
}

el("initSession").addEventListener("click", () => initializeSession().catch((e) => addAlert("Error", e.message, "Error")));
el("runTextScan").addEventListener("click", () => runTextScan().catch((e) => addAlert("Error", e.message, "Error")));
el("runImageScan").addEventListener("click", () => runImageScan().catch((e) => addAlert("Error", e.message, "Error")));
el("checkBreach").addEventListener("click", () => checkBreach().catch((e) => addAlert("Error", e.message, "Error")));
el("refreshDashboard").addEventListener("click", () => refreshDashboard().catch((e) => addAlert("Error", e.message, "Error")));
