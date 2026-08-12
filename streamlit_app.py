import os
import time
import json
import importlib
from datetime import datetime
from typing import Any

import requests
import streamlit as st

st.set_page_config(page_title="PII Redaction & Breach Pipeline", layout="wide")

API_BASE = os.getenv("API_BASE_URL", "http://localhost:8000/api/v1")
TOTAL_PII_TYPES = 8

DEMO_PROMPTS = {
    "Demo 1 (Email + Phone + SSN)": "Contact john.doe@gmail.com at 555-123-4567 for SSN 123-45-6789.",
    "Demo 2 (Card + Address + IP)": "Ship card 4111 1111 1111 1111 statement to 221 Baker Street and whitelist IP 192.168.1.45.",
    "Demo 3 (Mixed enterprise PII)": "Employee demo.user@company.com uses number +1 415 555 0132 and PAN ABCDE1234F.",
}




def api_post(path: str, payload: dict[str, Any]) -> dict[str, Any]:
    response = requests.post(f"{API_BASE}{path}", json=payload, timeout=30)
    response.raise_for_status()
    return response.json()


def api_get(path: str, params: dict[str, Any] | None = None) -> Any:
    response = requests.get(f"{API_BASE}{path}", params=params, timeout=30)
    response.raise_for_status()
    return response.json()


def monitor_status() -> dict[str, Any]:
    return api_get("/breach/monitor/status")


def run_monitor_once() -> dict[str, Any]:
    return api_post("/breach/monitor/run-once", {})


def fetch_alerts(email: str) -> list[dict[str, Any]]:
    return api_get("/alerts", {"email": email})


def fetch_recommendations(email: str) -> dict[str, Any]:
    return api_get("/remediation/recommendations", {"email": email})


def fetch_proactive_controls(email: str) -> dict[str, Any]:
    return api_get("/remediation/proactive-controls", {"email": email})


def remove_sensitive_email_from_dataset(email: str) -> dict[str, Any]:
    return api_post("/breach/remove-sensitive-email", {"user_email": email})


def run_phase_1(user_email: str, user_name: str, prompt: str) -> dict[str, Any]:
    scan = api_post(
        "/scan/text",
        {
            "user_email": user_email,
            "user_name": user_name,
            "content": prompt,
        },
    )

    pii_items = [
        {
            "type": item["entity_type"].lower(),
            "value": item["original"],
            "position": [item["start"], item["end"]],
            "confidence": item["confidence"],
            "token": item["redacted"],
        }
        for item in scan.get("findings", [])
    ]

    avg_conf = scan.get("confidence_avg", 0.0)
    unique_types = len({x["type"] for x in pii_items})
    precision = round(avg_conf * 100, 2)
    recall = round(min(100.0, (unique_types / TOTAL_PII_TYPES) * 100 + min(20, len(pii_items) * 2)), 2)
    f1 = round((2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0, 2)

    return {
        "redacted_prompt": scan.get("redacted_text", ""),
        "pii_metadata": {"pii_items": pii_items},
        "metrics": {
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "types_detected": unique_types,
            "total_found": len(pii_items),
            "redaction_confidence": precision,
            "risk_score": scan.get("risk_score", 0.0),
            "risk_level": scan.get("risk_level", "Low"),
        },
    }


def run_phase_2(pii_metadata: dict[str, Any], session_email: str) -> dict[str, Any]:
    results: list[dict[str, Any]] = []
    timeline: list[dict[str, Any]] = []
    email_breach_cache: dict[str, dict[str, Any]] = {}

    for item in pii_metadata.get("pii_items", []):
        pii_type = item.get("type", "unknown")
        value = item.get("value", "")
        sources: list[str] = []
        risk_score = 8

        if pii_type == "email":
            key = value.strip().lower()
            if key not in email_breach_cache:
                try:
                    email_breach_cache[key] = api_post("/breach/check-email", {"user_email": value})
                except requests.RequestException:
                    email_breach_cache[key] = {"events": [], "exposure_score": 0}

            payload = email_breach_cache[key]
            events = payload.get("events", [])
            sources = [event.get("breach_name", "Unknown") for event in events]
            risk_score = int(round(float(payload.get("exposure_score", 0.0))))

            for event in events:
                timeline.append(
                    {
                        "source": event.get("breach_name", "Unknown"),
                        "date": event.get("breach_date") or datetime.utcnow().date().isoformat(),
                        "pii_type": pii_type,
                    }
                )

        breached = len(sources) > 0
        results.append(
            {
                "pii_type": pii_type,
                "value": value,
                "breached": breached,
                "sources": sources,
                "risk_score": risk_score,
            }
        )

    return {"breach_results": results, "timeline": timeline}


def run_phase_3(redacted_prompt: str, breach_results: list[dict[str, Any]]) -> str:
    high_risk = [item for item in breach_results if item["risk_score"] >= 75]
    medium_risk = [item for item in breach_results if 40 <= item["risk_score"] < 75]
    return (
        "Safe LLM Response:\n"
        f"Processed redacted prompt: {redacted_prompt}\n\n"
        f"High-risk exposures: {len(high_risk)} | Medium-risk exposures: {len(medium_risk)}.\n"
        "Recommended actions: rotate passwords, enable MFA, and replace sensitive identifiers in shared channels."
    )


def highlight_text_with_pii(text: str, pii_items: list[dict[str, Any]]) -> str:
    if not pii_items:
        return text

    chunks: list[str] = []
    cursor = 0
    for item in sorted(pii_items, key=lambda x: x["position"][0]):
        start, end = item["position"]
        label = item["type"].upper()
        chunks.append(text[cursor:start])
        snippet = text[start:end]
        chunks.append(f"<span style='background:#f59e0b33;border-radius:4px;padding:0 2px'>{snippet} ({label})</span>")
        cursor = end
    chunks.append(text[cursor:])
    return "".join(chunks)


def create_pdf_bytes(report_text: str) -> bytes | None:
    try:
        fpdf_module = importlib.import_module("fpdf")
        FPDF = fpdf_module.FPDF
    except ImportError:
        return None

    try:
        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=12)
        pdf.add_page()
        pdf.set_font("Helvetica", size=12)
        safe_text = report_text.encode("latin-1", "replace").decode("latin-1")
        for line in safe_text.splitlines():
            pdf.multi_cell(0, 8, line)
        rendered = pdf.output(dest="S")
        if isinstance(rendered, str):
            rendered = rendered.encode("latin-1", "replace")
        elif isinstance(rendered, bytearray):
            rendered = bytes(rendered)
        if not isinstance(rendered, bytes) or not rendered.startswith(b"%PDF"):
            return None
        return rendered
    except Exception:
        return None


def build_report_payload(pipeline_result: dict[str, Any]) -> dict[str, Any]:
    return {
        "generated_at": datetime.utcnow().isoformat(),
        "phase_1": pipeline_result["phase_1"],
        "phase_2": pipeline_result["phase_2"],
        "phase_3": pipeline_result["phase_3"],
    }


def main() -> None:
    if "pipeline_result" not in st.session_state:
        st.session_state.pipeline_result = None

    

    st.title("🔐 PII Redaction & Dark Web Breach Detection Pipeline")
    st.caption("4-Phase, Python-only judge demo workflow")

    if "session" not in st.session_state:
        st.session_state.session = None

    st.sidebar.header("User Session")
    email = st.sidebar.text_input("Email", placeholder="you@company.com")
    name = st.sidebar.text_input("Name", value="Demo User")

    if st.sidebar.button("Start Session", use_container_width=True):
        if not email.strip():
            st.sidebar.error("Email is required")
        else:
            try:
                st.session_state.session = api_post(
                    "/auth/register", {"email": email.strip(), "name": name.strip() or "Demo User"}
                )
                st.sidebar.success(f"Connected: {st.session_state.session['email']}")
            except requests.RequestException as exc:
                st.sidebar.error(f"Session failed: {exc}")

    st.sidebar.markdown(f"**API:** `{API_BASE}`")

    selected_demo = st.selectbox("Demo Prompt", list(DEMO_PROMPTS.keys()))
    prompt = st.text_area("Input Prompt", value=DEMO_PROMPTS[selected_demo], height=140)

    if not st.session_state.session:
        st.info("Start a session from the sidebar to run the pipeline.")
        return

    user_email = st.session_state.session["email"]
    user_name = st.session_state.session["name"]

    st.sidebar.markdown("""### Monitor Controls""")
    try:
        monitor = monitor_status()
        st.sidebar.caption(
            f"Enabled: {monitor.get('enabled')} | Running: {monitor.get('running')} | Interval: {monitor.get('interval_seconds')}s"
        )
        if monitor.get("""last_run_at"""):
            st.sidebar.caption(f"Last Run: {monitor['last_run_at']}")
    except requests.RequestException:
        st.sidebar.caption("""Monitor status unavailable""")

    if st.sidebar.button("""Run Breach Monitor Once""", use_container_width=True):
        try:
            monitor_result = run_monitor_once()
            st.sidebar.success(
                f"Monitor cycle complete. Users: {monitor_result.get('users_processed', 0)}, Alerts: {monitor_result.get('alerts_created', 0)}"
            )
        except requests.RequestException as exc:
            st.sidebar.error(f"Monitor run failed: {exc}")

    run_pipeline = st.button("""Run Full 4-Phase Pipeline""", use_container_width=True)

    if run_pipeline:
        if not prompt.strip():
            st.warning("Prompt is required.")
        else:
            try:
                progress = st.progress(0)
                status = st.empty()

                status.markdown("<div class='phase-card'>Phase 1: PII Redaction</div>", unsafe_allow_html=True)
                phase_1 = run_phase_1(user_email, user_name, prompt)
                progress.progress(25)
                time.sleep(0.2)

                status.markdown("<div class='phase-card'>Phase 2: Dark Web Breach Monitor</div>", unsafe_allow_html=True)
                phase_2 = run_phase_2(phase_1["pii_metadata"], user_email)
                progress.progress(55)
                time.sleep(0.2)

                status.markdown("<div class='phase-card'>Phase 3: Safe LLM Processing</div>", unsafe_allow_html=True)
                phase_3 = run_phase_3(phase_1["redacted_prompt"], phase_2["breach_results"])
                progress.progress(80)
                time.sleep(0.2)

                status.markdown("<div class='phase-card'>Phase 4: Results Dashboard</div>", unsafe_allow_html=True)
                st.session_state.pipeline_result = {
                    "input_prompt": prompt,
                    "phase_1": phase_1,
                    "phase_2": phase_2,
                    "phase_3": phase_3,
                }
                progress.progress(100)
            except requests.RequestException as exc:
                st.error(f"Pipeline failed: {exc}")

    result = st.session_state.pipeline_result
    if not result:
        return

    phase_1 = result["phase_1"]
    phase_2 = result["phase_2"]
    phase_3 = result["phase_3"]
    metrics = phase_1["metrics"]
    pii_items = phase_1["pii_metadata"]["pii_items"]

    st.markdown("### 🔥 Real-Time Metrics")
    m1, m2, m3, m4, m5, m6 = st.columns(6)
    m1.metric("Precision", f"{metrics['precision']}%")
    m2.metric("Recall", f"{metrics['recall']}%")
    m3.metric("F1-Score", f"{metrics['f1']}%")
    m4.metric("PII Types", metrics["types_detected"])
    m5.metric("Total PII", metrics["total_found"])
    m6.metric("Confidence", f"{metrics['redaction_confidence']}%")

    st.markdown("### Pipeline Flow")
    st.info("User Prompt → Phase 1: PII Redactor → Phase 2: Breach Monitor → Phase 3: LLM Processing → Phase 4: Dashboard")

    left, right = st.columns(2)
    with left:
        st.markdown("### PII Detection Heatmap")
        st.markdown(highlight_text_with_pii(result["input_prompt"], pii_items), unsafe_allow_html=True)

        st.markdown("### Original vs Redacted")
        c1, c2 = st.columns(2)
        with c1:
            st.text_area("Original", value=result["input_prompt"], height=160)
        with c2:
            st.text_area("Redacted", value=phase_1["redacted_prompt"], height=160)

    with right:
        st.markdown("### Breach Risk Gauge (per PII)")
        for item in phase_2["breach_results"]:
            st.write(f"{item['pii_type'].upper()} | breached={item['breached']} | risk={item['risk_score']}%")
            st.progress(int(item["risk_score"]))

        st.markdown("### Breach Timeline")
        if phase_2["timeline"]:
            source_counts: dict[str, int] = {}
            for event in phase_2["timeline"]:
                source = event["source"]
                source_counts[source] = source_counts.get(source, 0) + 1
            st.bar_chart(source_counts)
        else:
            st.success("No timeline events generated.")

    st.markdown("""### Real-Time Alerts (Latest)""")
    extracted_emails = sorted({item["value"] for item in pii_items if item.get("type") == "email"})
    if not extracted_emails:
        st.info("No email extracted from input prompt. Real-time alert lookup skipped.")
    else:
        st.caption(f"Alert lookup emails: {', '.join(extracted_emails)}")
        try:
            combined_alerts: list[dict[str, Any]] = []
            for email_value in extracted_emails:
                combined_alerts.extend(fetch_alerts(email_value))

            deduped_alerts: list[dict[str, Any]] = []
            seen_ids: set[int] = set()
            for alert in combined_alerts:
                alert_id = int(alert.get("id", 0))
                if alert_id and alert_id not in seen_ids:
                    deduped_alerts.append(alert)
                    seen_ids.add(alert_id)

            if deduped_alerts:
                top_alert = deduped_alerts[0]
                severity = str(top_alert.get("severity", "High")).lower()
                border = "#ef4444" if severity in {"critical", "high"} else "#f59e0b" if severity == "medium" else "#3b82f6"
                badge = "CRITICAL SECURITY ALERT" if severity == "critical" else "SECURITY ALERT"
                title = str(top_alert.get("title", "Breach Exposure Detected")).replace("<", "&lt;").replace(">", "&gt;")
                message = str(top_alert.get("message", "Risk exposure detected.")).replace("<", "&lt;").replace(">", "&gt;")
                sev_label = str(top_alert.get("severity", "High")).upper()
                quick_actions: list[str] = []
                try:
                    popup_recs = fetch_recommendations(extracted_emails[0]).get("recommendations", [])
                    if popup_recs:
                        quick_actions = [str(item) for item in popup_recs[0].get("actions", [])[:3]]
                except requests.RequestException:
                    quick_actions = []
                if "popup_seen_alert_ids" not in st.session_state:
                    st.session_state.popup_seen_alert_ids = set()
                alert_id = int(top_alert.get("id", 0))

                @st.dialog("Security Exposure Alert")
                def show_security_dialog() -> None:
                    st.markdown(
                        f"<div style='font-weight:800;color:{border};margin-bottom:6px;'>{badge} - {sev_label}</div>",
                        unsafe_allow_html=True,
                    )
                    st.markdown(f"**{title}**")
                    st.write(message)
                    st.markdown("**Top Quick Actions**")
                    if quick_actions:
                        for item in quick_actions:
                            st.write(f"- {item}")
                    else:
                        st.write("- Review account security settings and keep MFA enabled.")
                    if st.button("Remove Sensitive Data", use_container_width=True, type="primary"):
                        removed_count = 0
                        for email_value in extracted_emails:
                            try:
                                remove_payload = remove_sensitive_email_from_dataset(email_value)
                                if remove_payload.get("deleted"):
                                    removed_count += int(remove_payload.get("deleted_events", 0))
                            except requests.RequestException:
                                continue
                        if alert_id:
                            st.session_state.popup_seen_alert_ids.add(alert_id)
                        if removed_count > 0:
                            st.success(f"Sensitive entries removed. Deleted events: {removed_count}")
                        else:
                            st.info("No matching records found in dataset for deletion.")
                        st.rerun()

                if not alert_id or alert_id not in st.session_state.popup_seen_alert_ids:
                    show_security_dialog()

                for alert in deduped_alerts[:5]:
                    st.error(f"[{alert['severity']}] {alert['title']} - {alert['message']}")
            else:
                st.success(f"No alerts found for extracted email(s): {', '.join(extracted_emails)}.")
        except requests.RequestException as exc:
            st.error(f"Unable to load alerts: {exc}")

    st.markdown("""### Remediation Recommendations""")
    try:
        recommendations = fetch_recommendations(user_email)
        recs = recommendations.get("""recommendations""", [])
        if recs:
            for rec in recs:
                st.markdown(
                    f"**{rec.get('priority', 'Medium')} | {rec.get('title', 'Recommendation')}**  \n"
                    f"Reason: {rec.get('reason', '')}  \n"
                    f"ETA: {rec.get('eta', 'N/A')}"
                )
                for action in rec.get("""actions""", []):
                    st.write(f"- {action}")
        else:
            st.info("""No remediation actions available.""")
    except requests.RequestException as exc:
        st.error(f"Unable to load recommendations: {exc}")

    st.markdown("### Proactive Account Protection Controls")
    try:
        controls_payload = fetch_proactive_controls(user_email)
        controls = controls_payload.get("controls", [])
        if controls:
            for item in controls:
                st.markdown(
                    f"**{item.get('control', 'Control')}** | Status: `{item.get('status', 'Recommended')}`  \n"
                    f"{item.get('why', '')}"
                )
        else:
            st.info("No proactive controls generated.")
    except requests.RequestException as exc:
        st.error(f"Unable to load proactive controls: {exc}")
    st.markdown("### Phase Outputs")
    st.json(
        {
            "phase_1": phase_1,
            "phase_2": {"breach_results": phase_2["breach_results"]},
            "phase_3": phase_3,
        }
    )

    report_payload = build_report_payload(result)
    report_json = st.session_state.get("report_json") or report_payload
    st.session_state.report_json = report_json

    report_text = (
        "AI DataShield Judge Report\n"
        f"Generated: {report_payload['generated_at']}\n\n"
        f"Input: {result['input_prompt']}\n\n"
        f"Redacted: {phase_1['redacted_prompt']}\n\n"
        f"Metrics: {metrics}\n\n"
        f"Breach Results: {phase_2['breach_results']}\n\n"
        f"LLM Output: {phase_3}\n"
    )

    


if __name__ == "__main__":
    main()

