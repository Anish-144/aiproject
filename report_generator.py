"""
Report Generator Module
Generates structured investigation reports from analysis data.
"""

from datetime import datetime


def generate_investigation_report(analysis_context):
    """
    Generate a structured text investigation report from the last analysis.

    Args:
        analysis_context (dict): Contains 'logs', 'analysis', and 'geo_data'

    Returns:
        str: Formatted text report
    """
    logs = analysis_context.get("logs", "N/A")
    analysis = analysis_context.get("analysis", {})
    geo_data = analysis_context.get("geo_data", [])

    report_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    lines = []
    lines.append("=" * 72)
    lines.append("         CYBERGUARD AI — AUTOMATED INVESTIGATION REPORT")
    lines.append("=" * 72)
    lines.append(f"Report Generated: {report_time}")
    lines.append(f"Report ID: RPT-{datetime.now().strftime('%Y%m%d%H%M%S')}")
    lines.append("")

    # --- 1. INCIDENT SUMMARY ---
    lines.append("-" * 72)
    lines.append("1. INCIDENT SUMMARY")
    lines.append("-" * 72)
    lines.append(f"Severity: {analysis.get('severity_rating', 'Unknown')}")
    lines.append(f"Confidence: {analysis.get('confidence_level', 'N/A')}")
    lines.append(f"ML Risk Score: {analysis.get('ml_risk_score', 'N/A')}/100")
    lines.append(f"Anomaly Score: {analysis.get('behavior_anomaly_score', 'N/A')}/100")
    lines.append("")
    explanation = analysis.get("attack_explanation", "No explanation available.")
    lines.append(f"Description:\n{explanation}")
    lines.append("")

    # --- 2. ATTACK TIMELINE ---
    lines.append("-" * 72)
    lines.append("2. ATTACK TIMELINE")
    lines.append("-" * 72)
    timeline = analysis.get("attack_timeline", {})
    current_stage = analysis.get("current_attack_stage", "Unknown")
    predicted_next = analysis.get("predicted_next_stage", "None")

    if timeline:
        stages_reached = [stage for stage, reached in timeline.items() if reached]
        for i, stage in enumerate(stages_reached, 1):
            marker = " <<< CURRENT" if stage == current_stage else ""
            lines.append(f"  [{i}] {stage}{marker}")
    else:
        lines.append("  No timeline data available.")

    lines.append(f"\n  Current Stage: {current_stage}")
    lines.append(f"  Predicted Next Move: {predicted_next}")
    lines.append("")

    # --- 3. MITRE ATT&CK MAPPING ---
    lines.append("-" * 72)
    lines.append("3. MITRE ATT&CK MAPPING")
    lines.append("-" * 72)
    techniques = analysis.get("likely_mitre_techniques", [])
    if techniques:
        for tech in techniques:
            lines.append(f"  • {tech}")
    else:
        lines.append("  No techniques identified.")
    lines.append("")

    # --- 4. ML RISK ASSESSMENT ---
    lines.append("-" * 72)
    lines.append("4. ML RISK ASSESSMENT")
    lines.append("-" * 72)
    ml_risk = analysis.get("ml_risk_score", "N/A")
    anomaly = analysis.get("behavior_anomaly_score", "N/A")
    lines.append(f"  ML Risk Score (RandomForest): {ml_risk}/100")
    lines.append(f"  Behavior Anomaly (IsolationForest): {anomaly}/100")

    if isinstance(ml_risk, (int, float)):
        if ml_risk > 70:
            lines.append("  ⚠ HIGH RISK — Immediate investigation recommended")
        elif ml_risk > 40:
            lines.append("  ⚡ MODERATE RISK — Monitor closely")
        else:
            lines.append("  ✅ LOW RISK — Routine monitoring")
    lines.append("")

    # --- 5. EXTERNAL IP ANALYSIS ---
    lines.append("-" * 72)
    lines.append("5. EXTERNAL IP ANALYSIS (Geo Intelligence)")
    lines.append("-" * 72)
    if geo_data:
        for g in geo_data:
            risk_marker = "🔴" if g.get("risk") == "Malicious" else ("🟡" if g.get("risk") == "Suspicious" else "🟢")
            lines.append(f"  {risk_marker} {g['ip']} | {g.get('country', '??')} | "
                         f"({g.get('lat', '?')}, {g.get('lon', '?')}) | Risk: {g.get('risk', 'Unknown')}")
    else:
        lines.append("  No external IPs detected in logs.")
    lines.append("")

    # --- 6. RECOMMENDED DEFENSIVE ACTIONS ---
    lines.append("-" * 72)
    lines.append("6. RECOMMENDED DEFENSIVE ACTIONS")
    lines.append("-" * 72)
    actions = analysis.get("recommended_actions", [])
    if actions:
        for i, action in enumerate(actions, 1):
            lines.append(f"  {i}. {action}")
    else:
        lines.append("  No specific actions recommended.")
    lines.append("")

    # --- 7. NEXT STEPS ---
    lines.append("-" * 72)
    lines.append("7. REMEDIATION & NEXT STEPS")
    lines.append("-" * 72)
    next_steps = analysis.get("possible_next_steps", [])
    if next_steps:
        for step in next_steps:
            lines.append(f"  • {step}")
    else:
        lines.append("  No next steps identified.")
    lines.append("")

    # --- 8. ORIGINAL LOG DATA ---
    lines.append("-" * 72)
    lines.append("8. ORIGINAL LOG DATA")
    lines.append("-" * 72)
    log_text = logs if isinstance(logs, str) else str(logs)
    if len(log_text) > 2000:
        lines.append(log_text[:2000] + "\n  ... [TRUNCATED]")
    else:
        lines.append(log_text)
    lines.append("")

    # --- CONCLUSION ---
    lines.append("=" * 72)
    lines.append("CONCLUSION")
    lines.append("=" * 72)
    severity = analysis.get("severity_rating", "Unknown")
    lines.append(f"This incident has been classified as {severity} severity.")
    if isinstance(ml_risk, (int, float)) and ml_risk > 70:
        lines.append("The ML risk assessment indicates high probability of malicious activity.")
        lines.append("Immediate escalation and containment measures are recommended.")
    else:
        lines.append("Continue monitoring and apply recommended defensive actions as appropriate.")

    lines.append("")
    lines.append("--- END OF REPORT ---")
    lines.append(f"Generated by CyberGuard AI | {report_time}")

    return "\n".join(lines)
