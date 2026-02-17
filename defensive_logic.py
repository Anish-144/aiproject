def generate_defense_actions(severity, techniques, anomalies=None):
    """
    Generates a list of recommended defensive actions based on analysis results.
    """
    actions = set()

    # Severity-based Rules
    if severity == "Critical":
        actions.add("Isolate the affected host from the network immediately.")
        actions.add("Initiate full incident response protocol.")
        actions.add("Block all outbound traffic from the source IP.")
    elif severity == "High":
        actions.add("Quarantine the affected system.")
        actions.add("Review firewall logs for suspicious connections.")
        actions.add("Reset credentials for involved accounts.")
    elif severity == "Medium":
        actions.add("Monitor the host for further suspicious activity.")
        actions.add("Run a full antivirus scan on the endpoint.")

    # MITRE Technique-based Rules
    for tech in techniques:
        if "T1078" in tech: # Valid Accounts
            actions.add("Force password reset for all affected users.")
            actions.add("Audit authentication logs for unauthorized access.")
        if "T1190" in tech: # Exploit Public-Facing Application
            actions.add("Patch the vulnerable application immediately.")
            actions.add("Check web server logs for exploitation attempts.")
        if "T1059" in tech: # Command and Scripting Interpreter
            actions.add("Disable PowerShell/CMD execution for non-admin users.")
            actions.add("Review script execution history.")
        if "T1021" in tech: # Lateral Movement
            actions.add("Restrict SMB/RDP access between workstations.")
            actions.add("Implement network segmentation to contain spread.")
            
    # Network Anomaly Rules
    if anomalies:
        for anomaly in anomalies:
            if "port scan" in anomaly.lower():
                actions.add("Block the scanning source IP at the perimeter firewall.")
            if "data exfiltration" in anomaly.lower():
                actions.add("Inspect outbound traffic for sensitive data patterns.")
                actions.add("Revoke API keys if application data is involved.")
    
    # Generic Fallback
    if not actions:
        actions.add("Conduct a manual investigation of the event context.")
        actions.add("Document findings in the incident management system.")

    return list(actions)
