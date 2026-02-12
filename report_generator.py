import datetime

def generate_text_report(incident_data, original_query):
    """
    Generates a formatted analysis report.
    """
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    analysis = incident_data # Alias for clarity if passed directly
    
    report = f"""
================================================================================
                        CYBERGUARD AI - INCIDENT REPORT
================================================================================
Reference ID: {abs(hash(timestamp))}
Date Generated: {timestamp}
================================================================================

[ INCIDENT SUMMARY ]
Severity Level       : {analysis.get('severity_rating', 'Unknown').upper()}
Confidence Level     : {analysis.get('confidence_level', 'Unknown')}
Current Stage        : {analysis.get('current_attack_stage', 'Unknown')}
Predicted Next Stage : {analysis.get('predicted_next_stage', 'Unknown')}

[ ORIGINAL EVENT ]
{original_query}

--------------------------------------------------------------------------------
[ AI ANALYSIS ]
Explanation:
{analysis.get('attack_explanation', 'No explanation provided.')}

Confidence Reasoning:
{analysis.get('confidence_reason', 'N/A')}

--------------------------------------------------------------------------------
[ THREAT INTELLIGENCE & ATTRIBUTION ]
Likely MITRE Techniques:
{', '.join(analysis.get('likely_mitre_techniques', []))}

--------------------------------------------------------------------------------
[ REMEDIATION & NEXT STEPS ]
The following actions are recommended to contain and remediate the threat:

"""
    for step in analysis.get('possible_next_steps', []):
        report += f"- {step}\n"

    report += """
--------------------------------------------------------------------------------
[ EVIDENCE TRACE ]
Relevant Fragments from Knowledge Base:

"""
    # If evidence is a list of strings
    evidence = analysis.get('evidence_from_kb', [])
    if isinstance(evidence, list):
         for i, frag in enumerate(evidence):
            report += f"Fragment {i+1}:\n{frag}\n\n"
    elif isinstance(evidence, str):
         report += f"{evidence}\n"


    report += """
================================================================================
                        END OF REPORT
================================================================================
    """
    
    return report
