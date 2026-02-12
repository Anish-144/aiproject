import json
import os
from datetime import datetime
from collections import Counter

METRICS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "metrics.json")

def ensure_metrics_file():
    if not os.path.exists(METRICS_FILE):
        with open(METRICS_FILE, "w") as f:
            json.dump([], f)

def log_incident(incident_data):
    """
    Logs an analysis result to the metrics file.
    """
    ensure_metrics_file()
    
    # Create a simplified record
    record = {
        "timestamp": datetime.now().isoformat(),
        "severity": incident_data.get("severity_rating", "Unknown"),
        "confidence": incident_data.get("confidence_level", "Unknown"),
        "techniques": incident_data.get("likely_mitre_techniques", [])
    }

    try:
        with open(METRICS_FILE, "r") as f:
            data = json.load(f)
        
        data.append(record)
        
        with open(METRICS_FILE, "w") as f:
            json.dump(data, f, indent=4)
            
    except Exception as e:
        print(f"Error logging metric: {e}")

def get_metrics_summary():
    """
    Aggregates metrics for the dashboard.
    """
    ensure_metrics_file()
    try:
        with open(METRICS_FILE, "r") as f:
            data = json.load(f)
            
        total_incidents = len(data)
        if total_incidents == 0:
             return {
                "total_incidents": 0,
                "avg_confidence": 0,
                "severity_dist": {},
                "technique_dist": {},
                "timeline": []
            }

        # Severity Distribution
        severities = [d["severity"] for d in data]
        sev_counts = dict(Counter(severities))

        # Technique Distribution
        techniques = [t for d in data for t in d.get("techniques", [])]
        tech_counts = dict(Counter(techniques).most_common(5)) # Top 5

        # Confidence Mapping (High=100, Medium=50, Low=0 for avg)
        conf_map = {"High": 100, "Medium": 50, "Low": 0}
        conf_scores = [conf_map.get(d["confidence"], 0) for d in data]
        avg_conf = sum(conf_scores) / len(conf_scores) if conf_scores else 0

        # Timeline (counts per day for last 7 entries for simplicity)
        # In a real app, we'd group by date properly. 
        # Here we just return the full list timestamps for the frontend to parse or a simple list.
        # Let's return the raw list of timestamps to be processed by frontend/chartjs
        timeline_dates = [d["timestamp"] for d in data]

        return {
            "total_incidents": total_incidents,
            "avg_confidence": round(avg_conf, 1),
            "severity_dist": sev_counts,
            "technique_dist": tech_counts,
            "timeline": timeline_dates
        }

    except Exception as e:
        print(f"Error getting metrics: {e}")
        return {}
