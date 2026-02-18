import os
import json
import numpy as np
from flask import Flask, render_template, request, jsonify, Response
from dotenv import load_dotenv
from knowledge_loader import load_and_split_documents
from vector_store import create_vector_db
from rag_engine import process_query, security_chat, log_qa
from defensive_logic import generate_defense_actions
from ml_engine import risk_predictor, behavior_profiler
from geo_intel import extract_and_enrich_geo
from report_generator import generate_investigation_report
import case_manager

# Load environment variables
load_dotenv()

app = Flask(__name__)

# Global variables
vector_db = None
last_analysis = None  # Stores last analysis context for Q&A and report generation


def convert_numpy_types(obj):
    """Recursively convert NumPy types to standard Python types."""
    if isinstance(obj, dict):
        return {k: convert_numpy_types(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [convert_numpy_types(i) for i in obj]
    elif isinstance(obj, np.generic):
        return obj.item()
    return obj


def initialize_knowledge_base():
    """Initializes the vector store on startup."""
    global vector_db
    print("--- Initializing Knowledge Base ---")
    base_dir = os.path.dirname(os.path.abspath(__file__))
    data_dir = os.path.join(base_dir, "data")

    if os.path.exists(data_dir):
        documents = load_and_split_documents(data_dir)
        vector_db = create_vector_db(documents)
        print("--- Knowledge Base Ready ---")
    else:
        print(f"Error: Data directory {data_dir} not found.")


@app.route('/')
def index():
    return render_template('index.html')


# =====================================================================
# TAB 1 — AI LOG INTELLIGENCE AGENT
# Supports: JSON body OR multipart file upload
# Returns: analysis + geo_data + auto-case info
# =====================================================================
@app.route('/api/log-intelligence', methods=['POST'])
def log_intelligence():
    global vector_db, last_analysis
    if not vector_db:
        return jsonify({"error": "Knowledge base not initialized."}), 500

    # --- Extract log text from JSON body or file upload ---
    event_description = None

    if request.content_type and 'multipart/form-data' in request.content_type:
        # File upload mode
        uploaded_file = request.files.get('log_file')
        if uploaded_file and uploaded_file.filename:
            try:
                event_description = uploaded_file.read().decode('utf-8', errors='replace')
            except Exception as e:
                return jsonify({"error": f"Failed to read file: {str(e)}"}), 400
        # Also check for text field in form data
        if not event_description:
            event_description = request.form.get('event_description')
    else:
        # JSON mode (existing behavior)
        data = request.json or {}
        event_description = data.get('event_description')

    if not event_description or not event_description.strip():
        return jsonify({"error": "No event description or log file provided."}), 400

    try:
        # RAG-based analysis
        result = process_query(event_description, vector_db)

        if "error" in result and "analysis" not in result:
            return jsonify({"error": result["error"]}), 500

        analysis = result["analysis"]

        # Generate Defensive Actions
        actions = generate_defense_actions(
            analysis.get("severity_rating", "Unknown"),
            analysis.get("likely_mitre_techniques", [])
        )
        analysis["recommended_actions"] = actions

        # ML Risk Prediction
        ml_risk = risk_predictor.predict(analysis)
        analysis["ml_risk_score"] = ml_risk

        # Behavioral Anomaly Detection
        anomaly_score = behavior_profiler.update_and_score(analysis)
        analysis["behavior_anomaly_score"] = anomaly_score

        # --- IP Geo Enrichment ---
        geo_data = extract_and_enrich_geo(event_description)
        result["geo_data"] = geo_data

        # --- Auto Case Creation ---
        has_malicious_ioc = False
        ioc_data = result.get("threat_intel_enrichment", [])
        if isinstance(ioc_data, list):
            for ioc in ioc_data:
                if isinstance(ioc, dict) and ioc.get("reputation") == "Malicious":
                    has_malicious_ioc = True
                    break
        # Also check geo data for malicious IPs
        for g in geo_data:
            if g.get("risk") == "Malicious":
                has_malicious_ioc = True
                break

        auto_case_created = False
        auto_case_id = None

        if ml_risk > 70 or anomaly_score > 70 or has_malicious_ioc:
            case_data = {
                "incident_summary": (analysis.get("attack_explanation") or "N/A")[:200],
                "severity": analysis.get("severity_rating", "Unknown"),
                "ml_risk_score": ml_risk,
                "anomaly_score": anomaly_score,
                "mitre_techniques": analysis.get("likely_mitre_techniques", []),
                "recommended_actions": actions
            }
            new_case = case_manager.create_case(case_data)
            auto_case_created = True
            auto_case_id = new_case.get("case_id")

        result["auto_case_created"] = auto_case_created
        result["auto_case_id"] = auto_case_id

        # --- Store for Q&A and Report ---
        last_analysis = {
            "logs": event_description,
            "analysis": analysis,
            "geo_data": geo_data
        }

        return jsonify(convert_numpy_types(result))
    except Exception as e:
        print(f"[Log Intelligence] Error: {e}")
        return jsonify({"error": str(e)}), 500


# =====================================================================
# TAB 2 — SECURITY KNOWLEDGE CHATBOT
# =====================================================================
@app.route('/api/security-chat', methods=['POST'])
def security_chat_endpoint():
    global vector_db
    if not vector_db:
        return jsonify({"error": "Knowledge base not initialized."}), 500

    data = request.json
    query = data.get('query')

    if not query:
        return jsonify({"error": "No query provided."}), 400

    try:
        response = security_chat(query, vector_db)
        return jsonify({"response": response})
    except Exception as e:
        print(f"[Security Chat] Error: {e}")
        return jsonify({"error": str(e)}), 500


# =====================================================================
# TAB 3 — CASE MANAGEMENT
# =====================================================================
@app.route('/api/cases', methods=['GET'])
def get_cases():
    return jsonify(case_manager.get_all_cases())


@app.route('/api/update-case-status', methods=['POST'])
def update_case_status():
    data = request.json
    case_id = data.get("case_id")
    new_status = data.get("status")

    if not case_id or not new_status:
        return jsonify({"error": "case_id and status are required."}), 400

    updated = case_manager.update_status(case_id, new_status)
    if updated:
        return jsonify({"message": "Status updated", "case": updated})
    return jsonify({"error": "Case not found"}), 404


# =====================================================================
# LOG QUESTION ANSWERING (context-aware follow-up)
# =====================================================================
@app.route('/api/log-qa', methods=['POST'])
def log_qa_endpoint():
    global vector_db, last_analysis
    if not vector_db:
        return jsonify({"error": "Knowledge base not initialized."}), 500

    if not last_analysis:
        return jsonify({"error": "No analysis context available. Run log analysis first."}), 400

    data = request.json
    question = data.get('question')

    if not question:
        return jsonify({"error": "No question provided."}), 400

    try:
        answer = log_qa(question, last_analysis, vector_db)
        return jsonify({"answer": answer})
    except Exception as e:
        print(f"[Log QA] Error: {e}")
        return jsonify({"error": str(e)}), 500


# =====================================================================
# AUTOMATED REPORT GENERATION
# =====================================================================
@app.route('/api/generate-report', methods=['POST'])
def generate_report():
    global last_analysis
    if not last_analysis:
        return jsonify({"error": "No analysis context available. Run log analysis first."}), 400

    try:
        report_text = generate_investigation_report(last_analysis)
        return Response(
            report_text,
            mimetype='text/plain',
            headers={
                'Content-Disposition': 'attachment; filename=CyberGuard_Investigation_Report.txt',
                'Content-Type': 'text/plain; charset=utf-8'
            }
        )
    except Exception as e:
        print(f"[Report Gen] Error: {e}")
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
    initialize_knowledge_base()
    app.run(debug=True, port=5000)
