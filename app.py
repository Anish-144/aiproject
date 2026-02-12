import os
import numpy as np
from flask import Flask, render_template, request, jsonify
from dotenv import load_dotenv
from knowledge_loader import load_and_split_documents
from vector_store import create_vector_db
from rag_engine import process_query
from network_rag_engine import analyze_network_logs, chat_with_network_rag
from report_generator import generate_text_report
from metrics_tracker import log_incident, get_metrics_summary

# Load environment variables
load_dotenv()

app = Flask(__name__)

# Global variables for the knowledge base
vector_db = None

# Global Metrics Store (In-Memory)
metrics_store = {
    "total_incidents": 0,
    "confidence_scores": [],
    "mitre_distribution": {},
    "severity_distribution": {},
    "incident_timestamps": []
}

def convert_numpy_types(obj):
    """
    Recursively convert NumPy types to standard Python types.
    This is necessary because Flask's jsonify cannot handle numpy.float32, etc.
    """
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

@app.route('/analyze', methods=['POST'])
def analyze():
    global vector_db
    if not vector_db:
        return jsonify({"error": "Knowledge base not initialized."}), 500
    
    data = request.json
    event_description = data.get('event_description')
    
    if not event_description:
        return jsonify({"error": "No event description provided."}), 400
    
    try:
        # result contains "analysis" (the JSON from LLM) and "retrieved_docs"
        result = process_query(event_description, vector_db)
        
        # Log to Metrics (File-based)
        log_incident(result["analysis"])
        
        # Update In-Memory Metrics Store
        try:
            from datetime import datetime
            analysis = result["analysis"]
            
            metrics_store["total_incidents"] += 1
            metrics_store["incident_timestamps"].append(datetime.now().isoformat())
            
            conf = analysis.get("confidence_level")
            if conf:
                # Store string or convert to mapped value? User asked for "confidence_score".
                # The prompt implies a list of scores. I have levels (High/Medium/Low). 
                # I will store the level string for now as requested by typical logic, 
                # or better, the raw score if available. The result["analysis"] has "confidence_level".
                # It also has "retrieval_scores" (list of floats). 
                # The prompt says: 'If confidence_score exists: append(confidence_score)'.
                # I will use the level as that is the singular scalar I have readily available as "confidence".
                metrics_store["confidence_scores"].append(conf)
            
            techniques = analysis.get("likely_mitre_techniques", [])
            if techniques:
                for tech in techniques:
                    metrics_store["mitre_distribution"][tech] = metrics_store["mitre_distribution"].get(tech, 0) + 1
            
            sev = analysis.get("severity_rating")
            if sev:
                metrics_store["severity_distribution"][sev] = metrics_store["severity_distribution"].get(sev, 0) + 1
        except Exception as e:
            print(f"Error updating in-memory metrics: {e}")
        
        # Safe JSON serialization by ensuring all numpy types are converted
        return jsonify(convert_numpy_types(result))
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/analyze_network', methods=['POST'])
def analyze_network():
    global vector_db
    if not vector_db:
        return jsonify({"error": "Knowledge base not initialized."}), 500
    
    data = request.json
    log_data = data.get('log_data')
    
    if not log_data:
        return jsonify({"error": "No log data provided."}), 400
    
    try:
        result = analyze_network_logs(log_data, vector_db)
        return jsonify(convert_numpy_types(result))
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/chat_network', methods=['POST'])
def chat_network():
    global vector_db
    if not vector_db:
        return jsonify({"error": "Knowledge base not initialized."}), 500
    
    data = request.json
    query = data.get('query')
    log_context = data.get('log_context')
    
    if not query:
        return jsonify({"error": "No query provided."}), 400
        
    try:
        response = chat_with_network_rag(query, log_context or "No specific log context provided.", vector_db)
        return jsonify({"response": response})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/generate_report', methods=['POST'])
def generate_report():
    data = request.json
    analysis_data = data.get('analysis_data')
    original_query = data.get('original_query', 'N/A')
    
    if not analysis_data:
        return jsonify({"error": "No analysis data provided."}), 400
        
    try:
        report_text = generate_text_report(analysis_data, original_query)
        return jsonify({"report_content": report_text, "filename": "incident_report.txt"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/metrics', methods=['GET'])
def metrics():
    try:
        summary = get_metrics_summary()
        return jsonify(convert_numpy_types(summary))
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/metrics', methods=['GET'])
def get_in_memory_metrics():
    return jsonify(metrics_store)

if __name__ == '__main__':
    initialize_knowledge_base()
    app.run(debug=True, port=5000)
