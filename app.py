import os
import numpy as np
from flask import Flask, render_template, request, jsonify
from dotenv import load_dotenv
from knowledge_loader import load_and_split_documents
from vector_store import create_vector_db
from rag_engine import process_query
from network_rag_engine import analyze_network_logs, chat_with_network_rag

# Load environment variables
load_dotenv()

app = Flask(__name__)

# Global variables for the knowledge base
vector_db = None

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

if __name__ == '__main__':
    initialize_knowledge_base()
    app.run(debug=True, port=5000)
