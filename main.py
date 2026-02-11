import os
import sys
from dotenv import load_dotenv
from knowledge_loader import load_and_split_documents
from vector_store import create_vector_db
from rag_engine import process_query
import json

# Load environment variables
load_dotenv()

def main():
    print("=== Cybersecurity RAG Reasoning Assistant ===")
    
    # 1. Setup Data Directory
    base_dir = os.path.dirname(os.path.abspath(__file__))
    data_dir = os.path.join(base_dir, "data")
    
    if not os.path.exists(data_dir):
        print(f"Error: Data directory not found at {data_dir}")
        return

    # 2. Ingestion
    print("\n--- Step 1: Data Ingestion ---")
    documents = load_and_split_documents(data_dir)
    
    # 3. Indexing
    print("\n--- Step 2: Creating Vector Store ---")
    vector_db = create_vector_db(documents)
    
    # 4. Demo Query
    # Using a query combined from our mock data concepts (Encoded command + External IP)
    user_event = "PowerShell process executed a base64 encoded script and initiated a connection to an external IP address 192.168.1.10."
    
    print(f"\n--- Step 3: Analyzing Security Event ---\nEvent: {user_event}")
    
    try:
        full_result = process_query(user_event, vector_db)
        result = full_result["analysis"]
        
        print("\n--- Step 4: Analysis Results ---")
        print(json.dumps(result, indent=2))
        
        print("\n--- Transparency: Retrieved Context ---")
        for i, doc in enumerate(full_result["retrieved_docs"]):
             print(f"\n[Source {i+1}]: {doc[:150]}...")
        
    except ValueError as e:
        print(f"\nError: {e}")
        print("Please ensure you have set the OPENAI_API_KEY environment variable.")

if __name__ == "__main__":
    main()
