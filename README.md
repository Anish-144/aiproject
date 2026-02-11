# Cyber Reasoning Assistant

A powerful Retrieval-Augmented Generation (RAG) tool designed to assist cybersecurity analysts. This application analyzes security events, maps them to MITRE ATT&CK techniques, and predicts potential next steps by an attacker, leveraging the power of Google's Gemini models and a local knowledge base.

## 🚀 Features

*   **AI-Powered Analysis**: Uses Google's Gemini Flash model to reason about security events.
*   **Context-Aware**: Retrieves relevant information from a local knowledge base (CVEs, Attack patterns, etc.) using RAG.
*   **MITRE ATT&CK Mapping**: Automatically maps observed behaviors to specific MITRE techniques.
*   **Predictive Insight**: Suggests possible next moves by the attacker.
*   **Dual Interface**:
    *   **Security Analyst Tab**: Standard event-based analysis with MITRE mapping and predictive insights.
    *   **Network Analyzer Tab**: Dedicated interface for parsing raw network logs (firewall, PCAP text), detecting anomalies, and integrity checking.
*   **Specialized Chatbots**:
    *   **Network Specialist Agent**: A context-aware chatbot that answers questions specifically about the network logs being analyzed.
*   **Web Dashboard**: A clean, modern Flask-based web interface for easy interaction.
*   **Transparency**: Shows the exact context retrieved from the knowledge base that influenced the AI's decision.

## 🛠️ Prerequisites

*   Python 3.8 or higher
*   A Google Cloud API Key with access to Gemini models.

## 📦 Installation

1.  **Clone the Repository** (if applicable) or navigate to the project directory.

2.  **Create a Virtual Environment** (Recommended):
    ```bash
    python -m venv venv
    # Windows
    venv\Scripts\activate
    # macOS/Linux
    source venv/bin/activate
    ```

3.  **Install Dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

4.  **Set Up Environment Variables**:
    *   Create a `.env` file in the root directory.
    *   Add your Google API Key:
        ```bash
        GOOGLE_API_KEY=your_actual_api_key_here
        ```

## 🖥️ Usage

### Option 1: Web Application (Dashboard)
The web interface provides a user-friendly way to input events and view structured analysis.

1.  Run the Flask app:
    ```bash
    python app.py
    ```
2.  Open your browser and navigate to:
    `http://127.0.0.1:5000`

3.  **Security Analysis Mode**:
    *   Click the **"Security Analyst"** tab.
    *   Enter a security event description (e.g., "Powershell script decoding base64 commands") and click "Initiate Analysis".

4.  **Network Analysis Mode**:
    *   Click the **"Network Analyzer"** tab.
    *   Paste raw network logs (e.g., firewall drop logs, SSH attempts).
    *   Click "Analyze Logs" to get a breakdown of Source/Dest IPs, Protocols, and Anomalies.
    *   Use the **Network Specialist Chat** on the left to ask specific questions about the traffic (e.g., "Is this a brute force attack?").

### Option 2: Command Line Interface
For quick tests or batch processing integration.

1.  Run the main script:
    ```bash
    python main.py
    ```
2.  The script will initialize the knowledge base, run a demo query, and print the JSON analysis to the console.

## 📂 Project Structure

*   **`app.py`**: The Flask web application entry point. Handles routes (`/analyze`, `/analyze_network`, `/chat_network`) and API endpoints.
*   **`main.py`**: A standalone script to run the reasoning engine in CLI mode.
*   **`rag_engine.py`**: Core logic for the **Security Analyst** RAG pipeline.
*   **`network_rag_engine.py`**: Dedicated RAG logic for the **Network Analyzer**, including log parsing and the specialized chatbot.
*   **`vector_store.py`**: Manages the FAISS vector database creation and retrieval.
*   **`knowledge_loader.py`**: Utilities for loading and splitting documents from the `data/` directory.
*   **`requirements.txt`**: List of Python dependencies.
*   **`data/`**: Directory containing text files (knowledge base) that the AI uses for context.
*   **`static/` & `templates/`**: Frontend assets for the web dashboard.

## 🔧 Configuration

*   **Knowledge Base**: To add more knowledge, simply add `.txt` files to the `data/` directory. The system automatically re-indexes them on startup.
*   **Model**: The project is configured to use `gemini-flash-latest`. You can modify `rag_engine.py` or `network_rag_engine.py` to use other models.

## 🔍 Troubleshooting

*   **API Key Errors**: Ensure your `GOOGLE_API_KEY` is correctly set in the `.env` file.
*   **Missing Data**: Ensure the `data/` directory exists and contains at least one text file.
