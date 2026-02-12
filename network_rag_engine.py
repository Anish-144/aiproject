import os
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.prompts import PromptTemplate
from langchain_core.output_parsers import JsonOutputParser, StrOutputParser
from pydantic import BaseModel, Field
from typing import List, Dict, Any
from threat_intel import enrich_ip

# Define the expected data structure for the Network Analysis output
class NetworkAnalysis(BaseModel):
    summary: str = Field(description="Brief summary of the network event")
    source_ip: str = Field(description="The source IP address involved, or 'N/A'")
    destination_ip: str = Field(description="The destination IP address involved, or 'N/A'")
    protocol: str = Field(description="The protocol used (e.g., TCP, UDP, SSH), or 'N/A'")
    anomalies: List[str] = Field(description="List of detected anomalies or suspicious patterns")
    severity: str = Field(description="Assessed severity level: Low, Medium, High, or Critical")
    recommended_action: str = Field(description="Immediate actionable recommendation")

def analyze_network_logs(log_data: str, vector_db) -> Dict[str, Any]:
    """
    Analyzes network logs using a specialized RAG approach.
    """
    print(f"DEBUG: Analyzing network logs...")

    # 1. Retrieval (Broad search for network concepts)
    # We search for keywords from the log to find relevant KB articles about ports, protocols, known attacks.
    # For simplicity, we just use the first few lines of the log as the query if it's long.
    query_preview = log_data[:200]
    results = vector_db.similarity_search_with_relevance_scores(query_preview, k=3)
    
    docs = [res[0] for res in results]
    context_text = "\n\n".join([doc.page_content for doc in docs])

    # 2. Prompt Construction
    parser = JsonOutputParser(pydantic_object=NetworkAnalysis)
    
    template = """
    You are a Network Security Specialist. Analyze the following network log data using the provided Knowledge Base context.
    
    Network Log:
    {log_data}
    
    Knowledge Base Context:
    {context}
    
    Instructions:
    1. Identify the Source and Destination IPs, Ports, and Protocol.
    2. Detect any anomalies (e.g., port scanning, brute force, data exfiltration signatures).
    3. Assess the severity based on the context and the nature of the traffic.
    4. Provide a concrete recommendation.
    
    Return the output ONLY as a valid JSON object matching the following format:
    {format_instructions}
    """
    
    prompt = PromptTemplate(
        template=template,
        input_variables=["log_data", "context"],
        partial_variables={"format_instructions": parser.get_format_instructions()},
    )
    
    # 3. LLM Generation
    if not os.getenv("GOOGLE_API_KEY"):
        raise ValueError("GOOGLE_API_KEY environment variable is not set.")
    
    # Use a slightly different model or temperature if desired, but Flash is good for speed.
    llm = ChatGoogleGenerativeAI(model="gemini-flash-latest", temperature=0)
    
    chain = prompt | llm | parser
    
    try:
        analysis_json = chain.invoke({"log_data": log_data, "context": context_text})
        
        # --- Threat Intelligence Enrichment ---
        src_ip = analysis_json.get("source_ip", "N/A")
        dest_ip = analysis_json.get("destination_ip", "N/A")
        
        enrichment_data = []
        if src_ip and src_ip != "N/A":
            enrichment_data.append(enrich_ip(src_ip))
            
        if dest_ip and dest_ip != "N/A":
            enrichment_data.append(enrich_ip(dest_ip))
            
        return {
            "analysis": analysis_json,
            "threat_intel_enrichment": enrichment_data,
            "retrieved_context": [doc.page_content for doc in docs]
        }
    except Exception as e:
        print(f"Error during Network LLM analysis: {e}")
        return {"error": str(e)}

def chat_with_network_rag(query: str, log_context: str, vector_db) -> str:
    """
    Chat with the Network Specialist Agent about the specific logs.
    """
    
    # 1. Retrieve relevant info for the user's question
    results = vector_db.similarity_search(query, k=2)
    kb_context = "\n\n".join([doc.page_content for doc in results])
    
    template = """
    You are a Network Security Assistant. You are currently discussing a specific network log with a user.
    
    Current Log Context:
    {log_context}
    
    Relevant Knowledge Base Info:
    {kb_context}
    
    User Question: {query}
    
    Answer the user's question directly and concisely, referencing the log details where appropriate.
    If the user asks about general security concepts, use the Knowledge Base Info.
    """
    
    prompt = PromptTemplate(
        template=template,
        input_variables=["query", "log_context", "kb_context"]
    )
    
    llm = ChatGoogleGenerativeAI(model="gemini-flash-latest", temperature=0.3)
    chain = prompt | llm | StrOutputParser()
    
    try:
        response = chain.invoke({
            "query": query,
            "log_context": log_context,
            "kb_context": kb_context
        })
        return response
    except Exception as e:
        print(f"Error during Network Chat: {e}")
        return "I encountered an error processing your request."
