import os
import json
import numpy as np
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.prompts import PromptTemplate
from langchain_core.output_parsers import JsonOutputParser
from pydantic import BaseModel, Field
from typing import List, Dict, Any, Tuple

# --- Advanced Attack Stage Intelligence ---

MITRE_STAGE_MAP = {
    "T1078": ["Initial Access", "Persistence"],
    "T1190": ["Initial Access"],
    "T1059": ["Execution"],
    "T1105": ["Command & Control"],
    "T1547": ["Persistence"],
    "T1021": ["Lateral Movement"],
    "T1003": ["Credential Access", "Privilege Escalation"],
    "T1055": ["Privilege Escalation", "Defense Evasion"],
    "T1486": ["Impact"],
    "T1562": ["Defense Evasion"],
    "T1041": ["Exfiltration"],
    "T1071": ["Command & Control"],
    # Adding a few common ones for robustness
    "T1059.001": ["Execution"], # PowerShell
    "T1098": ["Persistence", "Privilege Escalation"],
    "T1046": ["Discovery"],
    "T1083": ["Discovery"]
}

ATTACK_STAGE_ORDER = [
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command & Control",
    "Exfiltration",
    "Impact"
]

# Define the expected data structure for the LLM output
class CyberAnalysis(BaseModel):
    attack_explanation: str = Field(description="Explanation of why the behavior is malicious")
    likely_mitre_techniques: List[str] = Field(description="List of likely MITRE ATT&CK technique IDs (e.g. T1059)")
    possible_next_steps: List[str] = Field(description="List of predicted next steps the attacker might take")
    evidence_from_kb: List[str] = Field(description="List of quotes or summaries from the retrieved context used as evidence")

def analyze_attack_progression(techniques: List[str]) -> Tuple[Dict[str, bool], str, str]:
    """
    Analyzes which stages of the attack lifecycle have been reached based on mapped techniques.
    """
    stage_status = {stage: False for stage in ATTACK_STAGE_ORDER}

    for tech in techniques:
        # Check standard Map
        mapped_stages = MITRE_STAGE_MAP.get(tech, [])
        
        # If not found, try stripping sub-technique (e.g. T1059.001 -> T1059)
        if not mapped_stages and "." in tech:
             base_tech = tech.split(".")[0]
             mapped_stages = MITRE_STAGE_MAP.get(base_tech, [])

        for stage in mapped_stages:
            if stage in stage_status:
                stage_status[stage] = True

    # Find furthest stage reached (the highest index in ATTACK_STAGE_ORDER that is True)
    reached_indices = [i for i, stage in enumerate(ATTACK_STAGE_ORDER) if stage_status[stage]]
    
    if not reached_indices:
        # Default to first stage if nothing mapped
        reached_index = 0
        stage_status[ATTACK_STAGE_ORDER[0]] = True # Assume initial access if unknown
    else:
        reached_index = max(reached_indices)

    current_stage = ATTACK_STAGE_ORDER[reached_index]
    
    if reached_index + 1 < len(ATTACK_STAGE_ORDER):
        next_stage = ATTACK_STAGE_ORDER[reached_index + 1]
    else:
        next_stage = "Attack Objective Achieved"

    return stage_status, current_stage, next_stage

def calculate_confidence(scores: List[float]) -> Tuple[str, str]:
    """
    Calculates confidence based on retrieval relevance scores.
    Assumes scores are in range roughly 0 to 1.
    """
    if not scores:
        return "Low", "No relevant context found in knowledge base."
        
    # Explicitly calculate average as float
    avg = float(sum(scores) / len(scores))
    
    # Thresholds need to be tuned to the embedding model. 
    if avg > 0.65:
        return "High", "Strong match with known attack patterns and CVEs."
    elif avg > 0.45:
        return "Medium", "Partial match with threat intelligence."
    else:
        return "Low", "Limited supporting evidence from knowledge base."

def determine_severity(current_stage: str, confidence_level: str) -> str:
    """
    Determines severity based on stage and confidence.
    """
    # Define late stages
    late_stages = {"Lateral Movement", "Command & Control", "Exfiltration", "Impact"}
    mid_stages = {"Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access", "Collection", "Discovery"}
    
    if current_stage in late_stages:
        if confidence_level in ["High", "Medium"]:
             return "Critical"
        return "High"
    
    if current_stage in mid_stages:
        if confidence_level == "High":
            return "High"
        return "Medium"
        
    # Early stages
    if confidence_level == "High":
        return "Medium"
    return "Low"

def process_query(query, vector_db):
    """
    Retrieves context, generates a response, and enriches it with SOC-style analytics.
    """
    
    # 1. Retrieval with Scores
    print(f"Retrieving knowledge for query: '{query}'...")
    
    # Use similarity_search_with_relevance_scores to get (doc, score) tuples
    results = vector_db.similarity_search_with_relevance_scores(query, k=3)
    
    docs = [res[0] for res in results]
    # Explicitly cast to float to avoid JSON serialization errors with numpy types
    scores = [float(res[1]) for res in results]
    
    context_text = "\n\n".join([doc.page_content for doc in docs])
    
    # 2. Prompt Construction
    parser = JsonOutputParser(pydantic_object=CyberAnalysis)
    
    template = """
    You are a Cybersecurity Reasoning Assistant. Analyze the following security event using the provided Knowledge Base context.
    
    User Query: {query}
    
    Knowledge Base Context:
    {context}
    
    Instructions:
    1. Explain why this behavior is malicious (or suspicious).
    2. Map the behavior to specific MITRE ATT&CK techniques mentioned in the context (Use accurate IDs like T1059, T1105).
    3. Predict what the attacker might do next based on the context and general security knowledge.
    4. Cite specific parts of the context that support your analysis.
    
    Return the output ONLY as a valid JSON object matching the following format:
    {format_instructions}
    """
    
    prompt = PromptTemplate(
        template=template,
        input_variables=["query", "context"],
        partial_variables={"format_instructions": parser.get_format_instructions()},
    )
    
    # 3. LLM Generation
    if not os.getenv("GOOGLE_API_KEY"):
        raise ValueError("GOOGLE_API_KEY environment variable is not set.")
    
    print("Querying LLM (Reasoning with Gemini)...")
    llm = ChatGoogleGenerativeAI(model="gemini-flash-latest", temperature=0)
    
    chain = prompt | llm | parser
    
    try:
        # Get base analysis from LLM
        analysis_json = chain.invoke({"query": query, "context": context_text})
        
        # 4. Advanced Post-Processing (SOC Intelligence)
        techniques = analysis_json.get("likely_mitre_techniques", [])
        
        # Attack Progression
        stage_status, current_stage, next_stage = analyze_attack_progression(techniques)
        
        # Confidence
        conf_level, conf_reason = calculate_confidence(scores)
        
        # Severity
        severity = determine_severity(current_stage, conf_level)
        
        # Construct Final Wrapper
        final_output = {
            # Base LLM Content
            "attack_explanation": analysis_json.get("attack_explanation"),
            "likely_mitre_techniques": techniques,
            "possible_next_steps": analysis_json.get("possible_next_steps"),
            "evidence_from_kb": analysis_json.get("evidence_from_kb"),
            
            # Advanced Analytics
            "retrieval_scores": scores,
            "attack_timeline": stage_status, 
            "current_attack_stage": current_stage,
            "predicted_next_stage": next_stage,
            "confidence_level": conf_level,
            "confidence_reason": conf_reason,
            "severity_rating": severity
        }
        
        return {
            "analysis": final_output,
            "retrieved_docs": [doc.page_content for doc in docs]
        }
        
    except Exception as e:
        print(f"Error during LLM generation: {e}")
        # Return a graceful error structure
        return {
            "error": str(e),
            "raw_context": context_text
        }
