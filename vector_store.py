from langchain_community.vectorstores import FAISS
from langchain_huggingface import HuggingFaceEmbeddings

def create_vector_db(documents):
    """
    Creates a FAISS vector database from a list of documents using HuggingFace embeddings.
    
    Args:
        documents (list): List of Document objects.
        
    Returns:
        FAISS: The vector store object.
    """
    print("Initializing embeddings model (all-MiniLM-L6-v2)...")
    # Using a lightweight, high-performance sentence-transformer model
    embeddings = HuggingFaceEmbeddings(model_name="all-MiniLM-L6-v2")
    
    print("Creating FAISS vector index...")
    vector_db = FAISS.from_documents(documents, embeddings)
    
    return vector_db

if __name__ == "__main__":
    # Simple test stub
    print("Vector Store module. Import this module to use.")
