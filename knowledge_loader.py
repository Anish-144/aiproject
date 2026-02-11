import os
from langchain_community.document_loaders import DirectoryLoader, TextLoader
from langchain_text_splitters import RecursiveCharacterTextSplitter

def load_and_split_documents(directory_path):
    """
    Loads text files from a directory and splits them into chunks.
    
    Args:
        directory_path (str): Path to the directory containing text files.
        
    Returns:
        list: A list of Document objects (chunks).
    """
    print(f"Loading documents from {directory_path}...")
    
    # Load all .txt files from the directory
    loader = DirectoryLoader(directory_path, glob="*.txt", loader_cls=TextLoader)
    documents = loader.load()
    
    print(f"Loaded {len(documents)} documents.")
    
    # Split documents into chunks for better embedding and retrieval
    # Chunk size is small (500) to keep context precise for RAG
    text_splitter = RecursiveCharacterTextSplitter(
        chunk_size=500,
        chunk_overlap=50,
        length_function=len,
        is_separator_regex=False,
    )
    
    split_docs = text_splitter.split_documents(documents)
    print(f"Split documents into {len(split_docs)} chunks.")
    
    return split_docs

if __name__ == "__main__":
    # Test the loader
    data_dir = os.path.join(os.path.dirname(__file__), "data")
    if os.path.exists(data_dir):
        docs = load_and_split_documents(data_dir)
        print(f"Sample chunk content:\n{docs[0].page_content}")
    else:
        print(f"Directory {data_dir} not found.")
