from langchain_community.vectorstores import Chroma
from langchain_openai import OpenAIEmbeddings
from langchain.memory import VectorStoreRetrieverMemory

def build_memory(persist_dir: str = "memory_store") -> VectorStoreRetrieverMemory:
    """Build persistent vector memory.
    ATTACK SURFACE: if an attacker can write to persist_dir,
    or if the agent stores attacker-supplied content without validation,
    future retrievals will surface poisoned context."""
    embeddings = OpenAIEmbeddings()
    vectorstore = Chroma(
        collection_name="cve_triage_memory",
        embedding_function=embeddings,
        persist_directory=persist_dir
    )
    retriever = vectorstore.as_retriever(search_kwargs={"k": 3})
    return VectorStoreRetrieverMemory(retriever=retriever)