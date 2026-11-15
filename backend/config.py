"""Settings, read from environment variables (see .env.example)."""
import os

NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER") or os.getenv("NEO4J_USERNAME", "neo4j")  # Aura names it NEO4J_USERNAME
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "password123")

GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
GROQ_MODEL = os.getenv("GROQ_MODEL", "openai/gpt-oss-120b")
# How much the model thinks before answering. gpt-oss accepts low/medium/high (low = fastest,
# medium = better answers); qwen3 accepts none. Leave empty for models without reasoning.
GROQ_REASONING_EFFORT = os.getenv("GROQ_REASONING_EFFORT", "low")

# Search by meaning, for questions with no ID (needs requirements-semantic.txt, installed in Docker)
EMBEDDING_MODEL = os.getenv("EMBEDDING_MODEL", "sentence-transformers/all-MiniLM-L6-v2")
VECTOR_TOP_K = int(os.getenv("VECTOR_TOP_K", "5"))              # how many entry nodes to start from
VECTOR_MIN_SCORE = float(os.getenv("VECTOR_MIN_SCORE", "0.65"))  # 0..1; below this a match is too weak to use

# Browser origins allowed to call the API
CORS_ORIGINS = os.getenv("CORS_ORIGINS", "https://graphcyrag.vercel.app,https://rag-cyber-defense-ox4x.vercel.app,http://localhost:3000").split(",")
