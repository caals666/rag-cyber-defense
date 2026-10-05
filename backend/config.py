"""Settings, read from environment variables (see .env.example)."""
import os

NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER") or os.getenv("NEO4J_USERNAME", "neo4j")  # Aura names it NEO4J_USERNAME
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "password123")

GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
GROQ_MODEL = os.getenv("GROQ_MODEL", "openai/gpt-oss-120b")
# Lowest thinking for speed. gpt-oss accepts low/medium/high; qwen3 accepts none.
# Leave empty for models without reasoning (e.g. llama-3.3-70b-versatile).
GROQ_REASONING_EFFORT = os.getenv("GROQ_REASONING_EFFORT", "low")

# Browser origins allowed to call the API
CORS_ORIGINS = os.getenv("CORS_ORIGINS", "https://rag-cyber-defense-ox4x.vercel.app,http://localhost:3000").split(",")
