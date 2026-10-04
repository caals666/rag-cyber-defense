"""Settings, read from environment variables (see .env.example)."""
import os

NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "password123")

GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
GROQ_MODEL = os.getenv("GROQ_MODEL", "openai/gpt-oss-120b")

# Browser origins allowed to call the API
CORS_ORIGINS = os.getenv("CORS_ORIGINS", "https://rag-cyber-defense-ox4x.vercel.app,http://localhost:3000").split(",")
