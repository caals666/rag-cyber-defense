"""Turns text into 384 numbers (an "embedding") with all-MiniLM-L6-v2.

Texts that mean similar things get similar numbers, even with different words:
"steal login sessions" lands close to "session hijacking". The model is loaded once, at startup.
"""
import config

_model = None


def available():
    """True when the model library is installed (in Docker yes; on Vercel no, so we use keyword search)."""
    try:
        import sentence_transformers  # noqa: F401
        return True
    except ImportError:
        return False


def load():
    """Load the model into memory once. Called when the backend starts."""
    global _model
    if _model is None and available():
        from sentence_transformers import SentenceTransformer
        _model = SentenceTransformer(config.EMBEDDING_MODEL)
    return _model


def embed_texts(texts):
    """A list of texts -> a list of embeddings. Normalized, so similarity is a simple 0..1 score."""
    return load().encode(texts, normalize_embeddings=True, batch_size=64).tolist()


def embed_query(text):
    """One question -> one embedding."""
    return embed_texts([text])[0]
