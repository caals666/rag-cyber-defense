FROM python:3.12-slim

WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1

# Install dependencies first so this layer is cached between code changes
COPY requirements.txt requirements-semantic.txt ./
RUN pip install --no-cache-dir -r requirements.txt
# Search by meaning: the CPU-only build of torch keeps the image small, then sentence-transformers
RUN pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu
RUN pip install --no-cache-dir -r requirements-semantic.txt
# Download the model now, so the first question does not wait for it
RUN python -c "from sentence_transformers import SentenceTransformer; SentenceTransformer('sentence-transformers/all-MiniLM-L6-v2')"

COPY . .

EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
