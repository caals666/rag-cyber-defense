// Where the backend API lives. In Docker this file is rewritten at start-up from the API_URL setting.
window.API_URL = window.API_URL ||
  (["localhost", "127.0.0.1"].includes(location.hostname) ? "http://localhost:8000" : "https://rag-cyber-defense-sigma.vercel.app/");
