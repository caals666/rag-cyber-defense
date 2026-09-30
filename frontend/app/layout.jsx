import "./globals.css";

export const metadata = {
  title: "Cyber Defense RAG",
  description: "Ask cybersecurity questions answered from a CVE-CWE-CAPEC-ATT&CK knowledge graph",
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
