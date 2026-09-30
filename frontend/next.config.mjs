/** @type {import('next').NextConfig} */
const nextConfig = {
  // Bundles a minimal server into .next/standalone for a small Docker image
  output: "standalone",
};

export default nextConfig;
