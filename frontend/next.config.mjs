/** @type {import('next').NextConfig} */
const nextConfig = {
  async rewrites() {
    return [{ source: "/backend/:path*", destination: `${process.env.RELAYOPS_API_URL || "http://localhost:8080"}/:path*` }];
  },
};
export default nextConfig;
