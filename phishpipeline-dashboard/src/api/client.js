const BASE = import.meta.env.VITE_API_URL;

if (!BASE) {
  console.error(
    "[PhishPipeline] VITE_API_URL is not set. " +
      "Create a .env file with VITE_API_URL=http://localhost:8000"
  );
}

const API_BASE = BASE || "http://localhost:8000";

function queryString(params) {
  if (!params) return "";
  const entries = Object.entries(params).filter(
    ([, value]) => value !== undefined && value !== null && value !== ""
  );
  if (entries.length === 0) return "";
  return `?${new URLSearchParams(entries).toString()}`;
}

export const api = {
  base: API_BASE,
  get: (path, params) =>
    fetch(`${API_BASE}${path}${queryString(params)}`),
  post: (path, body) =>
    fetch(`${API_BASE}${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body),
    }),
  delete: (path) =>
    fetch(`${API_BASE}${path}`, { method: "DELETE" }),
};
