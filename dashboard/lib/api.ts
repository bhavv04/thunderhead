// ─── Typed API client for Thunderhead REST API ────────────────────────────────

import type {
  HealthResponse, MetricsResponse, ClientsResponse,
  ConfigResponse, BlocklistResponse, AllowlistResponse, MutationResponse,
} from "./types";

function getConfig(): { url: string; key: string } {
  if (typeof window !== "undefined") {
    return {
      url: localStorage.getItem("th_url") ?? "",
      key: localStorage.getItem("th_key") ?? "",
    };
  }
  return { url: "", key: "" };
}

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const { url, key } = getConfig();
  if (!url) throw new Error("Thunderhead URL not configured");

  const res = await fetch(`${url}${path}`, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      "X-API-Key": key,
      ...options?.headers,
    },
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error(err.error ?? `HTTP ${res.status}`);
  }
  return res.json();
}

const get  = <T>(path: string) => request<T>(path);
const post = <T>(path: string, body: unknown) =>
  request<T>(path, { method: "POST",   body: JSON.stringify(body) });
const del  = <T>(path: string, body: unknown) =>
  request<T>(path, { method: "DELETE", body: JSON.stringify(body) });

export const api = {
  health:          () => get<HealthResponse>    ("/api/v1/health"),
  metrics:         () => get<MetricsResponse>   ("/api/v1/metrics"),
  clients:         () => get<ClientsResponse>   ("/api/v1/clients"),
  config:          () => get<ConfigResponse>    ("/api/v1/config"),
  blocklist:       () => get<BlocklistResponse> ("/api/v1/blocklist"),
  allowlist:       () => get<AllowlistResponse> ("/api/v1/allowlist"),
  blocklistAdd:    (entry: string) => post<MutationResponse>("/api/v1/blocklist", { entry }),
  blocklistRemove: (entry: string) => del<MutationResponse> ("/api/v1/blocklist", { entry }),
  allowlistAdd:    (entry: string) => post<MutationResponse>("/api/v1/allowlist", { entry }),
  allowlistRemove: (entry: string) => del<MutationResponse> ("/api/v1/allowlist", { entry }),
};