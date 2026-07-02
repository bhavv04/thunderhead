// ─── Mirrors Go API response shapes exactly ───────────────────────────────────

export interface HealthResponse {
  status:  string;
  uptime:  string;
  version: string;
}

export interface MetricsResponse {
  total:   number;
  allowed: number;
  tarpit:  number;
  blocked: number;
  uptime:  string;
}

export interface ClientStatus {
  score:           number;
  request_count:   number;
  robots_violated: boolean;
}

export interface ClientsResponse {
  clients: Record<string, ClientStatus>;
}

export interface ConfigResponse {
  listen_addr:  string;
  upstream_url: string;
  thresholds:   { tarpit: number; block: number };
  tarpit_delay: string;
  expiry_days:  number;
  dry_run:      boolean;
}

export interface BlocklistResponse {
  ips:   string[];
  cidrs: string[];
}

export interface AllowlistResponse {
  ips:         string[];
  cidrs:       string[];
  user_agents: string[];
}

export interface MutationResponse {
  ok:    boolean;
  entry: string;
}

export type ConnectionStatus = "connected" | "disconnected" | "checking";