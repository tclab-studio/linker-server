export type ParsedProtocol = "ss" | "vless" | "vmess" | "trojan";

export interface ParsedConfig {
  id: string;
  protocol: ParsedProtocol;
  tag: string;
  host: string;
  port: number;
  uuid: string;
  alter_id: number;
  security: string;
  network: string;
  tls: boolean;
  sni: string | null;
  path: string | null;
  ws_host: string | null;
  fp: string | null;
  alpn: string | null;
  pbk: string | null;
  sid: string | null;
  flow: string | null;
  service_name: string | null;
  raw_link: string;
}

export interface VpnConfigApiResponse {
  id: string;
  tag: string;
  host: string;
  port: number;
  protocol: string;
  uuid: string;
  alter_id: number;
  security: string;
  network: string;
  tls: boolean;
  sni: string | null;
  path: string | null;
  ws_host: string | null;
  fp: string | null;
  alpn: string | null;
  pbk: string | null;
  sid: string | null;
  flow: string | null;
  service_name: string | null;
  studio_title: string;
  raw: Record<string, unknown>;
}

export interface JwtPayload {
  adminId: string;
  username: string;
}

declare global {
  namespace Express {
    interface Request {
      admin?: JwtPayload;
    }
  }
}
