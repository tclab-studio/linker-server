export interface Studio {
  id: string;
  studio_id: string;
  title: string;
  active: boolean;
  created_at: Date;
  config_count?: number;
}

export interface VpnConfig {
  id: string;
  studio_id: string;
  tag: string;
  host: string;
  port: number;
  protocol: string;
  uuid: string;
  alter_id: number;
  security: string;
  network: string;
  tls: boolean;
  extra: Record<string, unknown>;
  active: boolean;
  created_at: Date;
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
  studio_title: string;
  outbounds?: unknown[];
}

export interface AdminUser {
  id: string;
  username: string;
  password_hash: string;
  created_at: Date;
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
