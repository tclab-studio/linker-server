import { randomUUID } from "crypto";
import { ParsedConfig, ParsedProtocol } from "../types/index";

function safeBase64Decode(input: string): string {
  let normalized = input.replace(/-/g, "+").replace(/_/g, "/");
  const pad = normalized.length % 4;
  if (pad === 2) normalized += "==";
  else if (pad === 3) normalized += "=";
  else if (pad !== 0) normalized = normalized.slice(0, -pad);
  return Buffer.from(normalized, "base64").toString("utf-8");
}

function decodeTag(raw: string): string {
  try {
    return decodeURIComponent(raw);
  } catch {
    return raw;
  }
}

function parseShadowsocksLink(link: string): ParsedConfig | null {
  try {
    const body = link.slice("ss://".length);
    const hashIdx = body.indexOf("#");
    const beforeHash = hashIdx === -1 ? body : body.slice(0, hashIdx);
    const tagRaw = hashIdx === -1 ? "" : body.slice(hashIdx + 1);

    const atIdx = beforeHash.lastIndexOf("@");
    if (atIdx === -1) return null;

    const userInfoB64 = beforeHash.slice(0, atIdx);
    const hostPort = beforeHash.slice(atIdx + 1);

    const userInfo = safeBase64Decode(userInfoB64);
    const colonIdx = userInfo.indexOf(":");
    if (colonIdx === -1) return null;

    const method = userInfo.slice(0, colonIdx);
    const password = userInfo.slice(colonIdx + 1);

    const portIdx = hostPort.lastIndexOf(":");
    if (portIdx === -1) return null;

    const host = hostPort.slice(0, portIdx);
    const port = parseInt(hostPort.slice(portIdx + 1), 10);
    if (isNaN(port)) return null;

    const tag = decodeTag(tagRaw) || `${host}:${port}`;

    return {
      id: randomUUID(),
      protocol: "ss",
      tag,
      host,
      port,
      uuid: password,
      alter_id: 0,
      security: method,
      network: "tcp",
      tls: false,
      sni: null,
      path: null,
      ws_host: null,
      fp: null,
      alpn: null,
      raw_link: link,
    };
  } catch {
    return null;
  }
}

function parseQueryParams(query: string): Record<string, string> {
  const params: Record<string, string> = {};
  for (const pair of query.split("&")) {
    if (!pair) continue;
    const eqIdx = pair.indexOf("=");
    if (eqIdx === -1) {
      params[decodeURIComponent(pair)] = "";
    } else {
      const key = decodeURIComponent(pair.slice(0, eqIdx));
      const value = decodeURIComponent(pair.slice(eqIdx + 1));
      params[key] = value;
    }
  }
  return params;
}

function parseVlessOrTrojanLink(
  link: string,
  protocol: "vless" | "trojan",
): ParsedConfig | null {
  try {
    const prefix = `${protocol}://`;
    const body = link.slice(prefix.length);

    const hashIdx = body.indexOf("#");
    const beforeHash = hashIdx === -1 ? body : body.slice(0, hashIdx);
    const tagRaw = hashIdx === -1 ? "" : body.slice(hashIdx + 1);

    const atIdx = beforeHash.indexOf("@");
    if (atIdx === -1) return null;

    const uuid = beforeHash.slice(0, atIdx);
    const remainder = beforeHash.slice(atIdx + 1);

    const queryIdx = remainder.indexOf("?");
    const hostPort = queryIdx === -1 ? remainder : remainder.slice(0, queryIdx);
    const queryStr = queryIdx === -1 ? "" : remainder.slice(queryIdx + 1);

    const portIdx = hostPort.lastIndexOf(":");
    if (portIdx === -1) return null;

    const host = hostPort.slice(0, portIdx);
    const port = parseInt(hostPort.slice(portIdx + 1), 10);
    if (isNaN(port)) return null;

    const params = parseQueryParams(queryStr);
    const tag = decodeTag(tagRaw) || `${host}:${port}`;

    return {
      id: randomUUID(),
      protocol,
      tag,
      host,
      port,
      uuid,
      alter_id: 0,
      security: params["security"] ?? "none",
      network: params["type"] ?? "tcp",
      tls: params["security"] === "tls" || params["security"] === "reality",
      sni: params["sni"] ?? null,
      path: params["path"] ?? null,
      ws_host: params["host"] ?? null,
      fp: params["fp"] ?? null,
      alpn: params["alpn"] ?? null,
      raw_link: link,
    };
  } catch {
    return null;
  }
}

function parseVmessLink(link: string): ParsedConfig | null {
  try {
    const body = link.slice("vmess://".length);
    const decoded = safeBase64Decode(body);
    const json = JSON.parse(decoded) as Record<string, unknown>;

    const host = String(json["add"] ?? "");
    const port = parseInt(String(json["port"] ?? "0"), 10);
    if (!host || isNaN(port)) return null;

    const tag = String(json["ps"] ?? `${host}:${port}`);
    const tlsValue = String(json["tls"] ?? "");

    return {
      id: randomUUID(),
      protocol: "vmess",
      tag,
      host,
      port,
      uuid: String(json["id"] ?? ""),
      alter_id: parseInt(String(json["aid"] ?? "0"), 10) || 0,
      security: String(json["scy"] ?? "auto"),
      network: String(json["net"] ?? "tcp"),
      tls: tlsValue === "tls" || tlsValue === "reality",
      sni: json["sni"] ? String(json["sni"]) : null,
      path: json["path"] ? String(json["path"]) : null,
      ws_host: json["host"] ? String(json["host"]) : null,
      fp: json["fp"] ? String(json["fp"]) : null,
      alpn: json["alpn"] ? String(json["alpn"]) : null,
      raw_link: link,
    };
  } catch {
    return null;
  }
}

export function parseSubscriptionLink(link: string): ParsedConfig | null {
  const trimmed = link.trim();
  if (!trimmed) return null;

  if (trimmed.startsWith("ss://")) return parseShadowsocksLink(trimmed);
  if (trimmed.startsWith("vless://"))
    return parseVlessOrTrojanLink(trimmed, "vless");
  if (trimmed.startsWith("trojan://"))
    return parseVlessOrTrojanLink(trimmed, "trojan");
  if (trimmed.startsWith("vmess://")) return parseVmessLink(trimmed);

  return null;
}

export function parseSubscriptionBlob(blob: string): ParsedConfig[] {
  let content = blob.trim();

  if (!content.includes("://")) {
    try {
      const decoded = safeBase64Decode(content);
      if (decoded.includes("://")) {
        content = decoded;
      }
    } catch {
      // not base64, fall through with original content
    }
  }

  const lines = content
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l.length > 0);

  const configs: ParsedConfig[] = [];

  for (const line of lines) {
    const parsed = parseSubscriptionLink(line);
    if (parsed) configs.push(parsed);
  }

  return configs;
}

export function isKnownProtocol(protocol: string): protocol is ParsedProtocol {
  return (
    protocol === "ss" ||
    protocol === "vless" ||
    protocol === "vmess" ||
    protocol === "trojan"
  );
}
