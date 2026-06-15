import { randomUUID } from "crypto";
import { ParsedConfig, ParsedProtocol } from "../types/index";

function safeBase64Decode(input: string): string {
  let normalized = input.replace(/[^A-Za-z0-9+/_-]/g, "");
  normalized = normalized.replace(/-/g, "+").replace(/_/g, "/");
  const pad = normalized.length % 4;
  if (pad === 2) normalized += "==";
  else if (pad === 3) normalized += "=";
  else if (pad === 1) normalized = normalized.slice(0, -1);
  try {
    return Buffer.from(normalized, "base64").toString("utf-8");
  } catch {
    return "";
  }
}

function decodeTag(raw: string): string {
  try {
    return decodeURIComponent(raw);
  } catch {
    return raw;
  }
}

function orNull(value: string | undefined): string | null {
  return value && value.trim().length > 0 ? value : null;
}

function parseShadowsocksLink(link: string): ParsedConfig | null {
  try {
    const body = link.slice("ss://".length);
    const hashIdx = body.indexOf("#");
    const beforeHash = hashIdx === -1 ? body : body.slice(0, hashIdx);
    const tagRaw = hashIdx === -1 ? "" : body.slice(hashIdx + 1);

    let decodedContent = beforeHash;

    if (!beforeHash.includes("@")) {
      decodedContent = safeBase64Decode(beforeHash);
      if (!decodedContent.includes("@")) return null;
    }

    const atIdx = decodedContent.lastIndexOf("@");
    if (atIdx === -1) return null;

    let userInfoB64 = decodedContent.slice(0, atIdx);
    const hostPortAndQuery = decodedContent.slice(atIdx + 1);

    if (!userInfoB64.includes(":")) {
      userInfoB64 = safeBase64Decode(userInfoB64);
    }

    const colonIdx = userInfoB64.indexOf(":");
    if (colonIdx === -1) return null;

    const method = userInfoB64.slice(0, colonIdx);
    const password = userInfoB64.slice(colonIdx + 1);

    const queryIdx = hostPortAndQuery.indexOf("?");
    const hostPort =
      queryIdx === -1 ? hostPortAndQuery : hostPortAndQuery.slice(0, queryIdx);

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
      pbk: null,
      sid: null,
      flow: null,
      service_name: null,
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
    const security = params["security"] ?? "none";

    return {
      id: randomUUID(),
      protocol,
      tag,
      host,
      port,
      uuid,
      alter_id: 0,
      security,
      network: params["type"] ?? "tcp",
      tls: security === "tls" || security === "reality",
      sni: orNull(params["sni"]),
      path: orNull(params["path"]),
      ws_host: orNull(params["host"]),
      fp: orNull(params["fp"]),
      alpn: orNull(params["alpn"]),
      pbk: orNull(params["pbk"]),
      sid: orNull(params["sid"]),
      flow: orNull(params["flow"]),
      service_name: orNull(params["serviceName"]),
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

    const rawTls = json["tls"];
    const isTls =
      rawTls === "tls" ||
      rawTls === "reality" ||
      rawTls === true ||
      rawTls === "true";

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
      tls: isTls,
      // @ts-ignore
      sni: orNull(json["sni"] ? String(json["sni"]) : null),
      // @ts-ignore
      path: orNull(json["path"] ? String(json["path"]) : null),
      // @ts-ignore

      ws_host: orNull(json["host"] ? String(json["host"]) : null),
      // @ts-ignore

      fp: orNull(json["fp"] ? String(json["fp"]) : null),
      // @ts-ignore

      alpn: orNull(json["alpn"] ? String(json["alpn"]) : null),
      pbk: null,
      sid: null,
      flow: null,
      service_name: null,
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
    const decoded = safeBase64Decode(content);
    if (decoded.includes("://")) {
      content = decoded;
    }
  }

  return content
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l.length > 0)
    .map(parseSubscriptionLink)
    .filter((c): c is ParsedConfig => c !== null);
}

export function isKnownProtocol(protocol: string): protocol is ParsedProtocol {
  return (
    protocol === "ss" ||
    protocol === "vless" ||
    protocol === "vmess" ||
    protocol === "trojan"
  );
}

