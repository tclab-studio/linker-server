import { StudioModel, VpnConfigModel } from "../db/index";
import { parseSubscriptionBlob } from "../parser/subscription";

const FETCH_TIMEOUT_MS = 15000;

const HAPP_HEADERS: Record<string, string> = {
  "User-Agent": "Happ/3.13.0",
  "X-Device-Os": "Android",
  "X-Device-Locale": "en",
  "X-Device-Model": "Linker",
  "X-Ver-Os": "15",
  "Accept-Encoding": "identity",
  "X-Hwid": "linker-server-relay",
};

export interface RefreshResult {
  ok: boolean;
  configCount: number;
  error?: string;
}

export async function refreshStudioSubscription(
  studioId: string,
): Promise<RefreshResult> {
  const studio = await StudioModel.findOne({ studio_id: studioId });

  if (!studio) {
    return { ok: false, configCount: 0, error: "Studio not found" };
  }

  if (!studio.subscription_url) {
    return {
      ok: false,
      configCount: 0,
      error: "No subscription URL configured",
    };
  }

  let response: Response;
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);

    response = await fetch(studio.subscription_url, {
      headers: HAPP_HEADERS,
      signal: controller.signal,
    });

    clearTimeout(timeout);
  } catch (err) {
    const message = err instanceof Error ? err.message : "Network error";
    await markFetchFailed(studioId, message);
    return { ok: false, configCount: 0, error: message };
  }

  if (!response.ok) {
    const message = `HTTP ${response.status}`;
    await markFetchFailed(studioId, message);
    return { ok: false, configCount: 0, error: message };
  }

  const blob = await response.text();
  const parsed = parseSubscriptionBlob(blob);

  if (parsed.length === 0) {
    const message = "No valid configs found in subscription";
    await markFetchFailed(studioId, message);
    return { ok: false, configCount: 0, error: message };
  }

  await VpnConfigModel.deleteMany({ studio_id: studioId });

  await VpnConfigModel.insertMany(
    parsed.map((cfg) => ({
      studio_id: studioId,
      protocol: cfg.protocol,
      tag: cfg.tag,
      host: cfg.host,
      port: cfg.port,
      uuid: cfg.uuid,
      alter_id: cfg.alter_id,
      security: cfg.security,
      network: cfg.network,
      tls: cfg.tls,
      sni: cfg.sni,
      path: cfg.path,
      ws_host: cfg.ws_host,
      fp: cfg.fp,
      alpn: cfg.alpn,
      raw_link: cfg.raw_link,
      active: true,
    })),
  );

  studio.last_fetched_at = new Date();
  studio.last_fetch_status = "ok";
  await studio.save();

  return { ok: true, configCount: parsed.length };
}

async function markFetchFailed(
  studioId: string,
  message: string,
): Promise<void> {
  await StudioModel.updateOne(
    { studio_id: studioId },
    { last_fetched_at: new Date(), last_fetch_status: `error: ${message}` },
  );
}

export async function getCachedConfigs(studioId: string) {
  return VpnConfigModel.find({ studio_id: studioId, active: true });
}

const REFRESH_INTERVAL_MS = 30 * 60 * 1000;

export function startAutoRefresh(): void {
  setInterval(() => {
    void (async () => {
      const studios = await StudioModel.find({
        active: true,
        subscription_url: { $ne: null },
      });

      for (const studio of studios) {
        refreshStudioSubscription(studio.studio_id).catch((err) => {
          console.error(`[AutoRefresh] Failed for ${studio.studio_id}:`, err);
        });
      }
    })();
  }, REFRESH_INTERVAL_MS);
}
