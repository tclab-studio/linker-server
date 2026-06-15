import { Router, Request, Response } from "express";
import { StudioModel } from "../db/index";
import { getCachedConfigs, refreshStudioSubscription } from "../services/subscription";
import { VpnConfigApiResponse } from "../types/index";

export const studiosRouter = Router();

studiosRouter.post("/verify", async (req: Request, res: Response) => {
  const { studio_id } = req.body as { studio_id?: string };

  if (!studio_id || typeof studio_id !== "string" || studio_id.trim() === "") {
    res.status(400).json({ error: "studio_id is required" });
    return;
  }

  const normalized = studio_id.trim().toUpperCase();

  const studio = await StudioModel.findOne({ studio_id: normalized, active: true });

  if (!studio) {
    res.status(404).json({ error: "Studio not found" });
    return;
  }

  if (!studio.subscription_url) {
    res.status(403).json({ error: "Studio has no subscription configured" });
    return;
  }

  let configs = await getCachedConfigs(studio.studio_id);

  if (configs.length === 0) {
    const result = await refreshStudioSubscription(studio.studio_id);
    if (!result.ok) {
      res.status(502).json({ error: `Failed to load configs: ${result.error}` });
      return;
    }
    configs = await getCachedConfigs(studio.studio_id);
  }

  if (configs.length === 0) {
    res.status(403).json({ error: "No active configs for this studio" });
    return;
  }

  const response: VpnConfigApiResponse[] = configs.map((c) => ({
    id: String(c._id),
    tag: c.tag,
    host: c.host,
    port: c.port,
    protocol: c.protocol,
    uuid: c.uuid,
    alter_id: c.alter_id,
    security: c.security,
    network: c.network,
    tls: c.tls,
    sni: c.sni,
    path: c.path,
    ws_host: c.ws_host,
    fp: c.fp,
    alpn: c.alpn,
    studio_title: studio.title,
    raw: {
      sni: c.sni,
      path: c.path,
      host: c.ws_host,
      fp: c.fp,
      alpn: c.alpn,
      raw_link: c.raw_link,
    },
  }));

  res.json(response);
});
