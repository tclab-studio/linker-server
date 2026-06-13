import { Router, Request, Response } from "express";
import { StudioModel, VpnConfigModel } from "../db/index.js";
import { VpnConfigApiResponse } from "../types/index.js";

export const studiosRouter = Router();

studiosRouter.post("/verify", async (req: Request, res: Response) => {
  const { studio_id } = req.body as { studio_id?: string };

  if (!studio_id || typeof studio_id !== "string" || studio_id.trim() === "") {
    res.status(400).json({ error: "studio_id is required" });
    return;
  }

  const studio = await StudioModel.findOne({
    studio_id: studio_id.trim().toUpperCase(),
    active: true,
  });

  if (!studio) {
    res.status(404).json({ error: "Studio not found" });
    return;
  }

  const configs = await VpnConfigModel.find({
    studio_id: studio.studio_id,
    active: true,
  });

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
    studio_title: studio.title,
  }));

  res.json(response);
});
