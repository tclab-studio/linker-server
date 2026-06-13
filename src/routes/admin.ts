import { Router, Request, Response } from "express";
import bcrypt from "bcryptjs";
import {
  AdminUserModel,
  StudioModel,
  VpnConfigModel,
} from "../db/index.js";
import { authMiddleware, signToken } from "../middleware/auth.js";
import { VpnConfig } from "../types/index.js";

export const adminRouter = Router();

adminRouter.post("/login", async (req: Request, res: Response) => {
  const { username, password } = req.body as {
    username?: string;
    password?: string;
  };

  if (!username || !password) {
    res.status(400).json({ error: "username and password required" });
    return;
  }

  const admin = await AdminUserModel.findOne({ username });

  if (!admin || !bcrypt.compareSync(password, admin.password_hash)) {
    res.status(401).json({ error: "Invalid credentials" });
    return;
  }

  const token = signToken({
    adminId: String(admin._id),
    username: admin.username,
  });

  res.cookie("admin_token", token, {
    httpOnly: true,
    secure: process.env["NODE_ENV"] === "production",
    sameSite: "strict",
    maxAge: 24 * 60 * 60 * 1000,
  });

  res.json({ ok: true, username: admin.username });
});

adminRouter.post("/logout", (_req: Request, res: Response) => {
  res.clearCookie("admin_token");
  res.json({ ok: true });
});

adminRouter.get("/me", authMiddleware, (req: Request, res: Response) => {
  res.json({ username: req.admin?.username });
});

adminRouter.get(
  "/studios",
  authMiddleware,
  async (_req: Request, res: Response) => {
    const studios = await StudioModel.aggregate([
      {
        $lookup: {
          from: "vpnconfigs",
          let: { sid: "$studio_id" },
          pipeline: [
            {
              $match: {
                $expr: {
                  $and: [
                    { $eq: ["$studio_id", "$$sid"] },
                    { $eq: ["$active", true] },
                  ],
                },
              },
            },
            { $count: "count" },
          ],
          as: "configs",
        },
      },
      {
        $addFields: {
          id: { $toString: "$_id" },
          config_count: {
            $ifNull: [{ $arrayElemAt: ["$configs.count", 0] }, 0],
          },
        },
      },
      { $project: { _id: 0, __v: 0, configs: 0 } },
      { $sort: { created_at: -1 } },
    ]);

    res.json(studios);
  },
);

adminRouter.post(
  "/studios",
  authMiddleware,
  async (req: Request, res: Response) => {
    const { studio_id, title } = req.body as {
      studio_id?: string;
      title?: string;
    };

    if (!studio_id || !title) {
      res.status(400).json({ error: "studio_id and title required" });
      return;
    }

    const normalized = studio_id.trim().toUpperCase();

    const exists = await StudioModel.findOne({ studio_id: normalized });
    if (exists) {
      res.status(409).json({ error: "Studio ID already exists" });
      return;
    }

    const studio = await StudioModel.create({
      studio_id: normalized,
      title: title.trim(),
      active: true,
    });

    res.status(201).json(studio.toJSON());
  },
);

adminRouter.patch(
  "/studios/:studioId",
  authMiddleware,
  async (req: Request, res: Response) => {
    const { studioId } = req.params as { studioId: string };
    const { title, active } = req.body as { title?: string; active?: boolean };

    const update: Record<string, unknown> = {};
    if (title !== undefined) update["title"] = title.trim();
    if (active !== undefined) update["active"] = active;

    const studio = await StudioModel.findOneAndUpdate(
      { studio_id: studioId },
      { $set: update },
      { new: true },
    );

    if (!studio) {
      res.status(404).json({ error: "Studio not found" });
      return;
    }

    res.json(studio.toJSON());
  },
);

adminRouter.delete(
  "/studios/:studioId",
  authMiddleware,
  async (req: Request, res: Response) => {
    const { studioId } = req.params as { studioId: string };

    const studio = await StudioModel.findOneAndDelete({ studio_id: studioId });
    if (!studio) {
      res.status(404).json({ error: "Studio not found" });
      return;
    }

    await VpnConfigModel.deleteMany({ studio_id: studioId });

    res.json({ ok: true });
  },
);

adminRouter.get(
  "/studios/:studioId/configs",
  authMiddleware,
  async (req: Request, res: Response) => {
    const { studioId } = req.params as { studioId: string };

    const configs = await VpnConfigModel.find({ studio_id: studioId }).sort({
      created_at: -1,
    });

    res.json(configs.map((c) => c.toJSON()));
  },
);

adminRouter.post(
  "/studios/:studioId/configs",
  authMiddleware,
  async (req: Request, res: Response) => {
    const { studioId } = req.params as { studioId: string };
    const { tag, host, port, protocol, uuid, alter_id, security, network, tls } =
      req.body as {
        tag?: string;
        host?: string;
        port?: number;
        protocol?: string;
        uuid?: string;
        alter_id?: number;
        security?: string;
        network?: string;
        tls?: boolean;
      };

    if (!tag || !host || !uuid) {
      res.status(400).json({ error: "tag, host, and uuid are required" });
      return;
    }

    const studio = await StudioModel.findOne({ studio_id: studioId });
    if (!studio) {
      res.status(404).json({ error: "Studio not found" });
      return;
    }

    const config = await VpnConfigModel.create({
      studio_id: studioId,
      tag: tag.trim(),
      host: host.trim(),
      port: port ?? 443,
      protocol: protocol ?? "vmess",
      uuid: uuid.trim(),
      alter_id: alter_id ?? 0,
      security: security ?? "auto",
      network: network ?? "tcp",
      tls: tls ?? false,
      active: true,
    });

    res.status(201).json(config.toJSON());
  },
);

adminRouter.patch(
  "/configs/:configId",
  authMiddleware,
  async (req: Request, res: Response) => {
    const { configId } = req.params as { configId: string };
    const fields = req.body as Partial<VpnConfig>;

    const allowed: (keyof VpnConfig)[] = [
      "tag",
      "host",
      "port",
      "protocol",
      "uuid",
      "alter_id",
      "security",
      "network",
      "tls",
      "active",
    ];

    const update: Partial<VpnConfig> = {};
    for (const key of allowed) {
      if (key in fields) {
        (update as Record<string, unknown>)[key] = fields[key];
      }
    }

    if (Object.keys(update).length === 0) {
      res.status(400).json({ error: "No valid fields to update" });
      return;
    }

    const config = await VpnConfigModel.findByIdAndUpdate(
      configId,
      { $set: update },
      { new: true },
    );

    if (!config) {
      res.status(404).json({ error: "Config not found" });
      return;
    }

    res.json(config.toJSON());
  },
);

adminRouter.delete(
  "/configs/:configId",
  authMiddleware,
  async (req: Request, res: Response) => {
    const { configId } = req.params as { configId: string };

    const config = await VpnConfigModel.findByIdAndDelete(configId);
    if (!config) {
      res.status(404).json({ error: "Config not found" });
      return;
    }

    res.json({ ok: true });
  },
);

adminRouter.get(
  "/stats",
  authMiddleware,
  async (_req: Request, res: Response) => {
    const [totalStudios, activeStudios, totalConfigs, activeConfigs] =
      await Promise.all([
        StudioModel.countDocuments(),
        StudioModel.countDocuments({ active: true }),
        VpnConfigModel.countDocuments(),
        VpnConfigModel.countDocuments({ active: true }),
      ]);

    res.json({ totalStudios, activeStudios, totalConfigs, activeConfigs });
  },
);

adminRouter.post(
  "/change-password",
  authMiddleware,
  async (req: Request, res: Response) => {
    const { current_password, new_password } = req.body as {
      current_password?: string;
      new_password?: string;
    };

    if (!current_password || !new_password) {
      res
        .status(400)
        .json({ error: "current_password and new_password required" });
      return;
    }

    if (new_password.length < 8) {
      res.status(400).json({ error: "Password must be at least 8 characters" });
      return;
    }

    const admin = await AdminUserModel.findById(req.admin!.adminId);
    if (!admin) {
      res.status(404).json({ error: "Admin not found" });
      return;
    }

    if (!bcrypt.compareSync(current_password, admin.password_hash)) {
      res.status(401).json({ error: "Current password is wrong" });
      return;
    }

    const hash = bcrypt.hashSync(new_password, 12);
    await AdminUserModel.findByIdAndUpdate(req.admin!.adminId, {
      $set: { password_hash: hash },
    });

    res.json({ ok: true });
  },
);
