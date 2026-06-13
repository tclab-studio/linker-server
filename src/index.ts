import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import path from "path";
import dotenv from "dotenv";
import { initDb } from "./db/index.js";
import { studiosRouter } from "./routes/studios.js";
import { adminRouter } from "./routes/admin.js";

dotenv.config();

const app = express();

app.use(
  cors({
    origin: process.env["CORS_ORIGIN"] ?? "*",
    credentials: true,
  }),
);

app.use(express.json());
app.use(cookieParser());

app.use(express.static(path.join(process.cwd(), "admin")));

app.use("/studios", studiosRouter);
app.use("/admin/api", adminRouter);

app.get("/admin", (_req, res) => {
  res.sendFile(path.join(process.cwd(), "admin", "index.html"));
});

app.get("/health", (_req, res) => {
  res.json({ status: "ok", ts: new Date().toISOString() });
});

let initialized = false;

app.use(async (_req, _res, next) => {
  if (!initialized) {
    await initDb();
    initialized = true;
  }
  next();
});

export default app;
