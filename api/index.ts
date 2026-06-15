import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import path from "path";
import dotenv from "dotenv";
import { initDb } from "../src/db/index";
import { studiosRouter } from "../src/routes/studios";
import { adminRouter } from "../src/routes/admin";
import { startAutoRefresh } from "../src/services/subscription";

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

let dbInitialized = false;
let autoRefreshStarted = false;

app.use(async (_req, _res, next) => {
  try {
    if (!dbInitialized) {
      await initDb();
      dbInitialized = true;
    }
    if (!autoRefreshStarted) {
      startAutoRefresh();
      autoRefreshStarted = true;
    }
    next();
  } catch (error) {
    next(error);
  }
});

app.use("/studios", studiosRouter);
app.use("/admin/api", adminRouter);

app.get("/admin", (_req, res) => {
  const htmlPath = path.join(__dirname, "..", "src", "index.html");
  res.sendFile(htmlPath);
});

app.get("/health", (_req, res) => {
  res.json({
    status: "ok",
    ts: new Date().toISOString(),
  });
});

export default app;
