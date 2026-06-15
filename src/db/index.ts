import mongoose, { Schema, Document, model, Types } from "mongoose";
import bcrypt from "bcryptjs";

const toJSON = {
  transform: (_: unknown, ret: Record<string, unknown>) => {
    ret["id"] = String(ret["_id"]);
    delete ret["_id"];
    delete ret["__v"];
    return ret;
  },
};

export interface IAdminUser extends Document {
  _id: Types.ObjectId;
  username: string;
  password_hash: string;
  created_at: Date;
}

const AdminUserSchema = new Schema<IAdminUser>(
  {
    username: { type: String, required: true, unique: true },
    password_hash: { type: String, required: true },
    created_at: { type: Date, default: Date.now },
  },
  { toJSON },
);

export const AdminUserModel = model<IAdminUser>("AdminUser", AdminUserSchema);

export interface IStudio extends Document {
  _id: Types.ObjectId;
  studio_id: string;
  title: string;
  subscription_url: string | null;
  active: boolean;
  last_fetched_at: Date | null;
  last_fetch_status: string | null;
  created_at: Date;
}

const StudioSchema = new Schema<IStudio>(
  {
    studio_id: { type: String, required: true, unique: true },
    title: { type: String, required: true },
    subscription_url: { type: String, default: null },
    active: { type: Boolean, default: true },
    last_fetched_at: { type: Date, default: null },
    last_fetch_status: { type: String, default: null },
    created_at: { type: Date, default: Date.now },
  },
  { toJSON },
);

export const StudioModel = model<IStudio>("Studio", StudioSchema);

export type ParsedProtocol = "ss" | "vless" | "vmess" | "trojan";

export interface IVpnConfig extends Document {
  _id: Types.ObjectId;
  studio_id: string;
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
  raw_link: string;
  active: boolean;
  created_at: Date;
}
const VpnConfigSchema = new Schema<IVpnConfig>(
  {
    studio_id: { type: String, required: true, index: true },
    protocol: { type: String, default: "vmess" },
    tag: { type: String, required: true },
    host: { type: String, required: true },
    port: { type: Number, default: 443 },
    uuid: { type: String, required: true, default: "" },
    alter_id: { type: Number, default: 0 },
    security: { type: String, default: "auto" },
    network: { type: String, default: "tcp" },
    tls: { type: Boolean, default: false },
    sni: { type: String, default: null },
    path: { type: String, default: null },
    ws_host: { type: String, default: null },
    fp: { type: String, default: null },
    alpn: { type: String, default: null },
    // @ts-ignore
    pbk: { type: String, default: null },
    sid: { type: String, default: null },
    flow: { type: String, default: null },
    service_name: { type: String, default: null },
    raw_link: { type: String, default: "" },
    active: { type: Boolean, default: true },
    created_at: { type: Date, default: Date.now },
  },
  { toJSON },
);
export const VpnConfigModel = model<IVpnConfig>("VpnConfig", VpnConfigSchema);

let connected = false;

export async function initDb(): Promise<void> {
  if (connected && mongoose.connection.readyState === 1) {
    return;
  }

  const MONGO_URI =
    process.env["MONGO_URI"] ?? "mongodb://localhost:27017/linker";

  await mongoose.connect(MONGO_URI);
  connected = true;
  console.log("[DB] Connected to MongoDB");

  const adminExists = await AdminUserModel.findOne({ username: "admin" });
  if (!adminExists) {
    const defaultPassword = process.env["ADMIN_PASSWORD"] ?? "admin123";
    const hash = bcrypt.hashSync(defaultPassword, 12);
    await AdminUserModel.create({ username: "admin", password_hash: hash });
    console.log(
      `[DB] Default admin created — username: admin, password: ${defaultPassword}`,
    );
  }
}

