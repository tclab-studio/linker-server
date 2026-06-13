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
  active: boolean;
  created_at: Date;
}

const StudioSchema = new Schema<IStudio>(
  {
    studio_id: { type: String, required: true, unique: true },
    title: { type: String, required: true },
    active: { type: Boolean, default: true },
    created_at: { type: Date, default: Date.now },
  },
  { toJSON },
);

export const StudioModel = model<IStudio>("Studio", StudioSchema);

export interface IVpnConfig extends Document {
  _id: Types.ObjectId;
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

const VpnConfigSchema = new Schema<IVpnConfig>(
  {
    studio_id: { type: String, required: true },
    tag: { type: String, required: true },
    host: { type: String, required: true },
    port: { type: Number, default: 443 },
    protocol: { type: String, default: "vmess" },
    uuid: { type: String, required: true },
    alter_id: { type: Number, default: 0 },
    security: { type: String, default: "auto" },
    network: { type: String, default: "tcp" },
    tls: { type: Boolean, default: false },
    extra: { type: Schema.Types.Mixed, default: {} },
    active: { type: Boolean, default: true },
    created_at: { type: Date, default: Date.now },
  },
  { toJSON },
);

export const VpnConfigModel = model<IVpnConfig>("VpnConfig", VpnConfigSchema);

export async function initDb(): Promise<void> {
  const MONGO_URI =
    process.env["MONGO_URI"] ?? "mongodb://localhost:27017/linker";

  await mongoose.connect(MONGO_URI);
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

