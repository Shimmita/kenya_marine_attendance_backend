import mongoose from "mongoose";

const { Schema } = mongoose;

const userSnapshotSchema = new Schema(
  {
    userId: { type: String, default: "" },
    name: { type: String, default: "" },
    email: { type: String, default: "" },
    rank: { type: String, default: "" },
    role: { type: String, default: "" },
    department: { type: String, default: "" },
    station: { type: String, default: "" },
  },
  { _id: false }
);

const auditLogSchema = new Schema(
  {
    category: {
      type: String,
      enum: [
        "authentication",
        "attendance",
        "leave",
        "profile",
        "device",
        "password_reset",
        "admin_action",
      ],
      required: true,
    },
    action: { type: String, required: true, trim: true, index: true },
    description: { type: String, required: true, trim: true },
    status: {
      type: String,
      enum: ["success", "failed"],
      default: "success",
    },
    actor: { type: userSnapshotSchema, required: true },
    target: { type: userSnapshotSchema, default: null },
    metadata: { type: Schema.Types.Mixed, default: {} },
    ipAddress: { type: String, default: "" },
    userAgent: { type: String, default: "" },
    occurredAt: { type: Date, default: Date.now, index: true },
  },
  { timestamps: true }
);

auditLogSchema.index({ category: 1, occurredAt: -1 });
auditLogSchema.index({ "actor.email": 1, occurredAt: -1 });
auditLogSchema.index({ "target.email": 1, occurredAt: -1 });

export default mongoose.model("AuditLog", auditLogSchema);
