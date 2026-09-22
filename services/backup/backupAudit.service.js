import AuditLog from "../../model/AuditLog.js";

const snapshotActor = (actor = {}) => ({
  userId: actor?._id?.toString?.() || actor?.userId || "",
  name: actor?.name || "SYSTEM",
  email: actor?.email || "",
  rank: actor?.rank || "system",
  role: actor?.role || "",
  department: actor?.department || "",
  station: actor?.station || "",
});

export const logBackupAudit = async ({
  req = null,
  action,
  description,
  actor = null,
  metadata = {},
  status = "success",
}) => {
  try {
    const ipAddress =
      req?.headers?.["x-forwarded-for"]?.toString().split(",")[0].trim() ||
      req?.socket?.remoteAddress ||
      "";
    const userAgent = req?.get?.("user-agent") || "";

    await AuditLog.create({
      category: "superadmin",
      action,
      description,
      status,
      actor: snapshotActor(actor || { name: "SYSTEM", rank: "system" }),
      metadata,
      ipAddress,
      userAgent,
      occurredAt: new Date(),
    });
  } catch (error) {
    console.error("Backup audit log creation failed:", error?.message || error);
  }
};
