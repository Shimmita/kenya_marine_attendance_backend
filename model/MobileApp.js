import mongoose from "mongoose";

const mobileAppSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
    installationId: { type: String, required: true, trim: true },
    deviceHash: { type: String, required: true, trim: true, lowercase: true },
    deviceName: { type: String, required: true, trim: true },
    deviceModel: { type: String, default: "", trim: true },
    deviceManufacturer: { type: String, default: "", trim: true },
    deviceOS: { type: String, required: true, trim: true },
    deviceOSVersion: { type: String, default: "", trim: true },
    platform: { type: String, required: true, trim: true },
    appVersion: { type: String, default: "", trim: true },
    enrolledAt: { type: Date, default: Date.now },
    lastSeenAt: { type: Date, default: Date.now },
    lastAuthenticatedAt: { type: Date, default: Date.now },
    isActive: { type: Boolean, default: true },
    revokedAt: { type: Date, default: null },
    revokedReason: { type: String, default: "" },
    biometricEnabled: { type: Boolean, default: false },
    biometricType: { type: String, default: "" },
    pushToken: { type: String, default: "" },
  },
  { timestamps: true }
);

mobileAppSchema.index({ installationId: 1 }, { unique: true });
mobileAppSchema.index(
  { userId: 1 },
  { unique: true, partialFilterExpression: { isActive: true } }
);

export default mongoose.model("MobileApp", mobileAppSchema);
