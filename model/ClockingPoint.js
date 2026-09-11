import mongoose from "mongoose";

const clockingPointSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
      trim: true,
    },
    station: {
      type: String,
      required: true,
      trim: true,
    },
    deviceFingerprintHash: {
      type: String,
      required: true,
      unique: true,
      index: true,
    },
    enrolledBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
    isActive: {
      type: Boolean,
      default: true,
    },
    enrolledAt: {
      type: Date,
      default: Date.now,
    },
    lastSeenAt: {
      type: Date,
      default: null,
    },
    revokedAt: {
      type: Date,
      default: null,
    },
  },
  { timestamps: true }
);

clockingPointSchema.index({ station: 1, isActive: 1 });

export default mongoose.model("ClockingPoint", clockingPointSchema);
