import mongoose from "mongoose";

const clockingPointChallengeSchema = new mongoose.Schema(
  {
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
      index: true,
    },
    clockingPoint: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "ClockingPoint",
      required: true,
      index: true,
    },
    action: {
      type: String,
      enum: ["clock_in", "clock_out"],
      required: true,
    },
    otpHash: {
      type: String,
      required: true,
    },
    expiresAt: {
      type: Date,
      required: true,
      index: true,
    },
    attempts: {
      type: Number,
      default: 0,
    },
    resendCount: {
      type: Number,
      default: 0,
    },
    used: {
      type: Boolean,
      default: false,
      index: true,
    },
  },
  { timestamps: true }
);

clockingPointChallengeSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });
clockingPointChallengeSchema.index({ user: 1, used: 1, expiresAt: 1 });

export default mongoose.model("ClockingPointChallenge", clockingPointChallengeSchema);
