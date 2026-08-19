import mongoose from "mongoose";

const reminderDeliverySchema = new mongoose.Schema(
  {
    reminderKey: {
      type: String,
      required: true,
      unique: true,
      index: true,
    },
    user_email: {
      type: String,
      required: true,
      lowercase: true,
      trim: true,
      index: true,
    },
    type: {
      type: String,
      required: true,
      enum: ["CLOCK_IN_REMINDER", "CLOCK_OUT_REMINDER"],
      index: true,
    },
    dateKey: {
      type: String,
      required: true,
      index: true,
    },
    status: {
      type: String,
      enum: ["pending", "sent", "failed"],
      default: "pending",
    },
    sentAt: {
      type: Date,
      default: null,
    },
    error: {
      type: String,
      default: "",
    },
  },
  { timestamps: true }
);

reminderDeliverySchema.index({ type: 1, user_email: 1, dateKey: 1 }, { unique: true });

export default mongoose.model("reminder_delivery", reminderDeliverySchema);
