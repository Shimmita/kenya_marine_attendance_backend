import mongoose from "mongoose";

const passwordResetSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  codeHash: { type: String, required: true },
  expiresAt: { type: Date },
  lastSentAt: { type: Date, default: Date.now },
  attempts: { type: Number, default: 0 },
}, { timestamps: true });

export default mongoose.model("PasswordReset", passwordResetSchema);
