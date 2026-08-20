import mongoose from "mongoose";

const exportDocumentSchema = new mongoose.Schema(
  {
    token: { type: String, required: true, unique: true, index: true },
    type: { type: String, default: "attendance_export", index: true },
    title: { type: String, default: "KMFRI Attendance Export" },
    scope: { type: String, default: "" },
    filename: { type: String, default: "" },
    mimeType: { type: String, default: "application/pdf" },
    documentBase64: { type: String, default: "" },
    dataHash: { type: String, default: "" },
    metadata: { type: mongoose.Schema.Types.Mixed, default: {} },
    generatedBy: {
      userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", default: null },
      name: { type: String, default: "" },
      rank: { type: String, default: "" },
      station: { type: String, default: "" },
      department: { type: String, default: "" },
    },
    expiresAt: {
      type: Date,
      default: () => new Date(Date.now() + 90 * 24 * 60 * 60 * 1000),
      index: { expires: 0 },
    },
  },
  { timestamps: true }
);

export default mongoose.model("ExportDocument", exportDocumentSchema);
