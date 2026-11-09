import mongoose from "mongoose";

const deviceSchema = new mongoose.Schema(
    {
        device_name: { type: String, required: true, trim: true },
        user_email: {
            type: String,
            required: true,
            lowercase: true,
            trim: true,
        },
        user_id: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "User",
            default: null,
        },
        installation_id: { type: String, trim: true },

        device_os: { type: String, default: "" },
        device_browser: { type: String, default: "" },
        device_primary: { type: Boolean, default: false },
        device_lost: { type: Boolean, default: false },
        device_fingerprint: { type: String, required: true },
    },
    { timestamps: true, autoIndex: false }
);

deviceSchema.index(
    { user_id: 1, installation_id: 1 },
    {
        name: "user_id_installation_id_unique",
        unique: true,
        partialFilterExpression: {
            user_id: { $type: "objectId" },
            installation_id: { $type: "string", $gt: "" },
        },
    }
);
deviceSchema.index(
    { device_fingerprint: 1 },
    { name: "device_fingerprint_lookup" }
);

export default mongoose.model("devices", deviceSchema);
