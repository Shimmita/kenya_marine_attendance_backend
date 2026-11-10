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

        device_os: { type: String, default: "" },
        device_browser: { type: String, default: "" },
        device_primary: { type: Boolean, default: false },
        device_lost: { type: Boolean, default: false },
        // FingerprintJS visitorId. NOT globally unique: identical device models can
        // share it, so uniqueness is enforced per account (see index below) and
        // cross-account conflicts are decided with device_install_id.
        device_fingerprint: { type: String, required: true },
        // Random per-browser-install ID (optional; backfilled on next clock-in).
        device_install_id: { type: String, default: "", trim: true },
    },
    { timestamps: true }
);

// One record per fingerprint per account. Replaces the old global unique index
// on device_fingerprint (dropped at startup by ensureDeviceIdentityIndexes).
deviceSchema.index({ device_fingerprint: 1, user_email: 1 }, { unique: true });
deviceSchema.index({ device_install_id: 1 });


export default mongoose.model("devices", deviceSchema);
