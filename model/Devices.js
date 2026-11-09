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
        // fingerprinting using hashed algo, unique to each devices
        device_fingerprint: { type: String, required: true, unique: true },
    },
    { timestamps: true }
);


export default mongoose.model("devices", deviceSchema);
