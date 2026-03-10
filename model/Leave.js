// models/Leave.js
import mongoose from "mongoose";

const leaveSchema = new mongoose.Schema({
    startDate: { type: Date, required: true },
    endDate: { type: Date, required: true },
    status: {
        type: String,
        enum: ["pending", "rejected", "approved"],
        default: "pending",
    },
    email: {
        type: String,
        required: true,
        lowercase: true,
        trim: true,
    },
    type: { type: String, required: true },
    reliever: { type: String },
    remarks: { type: String },
    attachment: { type: String },
}, { timestamps: true });

export default mongoose.model("leave", leaveSchema);