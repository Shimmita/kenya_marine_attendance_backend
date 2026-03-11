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
    type: {
        type: String, required: true,
        enum: ["Adoption Leave", "Annual Leave", "Compassionate Leave", "Paternity Leave", "Sick Leave", "Study Leave", "Terminal Leave"],
        default: "Annual Leave"
    },
    reliever: { type: String, required: true, },
    remarks: { type: String, required: true, },
    attachment: { type: String, required: true },
}, { timestamps: true });

export default mongoose.model("leave", leaveSchema);