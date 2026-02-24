import mongoose from "mongoose";

const supervisorSchema = new mongoose.Schema({
    startDate: { type: Date, required: true },
    endDate: { type: Date, required: true, },
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
        type: String,
        enum: ["maternity", "sick", "compasion", "casual"],
        required: true
    },
}, { timestamps: true })

export default mongoose.model("leave", supervisorSchema);