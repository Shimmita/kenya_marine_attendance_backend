import mongoose from "mongoose";

const clockingSchema = new mongoose.Schema(
    {
        name: { type: String, required: true, trim: true },
        email: {
            type: String,
            required: true,
            unique: true,
            lowercase: true,
            trim: true,
        },

        department: { type: String, default: "" },
        supervisor: { type: String, default: "" },
        station: { type: String, default: "" },
        phone: { type: String, required: true },

        clock_in: { type: String, required: true },
        clock_out: { type: String, required: true },

    },
    { timestamps: true }
);


export default mongoose.model("Clocking", clockingSchema);
