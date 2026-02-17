import mongoose from "mongoose";

const clockingSchema = new mongoose.Schema(
    {
        name: { type: String, required: true, trim: true },
        email: {
            type: String,
            required: true,
            lowercase: true,
            trim: true,
        },

        department: { type: String, required: true, default: "" },
        supervisor: { type: String, default: "", required: true },
        station: { type: String, default: "", required: true },
        phone: { type: String, required: true },

        clock_in: { type: Date, required: true },
        clock_out: { type: Date, default: null },
        isPresent: { type: Boolean, default: false },
        isLate: { type: Boolean, default: false },

    },
    { timestamps: true }
);


export default mongoose.model("Clocking", clockingSchema);
