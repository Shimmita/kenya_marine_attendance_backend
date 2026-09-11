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
        supervisor: { type: String, default: "", required: false },
        station: { type: String, default: "", required: true },
        phone: { type: String, required: true },

        clock_in: { type: Date, required: true },
        clock_out: { type: Date, default: null },
        missedClockOut: { type: Boolean, default: false },
        isPresent: { type: Boolean, default: false },
        clockedOutSide: { type: Boolean, default: false },
        outSideReason: { type: String, default: ""},
        isLate: { type: Boolean, default: false },
        outsideLocation: { type: String, default: "" },
        clockInLocationName: { type: String, default: "" },
        clockOutLocationName: { type: String, default: "" },
        clockInWithinPremise: { type: Boolean, required: false },
        clockOutWithinPremise: { type: Boolean, required: false },
        clockInMethod: {
            type: String,
            enum: ["standard", "clocking-point"],
            default: "standard",
        },
        clockOutMethod: {
            type: String,
            enum: ["standard", "clocking-point"],
            default: null,
        },
        clockInClockingPoint: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "ClockingPoint",
            default: null,
        },
        clockOutClockingPoint: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "ClockingPoint",
            default: null,
        },
        userLocation: {
            latitude: { type: Number, required: false },
            longitude: { type: Number, required: false },
        },

    },
    { timestamps: true }
);


export default mongoose.model("Clocking", clockingSchema);
