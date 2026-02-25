import mongoose from "mongoose";

const feedbackSchema = new mongoose.Schema(
    {
        overall: {type: Number, default:0 },
        easeOfUse: {type: Number, default:0 },
        responsiveness: {type: Number, default:0 },
        speed: {type: Number, default:0 },
        clocking: {type: Number, default:0 },
        uiDesign: {type: Number, default:0 },
        reliability: {type: Number, default:0 },
    },
    { timestamps: true }
);

export default mongoose.model("Feedback", feedbackSchema);