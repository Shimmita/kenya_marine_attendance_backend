import mongoose from "mongoose";

const supervisorSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true,
    },
    email: {
        type: String,
        required: true,
        unique: true
    },
    department: {
        type: String,
        required: true
    },
    station: {
        type: String,
        default:''
    }
}, { timestamps: true })

export default mongoose.model("Supervisor", supervisorSchema);