import mongoose from "mongoose";

const authenticatorSchema = new mongoose.Schema({
  // Store as Base64URL strings — avoids Buffer serialization issues with MongoDB
  credentialID: { type: String, required: true },
  credentialPublicKey: { type: String, required: true },
  counter: { type: Number, required: true, default: 0 },
});


const userSchema = new mongoose.Schema(
  {
    name: { type: String, required: true, trim: true },
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
    },

    password: { type: String, required: true },

    department: { type: String, default: "" },
    supervisor: {
      type: String, default: "", lowercase: true,
      trim: true,
    },
    phone: { type: String, required: true },
    station: { type: String, default: "" },
    startDate: { type: String, required: false, default: null },
    endDate: { type: String, required: false, default: null },

    gender: {
      type: String,
      enum: ["Male", "Female", "Other"],
      default: "Other",
      required: true
    },
    employeeId: {
      type: String, default: ""
    },
    role: {
      type: String,
      enum: ["employee", "intern", "attachee", "employee-contract"],
      // Todo: make this required
      default: "employee",
    },
    rank: {
      type: String,
      enum: ["admin", "user", "hr", "supervisor", "ceo"],
      // default: "user",
      default: "admin",
    },
    avatarID: { type: String, default: "" },
    avatar: { type: String, default: "" },
    email_verified: { type: Boolean, default: true },
    deviceLost: { type: Boolean, default: false },
    hasDevices: { type: Boolean, default: false },
    doneBiometric: { type: Boolean, default: false },
    hasClockedIn: { type: Boolean, default: false },
    isToClockOut: { type: Boolean, default: false },
    isAccountActive: { type: Boolean, default: true },
    // 🔐 BIOMETRICS — credentialID and credentialPublicKey stored as Base64URL strings
    authenticator: authenticatorSchema,
  },
  { timestamps: true }
);

userSchema.set("toJSON", {
  transform: (doc, ret) => {
    delete ret.password;
    return ret;
  },
});

export default mongoose.model("User", userSchema);