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
    supervisor: { type: String, default: "" },
    phone: { type: String, required: true },

    startDate: { type: String, required: true },
    endDate: { type: String, required: true },

    gender: {
      type: String,
      enum: ["Male", "Female", "Other"],
      default: "Other",
    },

    avatarID: { type: String, default: "" },
    avatar: { type: String, default: "" },

    email_verified: { type: Boolean, default: true },

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