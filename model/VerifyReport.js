import mongoose from 'mongoose';

const verificationSchema = new mongoose.Schema({
  token: { type: String, required: true, unique: true },
  type: { type: String, default: 'attendance_report' },
  dataHash: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
  expiresAt: { type: Date },
});

export default mongoose.model('Verification', verificationSchema);