/**
 * One-time cleanup: device records whose owner account no longer exists.
 *
 * Before the user-delete fix, deleting a user left their Devices (and DeviceLost)
 * records behind. Those orphaned fingerprints keep blocking other staff with
 * "This device is already enrolled by another account."
 *
 * Only records whose user_email matches NO existing user are touched, so no
 * current user is affected.
 *
 * Usage (from the backend folder):
 *   node scripts/cleanupOrphanDevices.js           # dry run: report only (default)
 *   node scripts/cleanupOrphanDevices.js --apply   # actually delete
 *
 * Uses the same connection selection as index.js (ENVIRONMENT_MODE=SANDBOX → local).
 * Take a backup (mongodump) before running with --apply.
 */
import "dotenv/config";
import mongoose from "mongoose";
import DeviceLost from "../model/deviceLost.js";
import Devices from "../model/Devices.js";
import User from "../model/User.js";

const apply = process.argv.includes("--apply");
const uri =
  process.env.ENVIRONMENT_MODE === "SANDBOX"
    ? process.env.MONGO_CONNECTION_URI
    : process.env.MONGO_CONNECTION_URI_CLOUD;

const normalizeEmail = (email) => String(email || "").trim().toLowerCase();

const main = async () => {
  if (!uri) throw new Error("MongoDB connection URI is not configured.");

  await mongoose.connect(uri);
  console.log(`Connected (${process.env.ENVIRONMENT_MODE === "SANDBOX" ? "LOCAL" : "CLOUD"}). Mode: ${apply ? "APPLY" : "DRY RUN"}`);

  const existingEmails = new Set(
    (await User.find({}).select("email").lean()).map((user) => normalizeEmail(user.email))
  );

  const orphanDevices = (await Devices.find({})
    .select("user_email device_name device_os device_browser device_lost device_fingerprint createdAt")
    .lean())
    .filter((device) => !existingEmails.has(normalizeEmail(device.user_email)));

  const orphanLostRequests = (await DeviceLost.find({}).select("user_email status").lean())
    .filter((request) => !existingEmails.has(normalizeEmail(request.user_email)));

  console.log(`\nUsers: ${existingEmails.size}`);
  console.log(`Orphaned device records: ${orphanDevices.length}`);
  for (const device of orphanDevices) {
    console.log(
      `  - ${device.user_email} | ${device.device_name} (${device.device_os} / ${device.device_browser})` +
      ` | lost=${Boolean(device.device_lost)} | fp=${String(device.device_fingerprint).slice(0, 10)}…`
    );
  }
  console.log(`Orphaned lost-device requests: ${orphanLostRequests.length}`);

  if (!apply) {
    console.log("\nDry run only. Re-run with --apply to delete the records listed above.");
    return;
  }

  if (orphanDevices.length) {
    const result = await Devices.deleteMany({ _id: { $in: orphanDevices.map((device) => device._id) } });
    console.log(`Deleted ${result.deletedCount} orphaned device record(s).`);
  }

  if (orphanLostRequests.length) {
    const result = await DeviceLost.deleteMany({ _id: { $in: orphanLostRequests.map((request) => request._id) } });
    console.log(`Deleted ${result.deletedCount} orphaned lost-device request(s).`);
  }
};

main()
  .catch((err) => {
    console.error("Cleanup failed:", err.message);
    process.exitCode = 1;
  })
  .finally(() => mongoose.disconnect());
