import "dotenv/config";
import mongoose from "mongoose";
import DeviceLost from "../model/deviceLost.js";
import Devices from "../model/Devices.js";
import MessageAdmin from "../model/MessageAdmin.js";
import User from "../model/User.js";

const apply = process.argv.includes("--apply");
const rollback = process.argv.includes("--rollback");
if (apply && rollback) {
  throw new Error("Choose either --apply or --rollback, not both.");
}
const environment = String(process.env.ENVIRONMENT_MODE || "").trim().toUpperCase();
if (!environment) {
  throw new Error("Set ENVIRONMENT_MODE explicitly before running this migration.");
}
const mongoUri =
  environment === "SANDBOX"
    ? process.env.MONGO_CONNECTION_URI
    : process.env.MONGO_CONNECTION_URI_CLOUD;

if (!mongoUri) {
  throw new Error("The MongoDB connection URI for the selected environment is missing.");
}

const hasExactIndex = (index, key) =>
  index.key &&
  Object.keys(index.key).length === Object.keys(key).length &&
  Object.entries(key).every(([field, direction]) => index.key[field] === direction);

const duplicateInstallationBindings = async () => {
  const devices = await Devices.find({
    installation_id: { $type: "string", $ne: "" },
  })
    .select("user_id user_email installation_id")
    .lean();
  const emails = [
    ...new Set(
      devices
        .filter((device) => !device.user_id)
        .map((device) => device.user_email)
        .filter(Boolean),
    ),
  ];
  const users = await User.find({ email: { $in: emails } }).select("_id email").lean();
  const userByEmail = new Map(users.map((user) => [user.email, user._id.toString()]));
  const counts = new Map();

  for (const device of devices) {
    const ownerId =
      device.user_id?.toString?.() || userByEmail.get(device.user_email) || "";
    if (!ownerId) continue;

    const key = `${ownerId}|${device.installation_id}`;
    const duplicate = counts.get(key);
    if (duplicate) {
      duplicate.count += 1;
    } else {
      counts.set(key, {
        user_id: ownerId,
        installation_id: device.installation_id,
        count: 1,
      });
    }
  }

  return [...counts.values()].filter((binding) => binding.count > 1).slice(0, 20);
};

const duplicateFingerprints = async (model) =>
  model.aggregate([
    { $group: { _id: "$device_fingerprint", count: { $sum: 1 } } },
    { $match: { count: { $gt: 1 } } },
    { $limit: 20 },
  ]);

const backfillDeviceOwners = async () => {
  const devices = await Devices.find({
    $or: [{ user_id: { $exists: false } }, { user_id: null }],
  })
    .select("user_email")
    .lean();
  const emails = [...new Set(devices.map((device) => device.user_email).filter(Boolean))];
  const users = await User.find({ email: { $in: emails } }).select("_id email").lean();
  const userByEmail = new Map(users.map((user) => [user.email, user._id]));
  const updates = devices
    .filter((device) => userByEmail.has(device.user_email))
    .map((device) => ({
      updateOne: {
        filter: {
          _id: device._id,
          $or: [{ user_id: { $exists: false } }, { user_id: null }],
        },
        update: { $set: { user_id: userByEmail.get(device.user_email) } },
      },
    }));

  if (apply && updates.length) {
    await Devices.bulkWrite(updates, { ordered: false });
  }

  return {
    candidates: devices.length,
    mapped: updates.length,
    unmatched: devices.length - updates.length,
  };
};

const countUnmigratedInstallationOwners = async () => {
  const devices = await Devices.find({
    installation_id: { $type: "string", $ne: "" },
    $or: [{ user_id: { $exists: false } }, { user_id: null }],
  })
    .select("user_email")
    .lean();
  if (!devices.length) return 0;

  const emails = [...new Set(devices.map((device) => device.user_email).filter(Boolean))];
  const matchedUsers = await User.find({ email: { $in: emails } }).select("email").lean();
  const matchedEmails = new Set(matchedUsers.map((user) => user.email));
  return devices.filter((device) => !matchedEmails.has(device.user_email)).length;
};

const dropLegacyUniqueFingerprintIndex = async (model) => {
  const indexes = await model.collection.indexes();
  const index = indexes.find(
    (candidate) =>
      candidate.unique &&
      hasExactIndex(candidate, { device_fingerprint: 1 }),
  );
  if (!index) return null;

  if (apply) await model.collection.dropIndex(index.name);
  return index.name;
};

const rollbackIdentityIndexes = async () => {
  const duplicates = [];
  for (const model of [Devices, DeviceLost, MessageAdmin]) {
    const conflictingFingerprints = await duplicateFingerprints(model);
    if (conflictingFingerprints.length) {
      duplicates.push({
        collection: model.collection.name,
        fingerprints: conflictingFingerprints,
      });
    }
  }
  if (duplicates.length) {
    throw new Error(
      `Cannot restore global fingerprint uniqueness while duplicate values exist: ${JSON.stringify(duplicates)}`,
    );
  }

  if (!apply) {
    console.log("Rollback preflight passed. Pass --apply with --rollback to restore legacy indexes.");
    return;
  }

  const deviceIndexes = await Devices.collection.indexes();
  for (const index of deviceIndexes) {
    if (
      index.key &&
      ((hasExactIndex(index, { user_id: 1, installation_id: 1 }) && index.unique) ||
        (hasExactIndex(index, { device_fingerprint: 1 }) && !index.unique))
    ) {
      await Devices.collection.dropIndex(index.name);
    }
  }

  for (const model of [Devices, DeviceLost, MessageAdmin]) {
    const indexes = await model.collection.indexes();
    const existingUnique = indexes.find(
      (index) => index.unique && hasExactIndex(index, { device_fingerprint: 1 }),
    );
    if (!existingUnique) {
      await model.collection.createIndex(
        { device_fingerprint: 1 },
        { name: "device_fingerprint_1", unique: true },
      );
    }
  }

  console.log("Legacy global fingerprint indexes restored. Identity fields and records were retained.");
};

try {
  await mongoose.connect(mongoUri);

  if (rollback) {
    await rollbackIdentityIndexes();
    process.exitCode = 0;
  } else {
  const ownerBackfill = await backfillDeviceOwners();
  const duplicateBindings = await duplicateInstallationBindings();
  const unmigratedOwners = await countUnmigratedInstallationOwners();

  console.log(JSON.stringify({
    mode: apply ? "apply" : "dry-run",
    environment,
    ownerBackfill,
    duplicateInstallationBindings: duplicateBindings,
    installationRecordsWithoutOwner: unmigratedOwners,
  }, null, 2));

  if (duplicateBindings.length || unmigratedOwners) {
    throw new Error("Resolve the reported installation identity conflicts before index migration.");
  }

  if (!apply) {
    console.log("No changes made. Pass --apply to execute the index/data migration.");
  } else {
    await Devices.updateMany(
      { installation_id: "" },
      { $unset: { installation_id: "" } },
    );

    await Devices.collection.createIndex(
      { user_id: 1, installation_id: 1 },
      {
        name: "user_id_installation_id_unique",
        unique: true,
        partialFilterExpression: {
          user_id: { $type: "objectId" },
          installation_id: { $type: "string", $gt: "" },
        },
      },
    );

    const droppedIndexes = [];
    for (const model of [Devices, DeviceLost, MessageAdmin]) {
      const dropped = await dropLegacyUniqueFingerprintIndex(model);
      if (dropped) droppedIndexes.push({ collection: model.collection.name, name: dropped });
    }

    const deviceIndexes = await Devices.collection.indexes();
    if (!deviceIndexes.some((index) => hasExactIndex(index, { device_fingerprint: 1 }))) {
      await Devices.collection.createIndex(
        { device_fingerprint: 1 },
        { name: "device_fingerprint_lookup" },
      );
    }

    console.log(JSON.stringify({
      applied: true,
      droppedIndexes,
      createdIndexes: [
        "devices.user_id_installation_id_unique",
        "devices.device_fingerprint_lookup",
      ],
    }, null, 2));
  }
  }
} finally {
  await mongoose.disconnect();
}
