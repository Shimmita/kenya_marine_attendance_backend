import fs from "fs/promises";
import path from "path";

const trimEnvValue = (value) =>
  String(value || "").trim().replace(/^["']|["']$/g, "");

const parseBooleanEnv = (value, fallback = false) => {
  if (value === undefined || value === null || value === "") return fallback;
  const normalized = String(value).trim().toLowerCase();
  if (["true", "1", "yes", "y"].includes(normalized)) return true;
  if (["false", "0", "no", "n"].includes(normalized)) return false;
  return fallback;
};

export const isWindowsUncPath = (value) => {
  const text = trimEnvValue(value);
  return /^\\\\[^\\/:*?"<>|\r\n]+\\[^\\/:*?"<>|\r\n]+(?:\\[^:*?"<>|\r\n]+)*\\?$/u.test(text);
};

export const validateCustomNetworkPath = (value) => {
  const text = trimEnvValue(value);

  if (!text) {
    throw new Error("Network backup location is required.");
  }

  if (!isWindowsUncPath(text)) {
    throw new Error("Enter a valid Windows UNC network path.");
  }

  const segments = text.split("\\").filter(Boolean);
  if (segments.some((segment) => segment === "." || segment === "..")) {
    throw new Error("Network backup location contains invalid path traversal segments.");
  }

  return path.win32.normalize(text);
};

export const getBackupMongoUri = () => {
  const environment = process.env.ENVIRONMENT_MODE;
  const uri =
    environment === "SANDBOX"
      ? process.env.MONGO_CONNECTION_URI
      : process.env.MONGO_CONNECTION_URI_CLOUD;

  if (!trimEnvValue(uri)) {
    throw new Error("MongoDB connection URI is not configured.");
  }

  return trimEnvValue(uri);
};

export const getBackupConfig = () => {
  const localPath = trimEnvValue(process.env.BACKUP_LOCAL_PATH);
  const networkEnabled = parseBooleanEnv(process.env.BACKUP_NETWORK_ENABLED, false);
  const networkPath = trimEnvValue(process.env.BACKUP_NETWORK_PATH);
  const cronSchedule = trimEnvValue(process.env.BACKUP_CRON_SCHEDULE) || "0 2 * * 0";
  const mongoDumpBin = trimEnvValue(process.env.MONGODUMP_BIN) || "mongodump";
  const mongoRestoreBin = trimEnvValue(process.env.MONGORESTORE_BIN) || "mongorestore";

  return {
    localPath,
    networkEnabled,
    networkPath,
    cronSchedule,
    mongoDumpBin,
    mongoRestoreBin,
    mongoUri: getBackupMongoUri(),
  };
};

export const getDisplayPathStatus = (value) => ({
  configured: Boolean(trimEnvValue(value)),
  displayPath: trimEnvValue(value) ? "Configured" : "Not configured",
});

export const ensureLocalBackupPath = async (config = getBackupConfig()) => {
  if (!config.localPath) {
    throw new Error("BACKUP_LOCAL_PATH is not configured.");
  }

  await fs.mkdir(config.localPath, { recursive: true });
  await fs.access(config.localPath);
  return config.localPath;
};

export const resolveConfiguredNetworkPath = (config = getBackupConfig()) => {
  if (!config.networkEnabled) {
    throw new Error("Network backup storage is disabled.");
  }

  if (!config.networkPath) {
    throw new Error("BACKUP_NETWORK_PATH is not configured.");
  }

  return validateCustomNetworkPath(config.networkPath);
};
