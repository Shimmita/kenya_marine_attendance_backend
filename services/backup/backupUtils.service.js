import fs from "fs/promises";
import path from "path";

export const MONTHS = [
  "january",
  "february",
  "march",
  "april",
  "may",
  "june",
  "july",
  "august",
  "september",
  "october",
  "november",
  "december",
];

export const getWeekNumber = (date = new Date()) => {
  const day = date.getDate();
  if (day <= 7) return 1;
  if (day <= 14) return 2;
  if (day <= 21) return 3;
  return 4;
};

export const getBackupPeriod = (date = new Date()) => {
  const year = date.getFullYear();
  const monthNumber = date.getMonth() + 1;
  const month = MONTHS[date.getMonth()];
  const week = getWeekNumber(date);

  return {
    year,
    month,
    monthNumber,
    week,
    weekFolder: `week_${week}_backup`,
  };
};

export const toSafeTimestamp = (date = new Date()) =>
  date.toISOString().replace(/[-:]/g, "").replace(/\.\d{3}Z$/, "Z");

export const buildBackupId = (date = new Date()) => {
  const period = getBackupPeriod(date);
  return `${period.year}-${String(period.monthNumber).padStart(2, "0")}-W${period.week}-${toSafeTimestamp(date)}`;
};

export const buildSnapshotPath = (basePath, period, snapshotName) =>
  path.join(
    basePath,
    String(period.year),
    period.month,
    period.weekFolder || `week_${period.week}_backup`,
    snapshotName
  );

export const metadataFileName = "backup-metadata.json";

export const metadataPath = (snapshotPath) =>
  path.join(snapshotPath, metadataFileName);

export const readJsonFile = async (filePath) => {
  const raw = await fs.readFile(filePath, "utf8");
  return JSON.parse(raw);
};

export const writeJsonFile = async (filePath, value) => {
  await fs.writeFile(filePath, JSON.stringify(value, null, 2), "utf8");
};

export const pathExists = async (targetPath) => {
  try {
    await fs.access(targetPath);
    return true;
  } catch {
    return false;
  }
};

export const directorySize = async (targetPath) => {
  let total = 0;

  const entries = await fs.readdir(targetPath, { withFileTypes: true });
  for (const entry of entries) {
    const fullPath = path.join(targetPath, entry.name);
    if (entry.isDirectory()) {
      total += await directorySize(fullPath);
    } else if (entry.isFile()) {
      const stat = await fs.stat(fullPath);
      total += stat.size;
    }
  }

  return total;
};

export const hasDumpFiles = async (targetPath) => {
  const entries = await fs.readdir(targetPath, { withFileTypes: true });

  for (const entry of entries) {
    const fullPath = path.join(targetPath, entry.name);
    if (entry.isFile() && /\.(bson|json)$/i.test(entry.name)) return true;
    if (entry.isDirectory() && await hasDumpFiles(fullPath)) return true;
  }

  return false;
};

export const copyDirectory = async (source, destination) => {
  await fs.rm(destination, { recursive: true, force: true });
  await fs.cp(source, destination, {
    recursive: true,
    errorOnExist: true,
    force: false,
  });
};

export const sanitizeBackupForResponse = (backup = {}) => ({
  backupId: backup.backupId,
  snapshotName: backup.snapshotName,
  year: backup.year,
  month: backup.month,
  monthNumber: backup.monthNumber,
  week: backup.week,
  createdAt: backup.createdAt,
  completedAt: backup.completedAt,
  status: backup.status,
  trigger: backup.trigger,
  backupSize: backup.backupSize || 0,
  collectionCount: backup.collectionCount || 0,
  collections: Array.isArray(backup.collections) ? backup.collections : [],
  copies: backup.copies || {},
});

export const buildSafeError = (error, fallback = "Backup operation failed.") => ({
  message: error?.safeMessage || error?.message || fallback,
});
