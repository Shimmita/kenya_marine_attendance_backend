import fs from "fs/promises";
import path from "path";
import { getBackupConfig, resolveConfiguredNetworkPath, validateCustomNetworkPath } from "./backupConfig.service.js";
import {
  MONTHS,
  metadataPath,
  pathExists,
  readJsonFile,
  sanitizeBackupForResponse,
} from "./backupUtils.service.js";

const monthLookup = new Map(MONTHS.map((month, index) => [month, index + 1]));

const isYearFolder = (name) => /^\d{4}$/.test(name);
const parseWeekFolder = (name) => {
  const match = String(name || "").match(/^week_([1-4])_backup$/);
  return match ? Number(match[1]) : null;
};

const isIgnoredFolder = (name) =>
  name.startsWith(".tmp_") ||
  name.startsWith("_tmp_") ||
  name === "restore_temp" ||
  name === "recovery";

const normalizeMetadataBackup = (metadata, fallback = {}) => {
  if (!metadata || typeof metadata !== "object") return null;
  if (!metadata.backupId || metadata.status !== "completed") return null;

  const year = Number(metadata.year || fallback.year);
  const month = String(metadata.month || fallback.month || "").toLowerCase();
  const monthNumber = Number(metadata.monthNumber || monthLookup.get(month));
  const week = Number(metadata.week || fallback.week);

  if (!year || !monthLookup.has(month) || ![1, 2, 3, 4].includes(week)) {
    return null;
  }

  const createdAt = metadata.createdAt ? new Date(metadata.createdAt) : null;
  if (!createdAt || Number.isNaN(createdAt.getTime())) return null;

  return {
    ...metadata,
    year,
    month,
    monthNumber,
    week,
    snapshotName: fallback.snapshotName,
    createdAt: createdAt.toISOString(),
    completedAt: metadata.completedAt || createdAt.toISOString(),
  };
};

export const readBackupRoot = async (basePath, source = "local") => {
  const backups = [];

  if (!basePath || !(await pathExists(basePath))) {
    return backups;
  }

  const yearEntries = await fs.readdir(basePath, { withFileTypes: true });

  for (const yearEntry of yearEntries) {
    if (!yearEntry.isDirectory() || !isYearFolder(yearEntry.name) || isIgnoredFolder(yearEntry.name)) continue;
    const year = Number(yearEntry.name);
    const yearPath = path.join(basePath, yearEntry.name);
    const monthEntries = await fs.readdir(yearPath, { withFileTypes: true });

    for (const monthEntry of monthEntries) {
      const month = monthEntry.name.toLowerCase();
      if (!monthEntry.isDirectory() || !monthLookup.has(month) || isIgnoredFolder(month)) continue;
      const monthPath = path.join(yearPath, monthEntry.name);
      const weekEntries = await fs.readdir(monthPath, { withFileTypes: true });

      for (const weekEntry of weekEntries) {
        const week = parseWeekFolder(weekEntry.name);
        if (!weekEntry.isDirectory() || !week || isIgnoredFolder(weekEntry.name)) continue;
        const weekPath = path.join(monthPath, weekEntry.name);
        const snapshotEntries = await fs.readdir(weekPath, { withFileTypes: true });

        for (const snapshotEntry of snapshotEntries) {
          if (!snapshotEntry.isDirectory() || isIgnoredFolder(snapshotEntry.name)) continue;
          const snapshotPath = path.join(weekPath, snapshotEntry.name);

          try {
            const metadata = await readJsonFile(metadataPath(snapshotPath));
            const backup = normalizeMetadataBackup(metadata, {
              year,
              month,
              week,
              snapshotName: snapshotEntry.name,
            });

            if (!backup) continue;

            backups.push({
              ...sanitizeBackupForResponse(backup),
              source,
              sources: [source],
              canRestore: true,
            });
          } catch {
            // Ignore incomplete or corrupt snapshots.
          }
        }
      }
    }
  }

  backups.sort((a, b) => {
    if (a.year !== b.year) return b.year - a.year;
    if (a.monthNumber !== b.monthNumber) return b.monthNumber - a.monthNumber;
    if (a.week !== b.week) return b.week - a.week;
    return new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime();
  });

  return backups;
};

export const mergeBackupCopies = (localBackups = [], networkBackups = []) => {
  const map = new Map();

  for (const backup of [...localBackups, ...networkBackups]) {
    const existing = map.get(backup.backupId);
    if (!existing) {
      map.set(backup.backupId, {
        ...backup,
        sources: [...(backup.sources || [backup.source])],
      });
      continue;
    }

    existing.sources = Array.from(new Set([...(existing.sources || []), ...(backup.sources || [backup.source])]));
    existing.copies = {
      ...(existing.copies || {}),
      ...(backup.copies || {}),
    };
  }

  return Array.from(map.values()).sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
};

export const scanLocalBackups = async () => {
  const config = getBackupConfig();
  return readBackupRoot(config.localPath, "local");
};

export const scanConfiguredNetworkBackups = async () => {
  const config = getBackupConfig();
  const networkPath = resolveConfiguredNetworkPath(config);
  return readBackupRoot(networkPath, "network");
};

export const scanCustomNetworkBackups = async (networkPath) => {
  const safePath = validateCustomNetworkPath(networkPath);
  return readBackupRoot(safePath, "network");
};

export const findBackupById = async ({ source, backupId, networkMode = "configured", networkPath = "" }) => {
  const normalizedSource = String(source || "local").toLowerCase();
  let basePath;
  let backups;

  if (normalizedSource === "local") {
    const config = getBackupConfig();
    basePath = config.localPath;
    backups = await scanLocalBackups();
  } else if (networkMode === "custom") {
    basePath = validateCustomNetworkPath(networkPath);
    backups = await readBackupRoot(basePath, "network");
  } else {
    const config = getBackupConfig();
    basePath = resolveConfiguredNetworkPath(config);
    backups = await readBackupRoot(basePath, "network");
  }

  const backup = backups.find((item) => item.backupId === backupId);
  if (!backup) {
    throw new Error("Selected backup could not be found or is not a valid completed snapshot.");
  }

  const snapshotPath = path.join(
    basePath,
    String(backup.year),
    backup.month,
    `week_${backup.week}_backup`,
    backup.snapshotName
  );

  return { backup, snapshotPath, basePath };
};
