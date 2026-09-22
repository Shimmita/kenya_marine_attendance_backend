import { spawn } from "child_process";
import fs from "fs/promises";
import path from "path";
import mongoose from "mongoose";
import {
  ensureLocalBackupPath,
  getBackupConfig,
  getDisplayPathStatus,
  resolveConfiguredNetworkPath,
} from "./backupConfig.service.js";
import { logBackupAudit } from "./backupAudit.service.js";
import {
  buildBackupId,
  buildSnapshotPath,
  copyDirectory,
  directorySize,
  getBackupPeriod,
  hasDumpFiles,
  metadataPath,
  pathExists,
  sanitizeBackupForResponse,
  toSafeTimestamp,
  writeJsonFile,
} from "./backupUtils.service.js";
import { findBackupById, mergeBackupCopies, scanConfiguredNetworkBackups, scanLocalBackups } from "./backupScanner.service.js";
import {
  finishOperation,
  getOperation,
  operationSnapshot,
  startLockedOperation,
  updateOperation,
} from "./backupOperation.service.js";

const runTool = (command, args, options = {}) =>
  new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      windowsHide: true,
      stdio: ["ignore", "pipe", "pipe"],
      ...options,
    });

    let stderr = "";
    child.stderr.on("data", (chunk) => {
      stderr += chunk.toString();
      if (stderr.length > 4000) stderr = stderr.slice(-4000);
    });

    child.on("error", reject);
    child.on("close", (code) => {
      if (code === 0) {
        resolve();
        return;
      }

      const error = new Error(`MongoDB Database Tool exited with code ${code}.`);
      error.diagnostic = stderr;
      reject(error);
    });
  });

const listDumpCollections = async (dumpRoot) => {
  const collections = new Set();

  const walk = async (targetPath) => {
    const entries = await fs.readdir(targetPath, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(targetPath, entry.name);
      if (entry.isDirectory()) {
        await walk(fullPath);
      } else if (entry.isFile() && entry.name.endsWith(".bson")) {
        collections.add(entry.name.replace(/\.bson$/i, ""));
      }
    }
  };

  await walk(dumpRoot);
  return Array.from(collections).sort();
};

const validateSnapshotDirectory = async (snapshotPath) => {
  const dumpPath = path.join(snapshotPath, "dump");
  if (!(await pathExists(dumpPath)) || !(await hasDumpFiles(dumpPath))) {
    throw new Error("MongoDB snapshot validation failed.");
  }
  return dumpPath;
};

const atomicFinalize = async (temporaryPath, finalPath) => {
  if (await pathExists(finalPath)) {
    throw new Error("A backup snapshot with this identifier already exists.");
  }

  await fs.mkdir(path.dirname(finalPath), { recursive: true });
  await fs.rename(temporaryPath, finalPath);
};

const updateLocalMetadataAfterNetworkSync = async (localSnapshotPath, networkCopy) => {
  const metadata = networkCopy.metadata;
  await writeJsonFile(metadataPath(localSnapshotPath), metadata);
};

export const syncBackupToNetwork = async ({ localSnapshotPath, backup, actor = null, req = null }) => {
  const config = getBackupConfig();
  const networkPath = resolveConfiguredNetworkPath(config);
  const finalNetworkPath = buildSnapshotPath(networkPath, backup, backup.snapshotName);
  const temporaryNetworkPath = path.join(path.dirname(finalNetworkPath), `.tmp_${backup.backupId}`);

  await fs.mkdir(path.dirname(finalNetworkPath), { recursive: true });
  await fs.rm(temporaryNetworkPath, { recursive: true, force: true });

  if (await pathExists(finalNetworkPath)) {
    await validateSnapshotDirectory(finalNetworkPath);
    const syncedAt = new Date().toISOString();
    const metadata = {
      ...backup,
      copies: {
        ...(backup.copies || {}),
        network: {
          available: true,
          verified: true,
          status: "completed",
          syncedAt,
        },
      },
    };
    await updateLocalMetadataAfterNetworkSync(localSnapshotPath, { metadata });
    return { available: true, verified: true, status: "completed", syncedAt };
  }

  await copyDirectory(localSnapshotPath, temporaryNetworkPath);
  await validateSnapshotDirectory(temporaryNetworkPath);

  const syncedAt = new Date().toISOString();
  const metadata = {
    ...backup,
    copies: {
      ...(backup.copies || {}),
      network: {
        available: true,
        verified: true,
        status: "completed",
        syncedAt,
      },
    },
  };

  await writeJsonFile(metadataPath(temporaryNetworkPath), metadata);
  await atomicFinalize(temporaryNetworkPath, finalNetworkPath);
  await updateLocalMetadataAfterNetworkSync(localSnapshotPath, { metadata });

  await logBackupAudit({
    req,
    actor,
    action: "NETWORK_BACKUP_SYNCED",
    description: "Network backup copy synchronized.",
    metadata: {
      backupId: backup.backupId,
      year: backup.year,
      month: backup.month,
      week: backup.week,
    },
  });

  return metadata.copies.network;
};

export const createDatabaseBackup = async ({ trigger = "manual", actor = null, req = null } = {}) => {
  const operation = startLockedOperation("backup", {
    phase: "Preparing",
    trigger,
  });

  try {
    const config = getBackupConfig();
    const localPath = await ensureLocalBackupPath(config);
    const createdAt = new Date();
    const period = getBackupPeriod(createdAt);
    const backupId = buildBackupId(createdAt);
    const snapshotName = toSafeTimestamp(createdAt);
    const finalLocalPath = buildSnapshotPath(localPath, period, snapshotName);
    const temporaryLocalPath = path.join(path.dirname(finalLocalPath), `.tmp_${backupId}`);

    updateOperation(operation.operationId, {
      phase: "Creating local snapshot",
      message: "Creating MongoDB backup locally.",
      details: { trigger, backupId },
    });

    await fs.mkdir(path.dirname(finalLocalPath), { recursive: true });
    await fs.rm(temporaryLocalPath, { recursive: true, force: true });
    await fs.mkdir(temporaryLocalPath, { recursive: true });

    const dumpPath = path.join(temporaryLocalPath, "dump");
    await runTool(config.mongoDumpBin, ["--uri", config.mongoUri, "--out", dumpPath]);
    await validateSnapshotDirectory(temporaryLocalPath);

    const collections = await listDumpCollections(dumpPath);
    const backupSize = await directorySize(temporaryLocalPath);
    const completedAt = new Date().toISOString();
    const metadata = {
      backupId,
      snapshotName,
      year: period.year,
      month: period.month,
      monthNumber: period.monthNumber,
      week: period.week,
      createdAt: createdAt.toISOString(),
      completedAt,
      status: "completed",
      trigger,
      collections,
      collectionCount: collections.length,
      backupSize,
      copies: {
        local: {
          available: true,
          verified: true,
          status: "completed",
          completedAt,
        },
        network: {
          available: false,
          verified: false,
          status: config.networkEnabled ? "pending_sync" : "disabled",
          lastAttemptAt: null,
        },
      },
    };

    await writeJsonFile(metadataPath(temporaryLocalPath), metadata);
    await atomicFinalize(temporaryLocalPath, finalLocalPath);

    await logBackupAudit({
      req,
      actor,
      action: trigger === "manual" ? "BACKUP_MANUAL_TRIGGERED" : "BACKUP_CREATED",
      description: trigger === "manual" ? "Manual backup created." : "Scheduled backup created.",
      metadata: {
        backupId,
        year: period.year,
        month: period.month,
        week: period.week,
        trigger,
        operationId: operation.operationId,
      },
    });

    await logBackupAudit({
      req,
      actor,
      action: "LOCAL_BACKUP_CREATED",
      description: "Local backup copy created.",
      metadata: { backupId, year: period.year, month: period.month, week: period.week, trigger },
    });

    let finalMetadata = metadata;

    if (config.networkEnabled) {
      updateOperation(operation.operationId, {
        phase: "Syncing network copy",
        message: "Copying verified local backup to network storage.",
      });

      try {
        const networkCopy = await syncBackupToNetwork({
          localSnapshotPath: finalLocalPath,
          backup: metadata,
          actor,
          req,
        });
        finalMetadata = {
          ...metadata,
          copies: {
            ...metadata.copies,
            network: networkCopy,
          },
        };
      } catch (error) {
        finalMetadata = {
          ...metadata,
          copies: {
            ...metadata.copies,
            network: {
              available: false,
              verified: false,
              status: "pending_sync",
              lastAttemptAt: new Date().toISOString(),
            },
          },
        };
        await writeJsonFile(metadataPath(finalLocalPath), finalMetadata);
        console.error("Network backup synchronization failed:", error?.message || error);
        await logBackupAudit({
          req,
          actor,
          action: "NETWORK_BACKUP_SYNC_FAILED",
          description: "Network backup synchronization failed.",
          status: "failed",
          metadata: { backupId, year: period.year, month: period.month, week: period.week, trigger },
        });
      }
    }

    const result = sanitizeBackupForResponse(finalMetadata);
    finishOperation(operation.operationId, "completed", {
      phase: "Completed",
      message: "Backup completed.",
      result,
    });

    return {
      operation: operationSnapshot(getOperation(operation.operationId)),
      backup: result,
    };
  } catch (error) {
    console.error("Database backup failed:", error?.message || error);
    await logBackupAudit({
      req,
      actor,
      action: "BACKUP_FAILED",
      description: "Database backup failed.",
      status: "failed",
      metadata: { trigger, operationId: operation.operationId },
    });
    finishOperation(operation.operationId, "failed", {
      phase: "Failed",
      message: "Backup failed.",
      error: { message: "Database backup failed. Check server logs for details." },
    });
    throw error;
  }
};

export const retryNetworkSync = async ({ backupId, actor = null, req = null }) => {
  const operation = startLockedOperation("network_sync", {
    phase: "Preparing",
    backupId,
  });

  try {
    const config = getBackupConfig();
    const localBackups = await scanLocalBackups();
    const backup = localBackups.find((item) => item.backupId === backupId);

    if (!backup) {
      throw new Error("Local backup could not be found for retry.");
    }

    const localSnapshotPath = buildSnapshotPath(config.localPath, backup, backup.snapshotName);
    await validateSnapshotDirectory(localSnapshotPath);

    updateOperation(operation.operationId, {
      phase: "Syncing network copy",
      message: "Retrying network backup synchronization.",
    });

    await logBackupAudit({
      req,
      actor,
      action: "NETWORK_BACKUP_SYNC_RETRIED",
      description: "Network backup synchronization retry started.",
      metadata: { backupId, operationId: operation.operationId },
    });

    const networkCopy = await syncBackupToNetwork({
      localSnapshotPath,
      backup,
      actor,
      req,
    });

    const result = {
      ...backup,
      copies: {
        ...(backup.copies || {}),
        network: networkCopy,
      },
    };

    finishOperation(operation.operationId, "completed", {
      phase: "Completed",
      message: "Network synchronization completed.",
      result: sanitizeBackupForResponse(result),
    });

    return {
      operation: operationSnapshot(getOperation(operation.operationId)),
      backup: sanitizeBackupForResponse(result),
    };
  } catch (error) {
    console.error("Network backup retry failed:", error?.message || error);
    await logBackupAudit({
      req,
      actor,
      action: "NETWORK_BACKUP_SYNC_FAILED",
      description: "Network backup synchronization retry failed.",
      status: "failed",
      metadata: { backupId, operationId: operation.operationId },
    });
    finishOperation(operation.operationId, "failed", {
      phase: "Failed",
      message: "Network synchronization failed.",
      error: { message: "Network synchronization failed." },
    });
    throw error;
  }
};

const createPreRestoreSafetyBackup = async ({ actor, req, parentOperationId }) => {
  const config = getBackupConfig();
  const localPath = await ensureLocalBackupPath(config);
  const createdAt = new Date();
  const backupId = `pre_restore_${toSafeTimestamp(createdAt)}`;
  const recoveryRoot = path.join(localPath, "recovery");
  const temporaryPath = path.join(recoveryRoot, `.tmp_${backupId}`);
  const finalPath = path.join(recoveryRoot, backupId);

  await fs.mkdir(recoveryRoot, { recursive: true });
  await fs.rm(temporaryPath, { recursive: true, force: true });
  await fs.mkdir(temporaryPath, { recursive: true });

  await runTool(config.mongoDumpBin, ["--uri", config.mongoUri, "--out", path.join(temporaryPath, "dump")]);
  await validateSnapshotDirectory(temporaryPath);

  const metadata = {
    backupId,
    snapshotName: backupId,
    createdAt: createdAt.toISOString(),
    completedAt: new Date().toISOString(),
    status: "completed",
    trigger: "pre_restore",
    parentOperationId,
    copies: {
      local: { available: true, verified: true, status: "completed" },
      network: { available: false, verified: false, status: config.networkEnabled ? "pending_sync" : "disabled" },
    },
  };

  await writeJsonFile(metadataPath(temporaryPath), metadata);
  await atomicFinalize(temporaryPath, finalPath);

  await logBackupAudit({
    req,
    actor,
    action: "LOCAL_BACKUP_CREATED",
    description: "Pre-restore safety backup created.",
    metadata: { backupId, trigger: "pre_restore", operationId: parentOperationId },
  });

  if (config.networkEnabled) {
    try {
      const networkPath = resolveConfiguredNetworkPath(config);
      const networkRecoveryRoot = path.join(networkPath, "recovery");
      const temporaryNetworkPath = path.join(networkRecoveryRoot, `.tmp_${backupId}`);
      const finalNetworkPath = path.join(networkRecoveryRoot, backupId);

      await fs.mkdir(networkRecoveryRoot, { recursive: true });
      await copyDirectory(finalPath, temporaryNetworkPath);
      await validateSnapshotDirectory(temporaryNetworkPath);
      await atomicFinalize(temporaryNetworkPath, finalNetworkPath);
    } catch (error) {
      console.error("Pre-restore network recovery sync failed:", error?.message || error);
    }
  }

  return { backupId, path: finalPath };
};

export const restoreBackup = async ({ source, backupId, networkMode = "configured", networkPath = "", actor = null, req = null }) => {
  const operation = startLockedOperation("restore", {
    phase: "Preparing restore",
    source,
    backupId,
  });

  let stagedNetworkPath = "";

  try {
    await logBackupAudit({
      req,
      actor,
      action: "BACKUP_RESTORE_STARTED",
      description: "Database restore started.",
      metadata: { source, backupId, networkMode, operationId: operation.operationId },
    });

    updateOperation(operation.operationId, {
      phase: "Validating backup",
      message: "Validating selected backup.",
    });

    const selected = await findBackupById({ source, backupId, networkMode, networkPath });
    let restoreSnapshotPath = selected.snapshotPath;

    if (String(source).toLowerCase() === "network") {
      updateOperation(operation.operationId, {
        phase: "Copying network backup locally",
        message: "Copying selected network backup into local staging.",
      });

      const config = getBackupConfig();
      const localPath = await ensureLocalBackupPath(config);
      stagedNetworkPath = path.join(localPath, "restore_temp", operation.operationId);
      await copyDirectory(selected.snapshotPath, stagedNetworkPath);
      restoreSnapshotPath = stagedNetworkPath;
    }

    await validateSnapshotDirectory(restoreSnapshotPath);

    updateOperation(operation.operationId, {
      phase: "Creating safety backup",
      message: "Creating pre-restore safety backup of the current database.",
    });

    const safetyBackup = await createPreRestoreSafetyBackup({
      actor,
      req,
      parentOperationId: operation.operationId,
    });

    updateOperation(operation.operationId, {
      phase: "Restoring database",
      message: "Restoring MongoDB from selected backup.",
    });

    const config = getBackupConfig();
    await runTool(config.mongoRestoreBin, [
      "--uri",
      config.mongoUri,
      "--drop",
      path.join(restoreSnapshotPath, "dump"),
    ]);

    await mongoose.connection.db.admin().ping();

    const result = {
      source,
      backup: selected.backup,
      safetyBackupId: safetyBackup.backupId,
      restoredAt: new Date().toISOString(),
    };

    await logBackupAudit({
      req,
      actor,
      action: "BACKUP_RESTORE_COMPLETED",
      description: "Database restore completed.",
      metadata: {
        source,
        backupId,
        operationId: operation.operationId,
        safetyBackupId: safetyBackup.backupId,
      },
    });

    finishOperation(operation.operationId, "completed", {
      phase: "Completed",
      message: "Database restored successfully.",
      result,
    });

    return {
      operation: operationSnapshot(getOperation(operation.operationId)),
      ...result,
    };
  } catch (error) {
    console.error("Database restore failed:", error?.message || error);
    await logBackupAudit({
      req,
      actor,
      action: "BACKUP_RESTORE_FAILED",
      description: "Database restore failed.",
      status: "failed",
      metadata: { source, backupId, networkMode, operationId: operation.operationId },
    });
    finishOperation(operation.operationId, "failed", {
      phase: "Failed",
      message: "Database restoration failed.",
      error: { message: "Database restoration failed. The pre-restore safety backup has been preserved if it was created." },
    });
    throw error;
  } finally {
    if (stagedNetworkPath) {
      await fs.rm(stagedNetworkPath, { recursive: true, force: true }).catch(() => {});
    }
  }
};

const checkPathStatus = async (targetPath) => {
  if (!targetPath) return "not_configured";
  try {
    await fs.access(targetPath);
    return "connected";
  } catch {
    return "unavailable";
  }
};

export const getBackupOverview = async () => {
  const config = getBackupConfig();
  const [localBackups, networkBackups] = await Promise.all([
    scanLocalBackups().catch(() => []),
    config.networkEnabled ? scanConfiguredNetworkBackups().catch(() => []) : Promise.resolve([]),
  ]);
  const backups = mergeBackupCopies(localBackups, networkBackups);
  const latest = backups[0] || null;

  return {
    storage: {
      local: {
        ...getDisplayPathStatus(config.localPath),
        status: await checkPathStatus(config.localPath),
      },
      network: {
        enabled: config.networkEnabled,
        ...getDisplayPathStatus(config.networkPath),
        status: config.networkEnabled ? await checkPathStatus(config.networkPath) : "disabled",
      },
    },
    schedule: config.cronSchedule,
    lastSuccessfulBackup: latest?.createdAt || null,
    backups,
  };
};
