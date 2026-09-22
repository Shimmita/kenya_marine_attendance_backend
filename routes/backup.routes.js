import express from "express";
import {
  createDatabaseBackup,
  getBackupOverview,
  restoreBackup,
  retryNetworkSync,
} from "../services/backup/backup.service.js";
import { logBackupAudit } from "../services/backup/backupAudit.service.js";
import {
  scanConfiguredNetworkBackups,
  scanCustomNetworkBackups,
  scanLocalBackups,
} from "../services/backup/backupScanner.service.js";
import { operationSnapshot, getOperation } from "../services/backup/backupOperation.service.js";

const safeResponseError = (error, fallback = "Backup request failed.") => ({
  message: error?.statusCode === 409 ? error.message : fallback,
});

export const createBackupRouter = ({ ensureSuperadmin }) => {
  const router = express.Router();

  router.use(async (req, res, next) => {
    try {
      const auth = await ensureSuperadmin(req, res);
      if (!auth || auth.allowed !== true) return;
      req.currentUser = auth.currentUser;
      next();
    } catch (error) {
      next(error);
    }
  });

  router.get("/", async (req, res) => {
    try {
      const overview = await getBackupOverview();
      return res.status(200).json(overview);
    } catch (error) {
      console.error("Backup overview error:", error?.message || error);
      return res.status(500).json({ message: "Failed to load backup overview." });
    }
  });

  router.get("/local", async (req, res) => {
    try {
      const backups = await scanLocalBackups();
      return res.status(200).json({ backups });
    } catch (error) {
      console.error("Local backup scan error:", error?.message || error);
      return res.status(500).json({ message: "Failed to read local backups." });
    }
  });

  router.get("/network", async (req, res) => {
    try {
      const backups = await scanConfiguredNetworkBackups();
      await logBackupAudit({
        req,
        actor: req.currentUser,
        action: "BACKUP_NETWORK_CONNECTED",
        description: "Configured network backup location read successfully.",
        metadata: { count: backups.length },
      });
      return res.status(200).json({ backups, count: backups.length });
    } catch (error) {
      console.error("Configured network backup scan error:", error?.message || error);
      await logBackupAudit({
        req,
        actor: req.currentUser,
        action: "BACKUP_NETWORK_CONNECTION_FAILED",
        description: "Configured network backup location could not be read.",
        status: "failed",
      });
      return res.status(503).json({
        message: "Unable to access network backup location. Check that the backup computer is online and the service account has permission.",
      });
    }
  });

  router.post("/network/read", async (req, res) => {
    try {
      const { networkPath } = req.body || {};
      const backups = await scanCustomNetworkBackups(networkPath);
      await logBackupAudit({
        req,
        actor: req.currentUser,
        action: "BACKUP_NETWORK_CONNECTED",
        description: "Custom network backup location read successfully.",
        metadata: { count: backups.length, mode: "custom" },
      });
      return res.status(200).json({ backups, count: backups.length });
    } catch (error) {
      console.error("Custom network backup scan error:", error?.message || error);
      await logBackupAudit({
        req,
        actor: req.currentUser,
        action: "BACKUP_NETWORK_CONNECTION_FAILED",
        description: "Custom network backup location could not be read.",
        status: "failed",
        metadata: { mode: "custom" },
      });
      return res.status(400).json({
        message: "Unable to access network backup location. Check the UNC path, network availability, and share permissions.",
      });
    }
  });

  router.post("/manual", async (req, res) => {
    try {
      const result = await createDatabaseBackup({
        trigger: "manual",
        actor: req.currentUser,
        req,
      });
      return res.status(201).json(result);
    } catch (error) {
      const status = error?.statusCode || 500;
      return res.status(status).json(safeResponseError(error, "Manual backup failed. Check server logs for details."));
    }
  });

  router.post("/network/retry-sync", async (req, res) => {
    try {
      const { backupId } = req.body || {};
      if (!backupId) {
        return res.status(400).json({ message: "Backup identifier is required." });
      }

      const result = await retryNetworkSync({
        backupId,
        actor: req.currentUser,
        req,
      });
      return res.status(200).json(result);
    } catch (error) {
      const status = error?.statusCode || 500;
      return res.status(status).json(safeResponseError(error, "Network synchronization failed."));
    }
  });

  router.post("/restore", async (req, res) => {
    try {
      const { source, backupId, networkMode = "configured", networkPath = "" } = req.body || {};
      if (!["local", "network"].includes(String(source || "").toLowerCase())) {
        return res.status(400).json({ message: "Restore source must be local or network." });
      }
      if (!backupId) {
        return res.status(400).json({ message: "Backup identifier is required." });
      }

      const result = await restoreBackup({
        source: String(source).toLowerCase(),
        backupId,
        networkMode,
        networkPath,
        actor: req.currentUser,
        req,
      });
      return res.status(200).json(result);
    } catch (error) {
      const status = error?.statusCode || 500;
      return res.status(status).json(safeResponseError(error, "Database restoration failed. The pre-restore safety backup has been preserved if it was created."));
    }
  });

  router.get("/operations/:operationId", async (req, res) => {
    const operation = getOperation(req.params.operationId);
    if (!operation) {
      return res.status(404).json({ message: "Operation not found." });
    }
    return res.status(200).json(operationSnapshot(operation));
  });

  return router;
};

export default createBackupRouter;
