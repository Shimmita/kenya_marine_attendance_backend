import cron from "node-cron";
import { getBackupConfig } from "../services/backup/backupConfig.service.js";
import { createDatabaseBackup } from "../services/backup/backup.service.js";

let backupTask = null;

export const startBackupScheduler = () => {
  const config = getBackupConfig();

  if (backupTask) {
    backupTask.stop();
    if (typeof backupTask.destroy === "function") backupTask.destroy();
    backupTask = null;
  }

  if (!config.localPath) {
    console.error("Backup scheduler not started: BACKUP_LOCAL_PATH is not configured.");
    return null;
  }

  if (!cron.validate(config.cronSchedule)) {
    console.error("Backup scheduler not started: BACKUP_CRON_SCHEDULE is invalid.");
    return null;
  }

  backupTask = cron.createTask(
    config.cronSchedule,
    async () => {
      try {
        await createDatabaseBackup({
          trigger: "cron",
          actor: { name: "SYSTEM", rank: "system" },
        });
      } catch (error) {
        if (error?.statusCode === 409) {
          console.warn("Scheduled database backup skipped because another backup/restore operation is running.");
          return;
        }
        console.error("Scheduled database backup failed:", error?.message || error);
      }
    },
    { timezone: "Africa/Nairobi" }
  );

  backupTask.start();
  console.log("Database Backup Scheduler Started:", config.cronSchedule);
  return backupTask;
};

export default startBackupScheduler;
