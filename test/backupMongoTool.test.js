import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  getMongoToolCandidates,
  runMongoTool,
} from "../services/backup/mongoTool.service.js";
import { hasDumpFiles } from "../services/backup/backupUtils.service.js";

test("resolves Windows MongoDB tools from service PATH and standard install roots", () => {
  const candidates = getMongoToolCandidates("mongodump", {
    platform: "win32",
    env: {
      PATH: "C:\\service-tools",
      ProgramFiles: "C:\\Program Files",
      PATHEXT: ".EXE;.CMD",
    },
  });

  assert.ok(candidates.includes("C:\\service-tools\\mongodump.exe"));
  assert.ok(candidates.includes("C:\\Program Files\\MongoDB\\Tools\\bin\\mongodump.exe"));
  assert.ok(candidates.includes("C:\\Program Files\\MongoDB\\Server\\bin\\mongodump.exe"));
});

test("runs a configured dump executable and creates a valid dump file", async () => {
  const temporaryDirectory = await fs.mkdtemp(path.join(os.tmpdir(), "backup-tool-test-"));
  const dumpPath = path.join(temporaryDirectory, "dump");
  const mockDump = `
    const fs = require("node:fs");
    const path = require("node:path");
    const output = process.argv[process.argv.indexOf("--out") + 1];
    const database = path.join(output, "test-database");
    fs.mkdirSync(database, { recursive: true });
    fs.writeFileSync(path.join(database, "collection.bson"), Buffer.from([1, 2, 3]));
  `;

  try {
    await runMongoTool(process.execPath, ["-e", mockDump, "--", "--uri", "mongodb://test", "--out", dumpPath]);
    assert.equal(await hasDumpFiles(dumpPath), true);
  } finally {
    await fs.rm(temporaryDirectory, { recursive: true, force: true });
  }
});

test("reports how to fix a missing MongoDB dump executable", async () => {
  await assert.rejects(
    runMongoTool("missing-mongodump-for-backup-test", []),
    (error) => {
      assert.equal(error.code, "ENOENT");
      assert.match(error.message, /Install MongoDB Database Tools/);
      assert.match(error.message, /MONGODUMP_BIN/);
      assert.match(error.message, /Windows server/);
      assert.equal(error.safeMessage, error.message);
      return true;
    }
  );
});

test("reports the restore-specific configuration for a missing restore executable", async () => {
  await assert.rejects(
    runMongoTool("missing-mongorestore-for-backup-test", []),
    (error) => {
      assert.match(error.message, /MONGORESTORE_BIN/);
      return true;
    }
  );
});
