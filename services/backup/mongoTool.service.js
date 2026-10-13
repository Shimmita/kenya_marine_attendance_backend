import { spawn } from "child_process";
import fs from "fs/promises";
import path from "path";

const toolNameFromCommand = (command) =>
  path.basename(command).toLowerCase().includes("mongorestore") ? "mongorestore" : "mongodump";

const windowsExecutableNames = (command, env) => {
  const extension = path.win32.extname(command);
  const extensions = (env.PATHEXT || ".COM;.EXE;.BAT;.CMD")
    .split(";")
    .filter(Boolean);

  return extension ? [command] : extensions.map((item) => `${command}${item.toLowerCase()}`);
};

const windowsMongoInstallRoots = (env) =>
  Array.from(new Set([
    env.ProgramW6432,
    env.ProgramFiles,
    env["ProgramFiles(x86)"],
    "C:\\Program Files",
    "C:\\Program Files (x86)",
  ].filter(Boolean)));

export const getMongoToolCandidates = (command, {
  platform = process.platform,
  env = process.env,
} = {}) => {
  const windows = platform === "win32";
  const pathApi = windows ? path.win32 : path;
  const tool = toolNameFromCommand(command);
  const executableNames = windows ? windowsExecutableNames(command, env) : [command];
  const candidates = [];
  const add = (candidate) => {
    if (candidate && !candidates.includes(candidate)) candidates.push(candidate);
  };

  if (pathApi.isAbsolute(command) || /[\\/]/.test(command)) {
    if (windows && !pathApi.extname(command)) {
      for (const executable of executableNames) add(pathApi.resolve(command + path.win32.extname(executable)));
    } else {
      add(pathApi.resolve(command));
    }
    return candidates;
  }

  const pathEntries = (env.PATH || "").split(windows ? ";" : path.delimiter);
  if (windows && env.Path && env.Path !== env.PATH) {
    pathEntries.push(...env.Path.split(";"));
  }
  for (const directory of pathEntries) {
    if (!directory) continue;
    for (const executable of executableNames) {
      add(pathApi.join(directory.trim().replace(/^["']|["']$/g, ""), executable));
    }
  }

  if (windows) {
    for (const root of windowsMongoInstallRoots(env)) {
      for (const product of ["Tools", "Server"]) {
        const installRoot = path.win32.join(root, "MongoDB", product);
        for (const executable of executableNames) {
          add(path.win32.join(installRoot, "bin", executable));
        }
        add(path.win32.join(installRoot, "bin", tool));
      }
    }
  }

  return candidates;
};

const missingToolError = (command) => {
  const tool = toolNameFromCommand(command);
  const environmentVariable = tool === "mongorestore" ? "MONGORESTORE_BIN" : "MONGODUMP_BIN";
  const error = new Error(
    `MongoDB Database Tools executable "${path.basename(command)}" was not found. Install MongoDB Database Tools on the Windows server and set ${environmentVariable} to the full path of ${tool}.exe (for example, "C:\\Program Files\\MongoDB\\Tools\\100\\bin\\${tool}.exe"), or add its bin folder to the Windows system PATH and restart the backend service.`
  );
  error.code = "ENOENT";
  error.safeMessage = error.message;
  return error;
};

export const resolveMongoToolPath = async (command, options = {}) => {
  const candidates = getMongoToolCandidates(command, options);
  for (const candidate of candidates) {
    try {
      await fs.access(candidate);
      return candidate;
    } catch {
      // Continue checking PATH and the standard MongoDB installation locations.
    }
  }

  if ((options.platform || process.platform) === "win32") {
    const executableNames = windowsExecutableNames(command, options.env || process.env);
    for (const root of windowsMongoInstallRoots(options.env || process.env)) {
      for (const product of ["Tools", "Server"]) {
        const installRoot = path.win32.join(root, "MongoDB", product);
        let versions;
        try {
          versions = await fs.readdir(installRoot, { withFileTypes: true });
        } catch {
          continue;
        }

        versions.sort((a, b) => b.name.localeCompare(a.name, undefined, { numeric: true }));
        for (const version of versions) {
          if (!version.isDirectory()) continue;
          for (const executable of executableNames) {
            const candidate = path.win32.join(installRoot, version.name, "bin", executable);
            try {
              await fs.access(candidate);
              return candidate;
            } catch {
              // Continue checking other installed MongoDB versions.
            }
          }
        }
      }
    }
  }

  throw missingToolError(command);
};

export const runMongoTool = async (command, args, options = {}) => {
  const resolvedCommand = await resolveMongoToolPath(command);

  return new Promise((resolve, reject) => {
    const child = spawn(resolvedCommand, args, {
      windowsHide: true,
      stdio: ["ignore", "pipe", "pipe"],
      ...options,
    });

    let stderr = "";
    child.stderr.on("data", (chunk) => {
      stderr += chunk.toString();
      if (stderr.length > 4000) stderr = stderr.slice(-4000);
    });

    child.once("error", (cause) => {
      if (cause.code === "ENOENT") {
        reject(missingToolError(command));
        return;
      }
      reject(cause);
    });

    child.once("close", (code) => {
      if (code === 0) {
        resolve();
        return;
      }

      const error = new Error(`MongoDB Database Tool exited with code ${code}.`);
      error.diagnostic = stderr;
      reject(error);
    });
  });
};
