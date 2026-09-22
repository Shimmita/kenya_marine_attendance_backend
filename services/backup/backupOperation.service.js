import crypto from "crypto";

const operations = new Map();
let activeOperationId = null;

export const createOperationId = (prefix = "backup") =>
  `${prefix}_${crypto.randomBytes(8).toString("hex")}_${Date.now()}`;

export const getActiveOperation = () =>
  activeOperationId ? operations.get(activeOperationId) : null;

export const getOperation = (operationId) =>
  operations.get(operationId) || null;

export const startLockedOperation = (type, details = {}) => {
  const active = getActiveOperation();
  if (active && ["running", "pending"].includes(active.status)) {
    const err = new Error("Another backup or restore operation is already running.");
    err.statusCode = 409;
    throw err;
  }

  const operation = {
    operationId: createOperationId(type),
    type,
    status: "running",
    phase: details.phase || "Starting",
    message: details.message || "Operation started.",
    details,
    startedAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    completedAt: null,
    result: null,
    error: null,
  };

  operations.set(operation.operationId, operation);
  activeOperationId = operation.operationId;
  return operation;
};

export const updateOperation = (operationId, patch = {}) => {
  const operation = operations.get(operationId);
  if (!operation) return null;

  Object.assign(operation, patch, {
    updatedAt: new Date().toISOString(),
  });

  return operation;
};

export const finishOperation = (operationId, status, patch = {}) => {
  const operation = operations.get(operationId);
  if (!operation) return null;

  Object.assign(operation, patch, {
    status,
    completedAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  });

  if (activeOperationId === operationId) {
    activeOperationId = null;
  }

  return operation;
};

export const operationSnapshot = (operation) => {
  if (!operation) return null;
  return {
    operationId: operation.operationId,
    type: operation.type,
    status: operation.status,
    phase: operation.phase,
    message: operation.message,
    details: operation.details,
    startedAt: operation.startedAt,
    updatedAt: operation.updatedAt,
    completedAt: operation.completedAt,
    result: operation.result,
    error: operation.error,
  };
};
