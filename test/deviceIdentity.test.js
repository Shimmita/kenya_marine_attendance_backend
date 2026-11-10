import assert from "node:assert/strict";
import test from "node:test";
import {
  evaluateFingerprintConflict,
  normalizeDeviceInstallId,
} from "../util/deviceIdentity.js";

const INSTALL_A = "3f2b8c1e-7d4a-4c9b-9e21-5a6f0d8b7c41";
const INSTALL_B = "a91c4e07-2b5d-4f3e-8c6a-1d9e7b3f5a20";

test("normalizeDeviceInstallId accepts UUIDs and rejects junk", () => {
  assert.equal(normalizeDeviceInstallId(INSTALL_A), INSTALL_A);
  assert.equal(normalizeDeviceInstallId(`  ${INSTALL_A}  `), INSTALL_A);
  assert.equal(normalizeDeviceInstallId(undefined), "");
  assert.equal(normalizeDeviceInstallId(""), "");
  assert.equal(normalizeDeviceInstallId("short"), "");
  assert.equal(normalizeDeviceInstallId("has spaces in the middle of it"), "");
  assert.equal(normalizeDeviceInstallId({ $ne: null }), "");
  assert.equal(normalizeDeviceInstallId("x".repeat(129)), "");
});

test("no other-account devices: allowed, no collision", () => {
  assert.deepEqual(evaluateFingerprintConflict([], INSTALL_A), {
    blocked: false,
    collision: false,
    reason: "none",
  });
  assert.equal(evaluateFingerprintConflict(undefined, "").blocked, false);
});

test("old frontend without install id keeps the legacy block", () => {
  const result = evaluateFingerprintConflict([{ device_install_id: INSTALL_B }], "");
  assert.equal(result.blocked, true);
  assert.equal(result.reason, "legacy_client");
});

test("same browser install on another account is blocked", () => {
  const result = evaluateFingerprintConflict(
    [{ device_install_id: INSTALL_A, device_lost: false }],
    INSTALL_A
  );
  assert.equal(result.blocked, true);
  assert.equal(result.reason, "same_install");
});

test("look-alike device with a different install id is allowed and flagged", () => {
  const result = evaluateFingerprintConflict(
    [{ device_install_id: INSTALL_B, device_lost: false }],
    INSTALL_A
  );
  assert.equal(result.blocked, false);
  assert.equal(result.collision, true);
  assert.equal(result.reason, "fingerprint_collision");
});

test("legacy record (not yet backfilled) is allowed and flagged", () => {
  const result = evaluateFingerprintConflict([{ device_lost: false }], INSTALL_A);
  assert.equal(result.blocked, false);
  assert.equal(result.collision, true);
});

test("another account's lost device stays blocked", () => {
  const result = evaluateFingerprintConflict(
    [{ device_install_id: INSTALL_B, device_lost: true }],
    INSTALL_A
  );
  assert.equal(result.blocked, true);
  assert.equal(result.reason, "lost_device");
});

test("same install wins over other records", () => {
  const result = evaluateFingerprintConflict(
    [{ device_install_id: INSTALL_B }, { device_install_id: INSTALL_A }],
    INSTALL_A
  );
  assert.equal(result.reason, "same_install");
});
