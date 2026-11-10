/**
 * Device identity helpers.
 *
 * The browser `device_fingerprint` is a FingerprintJS (open-source) visitorId: a
 * deterministic hash of browser/hardware traits. Two physically different
 * devices of the same model, OS version and browser version can produce the
 * SAME value (very common on iPhones and on bulk-imaged laptops), so the
 * fingerprint alone cannot prove that two enrollments are the same device.
 *
 * `device_install_id` is a random ID generated once per browser install and kept
 * in that browser's storage. Two different accounts signing in on the same
 * browser share it; two different devices never do. Combining both signals lets
 * us keep blocking "second account on the same device" while allowing
 * look-alike devices that merely share a fingerprint.
 */

const DEVICE_INSTALL_ID_PATTERN = /^[A-Za-z0-9_-]{16,128}$/;

/**
 * Returns the trimmed install ID if it is well formed, otherwise "".
 * Old frontends that do not send one simply yield "" (legacy behaviour).
 */
export const normalizeDeviceInstallId = (value) => {
  const installId = String(value ?? "").trim();
  return DEVICE_INSTALL_ID_PATTERN.test(installId) ? installId : "";
};

/**
 * Decide whether device records owned by OTHER accounts that share this
 * fingerprint should block the current enrollment.
 *
 * Rules (first match wins):
 *  1. No other-account records                    → allow, no collision.
 *  2. Client sent no install ID (old frontend)     → block (unchanged legacy rule).
 *  3. Any record has the SAME install ID           → block (same browser install).
 *  4. Any record is marked lost                    → block (lost devices stay blocked;
 *                                                    an admin device reset releases them).
 *  5. Otherwise                                    → allow, but report a collision so
 *                                                    it is audit-logged for admin review.
 *
 * @param {Array<{device_install_id?: string, device_lost?: boolean}>} otherAccountDevices
 * @param {string} deviceInstallId normalized install ID of the current browser ("" if none)
 */
export const evaluateFingerprintConflict = (otherAccountDevices = [], deviceInstallId = "") => {
  const devices = Array.isArray(otherAccountDevices) ? otherAccountDevices : [];

  if (!devices.length) {
    return { blocked: false, collision: false, reason: "none" };
  }

  if (!deviceInstallId) {
    return { blocked: true, collision: false, reason: "legacy_client" };
  }

  if (devices.some((device) => device?.device_install_id && device.device_install_id === deviceInstallId)) {
    return { blocked: true, collision: false, reason: "same_install" };
  }

  if (devices.some((device) => device?.device_lost === true)) {
    return { blocked: true, collision: false, reason: "lost_device" };
  }

  return { blocked: false, collision: true, reason: "fingerprint_collision" };
};
