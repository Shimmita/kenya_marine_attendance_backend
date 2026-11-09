export const resolveDeviceIdentity = (
  devices,
  { installationId = "", fingerprint = "" } = {},
) => {
  const withInstallationId = installationId
    ? devices.filter((device) => device.installation_id === installationId)
    : [];

  if (withInstallationId.length === 1) {
    return { device: withInstallationId[0], ambiguous: false };
  }
  if (withInstallationId.length > 1) {
    return { device: null, ambiguous: true };
  }

  if (!fingerprint) {
    return { device: null, ambiguous: false };
  }

  const fingerprintMatches = devices.filter(
    (device) => device.device_fingerprint === fingerprint,
  );
  const legacyMatches = fingerprintMatches.filter((device) => !device.installation_id);

  if (!installationId && fingerprintMatches.length === 1) {
    return { device: fingerprintMatches[0], ambiguous: false };
  }
  if (
    installationId &&
    fingerprintMatches.length === 1 &&
    legacyMatches.length === 1
  ) {
    return { device: legacyMatches[0], ambiguous: false };
  }

  return {
    device: null,
    ambiguous: installationId
      ? legacyMatches.length > 0
      : fingerprintMatches.length > 1,
  };
};

export const isValidInstallationId = (value) =>
  typeof value === "string" &&
  value.length >= 16 &&
  value.length <= 128 &&
  /^[a-zA-Z0-9_-]+$/.test(value);
