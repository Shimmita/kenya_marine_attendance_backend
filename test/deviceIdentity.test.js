import assert from "node:assert/strict";
import test from "node:test";
import {
  isValidInstallationId,
  resolveDeviceIdentity,
} from "../util/deviceIdentity.js";
import Devices from "../model/Devices.js";

const oldDevice = {
  _id: "old",
  device_fingerprint: "shared-fingerprint",
  installation_id: "",
};

test("resolves an exact installation before fingerprint matches", () => {
  const installedDevice = {
    _id: "installed",
    device_fingerprint: "shared-fingerprint",
    installation_id: "browser-installation-1234",
  };

  assert.deepEqual(
    resolveDeviceIdentity([oldDevice, installedDevice], {
      installationId: installedDevice.installation_id,
      fingerprint: installedDevice.device_fingerprint,
    }),
    { device: installedDevice, ambiguous: false },
  );
});

test("distinguishes multiple installations with the same account fingerprint", () => {
  const firstInstallation = {
    _id: "first",
    device_fingerprint: "shared-fingerprint",
    installation_id: "browser-installation-1111",
  };
  const secondInstallation = {
    _id: "second",
    device_fingerprint: "shared-fingerprint",
    installation_id: "browser-installation-2222",
  };

  assert.equal(
    resolveDeviceIdentity([firstInstallation, secondInstallation], {
      installationId: secondInstallation.installation_id,
      fingerprint: secondInstallation.device_fingerprint,
    }).device,
    secondInstallation,
  );
});

test("uses a unique legacy fingerprint match during migration", () => {
  assert.deepEqual(
    resolveDeviceIdentity([oldDevice], {
      installationId: "browser-installation-1234",
      fingerprint: "shared-fingerprint",
    }),
    { device: oldDevice, ambiguous: false },
  );
});

test("keeps the legacy fingerprint-only client path when it is unambiguous", () => {
  assert.deepEqual(
    resolveDeviceIdentity([oldDevice], {
      fingerprint: "shared-fingerprint",
    }),
    { device: oldDevice, ambiguous: false },
  );
});

test("does not guess between colliding legacy devices", () => {
  const secondOldDevice = { ...oldDevice, _id: "second" };

  assert.deepEqual(
    resolveDeviceIdentity([oldDevice, secondOldDevice], {
      installationId: "browser-installation-1234",
      fingerprint: "shared-fingerprint",
    }),
    { device: null, ambiguous: true },
  );
});

test("does not claim a legacy record when another colliding device is already bound", () => {
  const boundDevice = {
    _id: "bound",
    device_fingerprint: "shared-fingerprint",
    installation_id: "another-installation-5678",
  };

  assert.deepEqual(
    resolveDeviceIdentity([oldDevice, boundDevice], {
      installationId: "browser-installation-1234",
      fingerprint: "shared-fingerprint",
    }),
    { device: null, ambiguous: true },
  );
});

test("does not treat a fingerprint bound to another installation as an identity match", () => {
  const boundDevice = {
    ...oldDevice,
    installation_id: "other-installation-5678",
  };

  assert.deepEqual(
    resolveDeviceIdentity([boundDevice], {
      installationId: "browser-installation-1234",
      fingerprint: "shared-fingerprint",
    }),
    { device: null, ambiguous: false },
  );
});

test("validates installation IDs without accepting short or malformed values", () => {
  assert.equal(isValidInstallationId("browser_installation-1234"), true);
  assert.equal(isValidInstallationId("short"), false);
  assert.equal(isValidInstallationId("invalid installation id"), false);
});

test("declares account-scoped installation uniqueness and non-unique fingerprints", () => {
  const indexes = Devices.schema.indexes();
  const installationIndex = indexes.find(
    ([keys]) => keys.user_id === 1 && keys.installation_id === 1,
  );
  const fingerprintIndex = indexes.find(
    ([keys]) => Object.keys(keys).length === 1 && keys.device_fingerprint === 1,
  );

  assert.equal(installationIndex?.[1].unique, true);
  assert.deepEqual(installationIndex?.[1].partialFilterExpression, {
    user_id: { $type: "objectId" },
    installation_id: { $type: "string", $gt: "" },
  });
  assert.equal(fingerprintIndex?.[1].unique, undefined);
  assert.equal(Devices.schema.options.autoIndex, false);
});
