import assert from "node:assert/strict";
import test from "node:test";
import { parseMobileEventAt } from "../util/mobileEventTime.js";

const now = new Date("2026-10-07T14:00:00.000Z");

test("accepts valid event timestamps older than 24 hours without changing them", () => {
  const eventAt = "2026-10-01T07:15:00.000Z";

  assert.equal(parseMobileEventAt(eventAt, now)?.toISOString(), eventAt);
});

test("accepts events within 24 hours", () => {
  assert.equal(
    parseMobileEventAt("2026-10-07T13:30:00.000Z", now)?.toISOString(),
    "2026-10-07T13:30:00.000Z",
  );
});

test("rejects invalid and future event timestamps", () => {
  assert.equal(parseMobileEventAt("not-a-timestamp", now), null);
  assert.equal(parseMobileEventAt("", now), null);
  assert.equal(parseMobileEventAt(undefined, now), null);
  assert.equal(
    parseMobileEventAt("2026-10-07T14:05:00.001Z", now),
    null,
  );
});

test("accepts a small device clock skew and preserves the submitted timestamp", () => {
  const eventAt = "2026-10-07T14:04:59.999Z";

  assert.equal(parseMobileEventAt(eventAt, now)?.toISOString(), eventAt);
});
