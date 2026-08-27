import { describe, expect, it } from "vitest";

import { satisfiesPermissionRequirement } from "../src/authorization/index.js";
import { getCapabilityAvailability } from "../src/capabilities/index.js";
import { createValueRecorder } from "../src/testing/index.js";
import { calculateUploadProgress } from "../src/uploads/index.js";


describe("framework-neutral primitives", () => {
  it("requires every allOf permission and one non-empty anyOf permission", () => {
    const granted = new Set(["records.read", "records.write"]);
    expect(
      satisfiesPermissionRequirement(granted, {
        allOf: ["records.read"],
        anyOf: ["records.write", "records.admin"],
      }),
    ).toBe(true);
    expect(
      satisfiesPermissionRequirement(granted, {
        allOf: ["records.read", "records.delete"],
      }),
    ).toBe(false);
  });

  it("distinguishes build-time and runtime capability absence", () => {
    expect(getCapabilityAvailability({ compiled: false, runtimeAvailable: false })).toBe(
      "not-compiled",
    );
    expect(getCapabilityAvailability({ compiled: true, runtimeAvailable: false })).toBe(
      "runtime-unavailable",
    );
    expect(getCapabilityAvailability({ compiled: true, runtimeAvailable: true })).toBe("available");
  });

  it("validates upload progress boundaries", () => {
    expect(calculateUploadProgress(3, 4)).toEqual({
      bytesTransferred: 3,
      totalBytes: 4,
      fraction: 0.75,
    });
    expect(calculateUploadProgress(0, 0).fraction).toBe(1);
    expect(() => calculateUploadProgress(5, 4)).toThrow(RangeError);
  });

  it("returns immutable recorder snapshots and clears future snapshots", () => {
    const recorder = createValueRecorder<number>();
    recorder.record(1);
    const snapshot = recorder.snapshot();
    expect(snapshot).toEqual([1]);
    expect(Object.isFrozen(snapshot)).toBe(true);
    recorder.clear();
    expect(snapshot).toEqual([1]);
    expect(recorder.snapshot()).toEqual([]);
  });
});
