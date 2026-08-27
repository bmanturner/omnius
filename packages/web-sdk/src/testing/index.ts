export interface ValueRecorder<TValue> {
  record(value: TValue): void;
  snapshot(): readonly TValue[];
  clear(): void;
}

/** Creates an isolated recorder whose snapshots cannot mutate the captured sequence. */
export function createValueRecorder<TValue>(): ValueRecorder<TValue> {
  const values: TValue[] = [];
  return Object.freeze({
    record(value: TValue): void {
      values.push(value);
    },
    snapshot(): readonly TValue[] {
      return Object.freeze(values.slice());
    },
    clear(): void {
      values.length = 0;
    },
  });
}
