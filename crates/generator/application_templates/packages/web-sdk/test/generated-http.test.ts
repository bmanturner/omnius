import { describe, expect, it } from "vitest";

import { serviceHttp } from "../src/client/index.js";
import { serviceQueries } from "../src/react/index.js";

describe("generated application HTTP surface", () => {
  it("is empty until the application owns an operation", () => {
    expect(Object.keys(serviceHttp)).toEqual([]);
    expect(Object.keys(serviceQueries)).toEqual([]);
  });
});
