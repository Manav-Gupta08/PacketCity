import { describe, expect, it } from "vitest";

import { hexDump } from "./format";

describe("hexDump", () => {
  it("prints offset, padded hex and printable ASCII", () => {
    const bytes = [...Array.from("GET / HTTP/1.1\r\n", (c) => c.charCodeAt(0)), 0x00, 0xff];
    const lines = hexDump(bytes).split("\n");
    expect(lines).toHaveLength(2);
    expect(lines[0]).toBe("0000  47 45 54 20 2f 20 48 54 54 50 2f 31 2e 31 0d 0a  GET / HTTP/1.1..");
    expect(lines[1]).toBe(`0010  00 ff${" ".repeat(42)}  ..`);
  });

  it("is empty for no bytes", () => {
    expect(hexDump([])).toBe("");
  });
});
