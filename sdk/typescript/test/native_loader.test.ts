// The native loader's decisions that no single machine reaches: which artifacts a
// platform tries and in what order, the target stamp, and the failure chain.
import { createRequire } from "node:module";
import { describe, expect, it } from "vitest";

const load = createRequire(import.meta.url);
const { selectTargets } = load("../native/loader/targets.js");
const { stampBindingTarget } = load("../native/loader/stamp.js");
const { loadBinding } = load("../native/loader/index.js");

const probes = (over: { musl?: boolean; config?: unknown } = {}) => ({
  isMusl: () => over.musl ?? false,
  config: over.config,
});

describe("selectTargets", () => {
  it("tries the universal macOS artifact before the architecture's own", () => {
    expect(selectTargets("darwin", "arm64", probes()).suffixes).toEqual(["darwin-universal", "darwin-arm64"]);
  });

  it("chooses the Linux libc variant from the probe", () => {
    expect(selectTargets("linux", "x64", probes({ musl: true })).suffixes).toEqual(["linux-x64-musl"]);
    expect(selectTargets("linux", "arm", probes()).suffixes).toEqual(["linux-arm-gnueabihf"]);
  });

  it("chooses the Windows ABI from the Node build", () => {
    const mingw = { variables: { shlib_suffix: "dll.a" } };
    expect(selectTargets("win32", "x64", probes({ config: mingw })).suffixes).toEqual(["win32-x64-gnu"]);
    expect(selectTargets("win32", "x64", probes()).suffixes).toEqual(["win32-x64-msvc"]);
  });

  it("names an unsupported architecture or operating system", () => {
    expect(selectTargets("linux", "mips", probes()).unsupported).toBe("Unsupported architecture on Linux: mips");
    expect(selectTargets("sunos", "x64", probes()).unsupported).toBe("Unsupported OS: sunos, architecture: x64");
  });
});

describe("stampBindingTarget", () => {
  it("defines the target once and accepts the same value again", () => {
    const binding = {};
    expect(stampBindingTarget(binding, "native")).toBe("native");
    expect(stampBindingTarget(binding, "native")).toBe("native");
    expect(Object.getOwnPropertyDescriptor(binding, "__napiBindingTarget")?.value).toBe("native");
  });

  it("refuses an export that claims the reserved name with another value", () => {
    expect(() => stampBindingTarget({ __napiBindingTarget: "x" }, "native")).toThrow(
      expect.objectContaining({ code: "ERR_NAPI_BINDING_TARGET_CONFLICT" }),
    );
  });

  it("skips a frozen binding instead of failing the load", () => {
    const binding = Object.freeze({});
    expect(stampBindingTarget(binding, "native")).toBe("native");
    expect(Object.hasOwn(binding, "__napiBindingTarget")).toBe(false);
  });
});

describe("loadBinding", () => {
  const config = (require: unknown) => ({ require, binaryName: "pkg-core", packageName: "@scope/pkg", version: "1.0.0" });
  const missing = (spec: string) => Object.assign(new Error(`Cannot find module '${spec}'`), { code: "MODULE_NOT_FOUND" });
  const nothingResolves = () =>
    Object.assign((spec: string) => { throw missing(spec); }, { resolve: (spec: string) => { throw missing(spec); } });

  it("chains every failure under one not-found error", () => {
    const run = () => loadBinding(config(nothingResolves()));
    expect(run).toThrow(/Cannot find native binding/);
    try {
      run();
    } catch (error) {
      expect((error as Error & { cause: Error }).cause.message).toContain("wasm32-wasi");
    }
  });

  it("loads the override named by NAPI_RS_NATIVE_LIBRARY_PATH and reports it as native", () => {
    const addon = { loaded: true };
    const require = Object.assign((spec: string) => (spec === "/override.node" ? addon : nothingResolves()(spec)), {
      resolve: nothingResolves().resolve,
    });
    process.env.NAPI_RS_NATIVE_LIBRARY_PATH = "/override.node";
    try {
      expect(loadBinding(config(require))).toEqual({ binding: addon, target: "native" });
    } finally {
      delete process.env.NAPI_RS_NATIVE_LIBRARY_PATH;
    }
  });
});
