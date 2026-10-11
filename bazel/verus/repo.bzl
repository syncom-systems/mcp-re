"""The pinned Verus install as a repository, read from the toolchain lock.

`verification/policy/toolchains.lock.toml` is the one statement of which Verus release is
pinned and where it is installed; this reads the host's `install_root` (`[verus]` on macOS arm64, `[verus_linux_x86_64]` on Linux x86-64) from it rather than
restating the path. The install lives outside the workspace on the hosts that run the
Verus lane, so the repository links its files in, and every one of them is an input to
the actions that use it — a different prover is a different action.

A host without the install gets a repository that says so: `verus_verify` refuses at
analysis with the path it looked for, rather than failing on a missing file.
"""

def _pin_table(rctx):
    """The lock table pinning the prover for this host, mirroring `verify-verus` HOST_PINS."""
    os_name = rctx.os.name.lower()
    arch = rctx.os.arch.lower()
    if os_name.startswith("mac") and arch in ("aarch64", "arm64"):
        return "[verus]"
    if os_name.startswith("linux") and arch in ("amd64", "x86_64"):
        return "[verus_linux_x86_64]"
    return None

def _install_root(lock_text, table):
    in_verus = False
    for line in lock_text.splitlines():
        stripped = line.strip()
        if stripped.startswith("["):
            in_verus = stripped == table
            continue
        if in_verus and stripped.startswith("install_root"):
            return stripped.split("=", 1)[1].strip().strip('"')
    return None

def _verus_install_impl(rctx):
    table = _pin_table(rctx)
    if table == None:
        rctx.file("UNAVAILABLE", "the lock pins no Verus build for {} {}\n".format(rctx.os.name, rctx.os.arch))
        rctx.file("BUILD.bazel", 'filegroup(name = "files", srcs = ["UNAVAILABLE"], visibility = ["//visibility:public"])\n')
        return
    root = _install_root(rctx.read(rctx.attr.lock), table)
    if root == None:
        fail("{}: {} names no install_root".format(rctx.attr.lock, table))
    install = rctx.path(root)
    if not install.exists or not install.get_child("rust_verify").exists:
        rctx.file("UNAVAILABLE", "the pinned Verus release is not installed at {}\n".format(root))
        rctx.file("BUILD.bazel", 'filegroup(name = "files", srcs = ["UNAVAILABLE"], visibility = ["//visibility:public"])\n')
        return
    for entry in install.readdir():
        rctx.symlink(entry, entry.basename)
    rctx.file("BUILD.bazel", """filegroup(
    name = "files",
    srcs = glob(["**"], exclude = ["BUILD.bazel", "WORKSPACE", "REPO.bazel"]),
    visibility = ["//visibility:public"],
)
""")

verus_install = repository_rule(
    implementation = _verus_install_impl,
    attrs = {"lock": attr.label(allow_single_file = True, mandatory = True)},
    local = True,
    doc = "Links the Verus release `toolchains.lock.toml` pins into a repository.",
)
