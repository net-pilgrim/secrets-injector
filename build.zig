const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // 1. Default / Host shared library
    const lib = b.addSharedLibrary(.{
        .name = "secrets_injector",
        .root_source_file = b.path("src/injector.zig"),
        .target = target,
        .optimize = optimize,
    });
    lib.linkLibC();
    b.installArtifact(lib);

    // 2. Glibc shared library
    const gnu_target = b.resolveTargetQuery(.{
        .cpu_arch = target.result.cpu.arch,
        .os_tag = .linux,
        .abi = .gnu,
    });
    const lib_gnu = b.addSharedLibrary(.{
        .name = "secrets_injector_glibc",
        .root_source_file = b.path("src/injector.zig"),
        .target = gnu_target,
        .optimize = optimize,
    });
    lib_gnu.linkLibC();
    b.installArtifact(lib_gnu);

    // 3. Musl shared library (for Alpine Linux)
    const musl_target = b.resolveTargetQuery(.{
        .cpu_arch = target.result.cpu.arch,
        .os_tag = .linux,
        .abi = .musl,
    });
    const lib_musl = b.addSharedLibrary(.{
        .name = "secrets_injector_musl",
        .root_source_file = b.path("src/injector.zig"),
        .target = musl_target,
        .optimize = optimize,
    });
    lib_musl.linkLibC();
    b.installArtifact(lib_musl);

    // Test application: test_app
    const test_app = b.addExecutable(.{
        .name = "test_app",
        .target = target,
        .optimize = optimize,
    });
    test_app.addCSourceFile(.{
        .file = b.path("test/test_app.c"),
        .flags = &.{"-Wall", "-Wextra"},
    });
    test_app.linkLibC();
    b.installArtifact(test_app);

    // Unit tests: zig build test
    const unit_tests = b.addTest(.{
        .root_source_file = b.path("src/json_parser.zig"),
        .target = target,
        .optimize = optimize,
    });
    const run_unit_tests = b.addRunArtifact(unit_tests);
    const test_step = b.step("test-unit", "Run unit tests");
    test_step.dependOn(&run_unit_tests.step);
}
