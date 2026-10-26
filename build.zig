const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Shared library: libsecrets_injector.so
    const lib = b.addSharedLibrary(.{
        .name = "secrets_injector",
        .root_source_file = b.path("src/injector.zig"),
        .target = target,
        .optimize = optimize,
    });
    lib.linkLibC();
    lib.linkSystemLibrary("curl");
    b.installArtifact(lib);

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
