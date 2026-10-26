const std = @import("std");
const json_parser = @import("json_parser.zig");
const vault_client = @import("vault_client.zig");

const c = @cImport({
    @cDefine("_GNU_SOURCE", "1");
    @cInclude("dlfcn.h");
    @cInclude("stdlib.h");
    @cInclude("string.h");
    @cInclude("unistd.h");
});

const GetEnvFn = *const fn (?[*:0]const u8) callconv(.C) ?[*:0]u8;

var real_getenv_ptr: ?GetEnvFn = null;
var real_secure_getenv_ptr: ?GetEnvFn = null;

threadlocal var in_fetch: bool = false;
threadlocal var resolving_real: bool = false;

var secrets_map: json_parser.SecretsMap = undefined;
var secrets_initialized: bool = false;
var scrub_fetch_key: bool = true;
var debug_mode: bool = false;

var init_once = std.once(doInit);

// Constructor placed in .init_array to run before main()
pub export const init_fn_ptr: *const fn () callconv(.C) void linksection(".init_array") = &init;

fn init() callconv(.C) void {
    init_once.call();
}

fn fallbackGetenv(name: [*:0]const u8) ?[*:0]u8 {
    const env_ptr = c.environ orelse return null;
    const name_slice = std.mem.span(name);

    var idx: usize = 0;
    while (env_ptr[idx]) |entry| : (idx += 1) {
        const entry_slice = std.mem.span(entry);
        if (entry_slice.len > name_slice.len and entry_slice[name_slice.len] == '=') {
            if (std.mem.eql(u8, entry_slice[0..name_slice.len], name_slice)) {
                return @ptrCast(&entry[name_slice.len + 1]);
            }
        }
    }
    return null;
}

fn callRealGetenv(name: ?[*:0]const u8) ?[*:0]u8 {
    const n = name orelse return null;
    if (resolving_real) {
        return fallbackGetenv(n);
    }

    if (real_getenv_ptr == null) {
        resolving_real = true;
        defer resolving_real = false;
        if (c.dlsym(c.RTLD_NEXT, "getenv")) |sym| {
            real_getenv_ptr = @ptrCast(sym);
        }
    }

    if (real_getenv_ptr) |real_fn| {
        return real_fn(n);
    }
    return fallbackGetenv(n);
}

fn callRealSecureGetenv(name: ?[*:0]const u8) ?[*:0]u8 {
    const n = name orelse return null;
    if (resolving_real) {
        return fallbackGetenv(n);
    }

    if (real_secure_getenv_ptr == null) {
        resolving_real = true;
        defer resolving_real = false;
        if (c.dlsym(c.RTLD_NEXT, "secure_getenv")) |sym| {
            real_secure_getenv_ptr = @ptrCast(sym);
        } else if (c.dlsym(c.RTLD_NEXT, "getenv")) |sym| {
            real_secure_getenv_ptr = @ptrCast(sym);
        }
    }

    if (real_secure_getenv_ptr) |real_fn| {
        return real_fn(n);
    }
    return fallbackGetenv(n);
}

fn doInit() void {
    in_fetch = true;
    defer in_fetch = false;

    // Allocate map using C allocator for long-lived static storage
    secrets_map = json_parser.SecretsMap.init(std.heap.c_allocator);

    // Read debug setting
    if (callRealGetenv("SECRETS_INJECTOR_DEBUG")) |val| {
        const s = std.mem.span(val);
        if (std.mem.eql(u8, s, "1") or std.ascii.eqlIgnoreCase(s, "true")) {
            debug_mode = true;
        }
    }

    if (debug_mode) {
        std.debug.print("[secrets_injector_zig] Initializing secrets injector...\n", .{});
    }

    // Read scrub setting
    if (callRealGetenv("SECRETS_INJECTOR_SCRUB")) |val| {
        const s = std.mem.span(val);
        if (std.mem.eql(u8, s, "0") or std.ascii.eqlIgnoreCase(s, "false")) {
            scrub_fetch_key = false;
        }
    }

    // Read SECRETS_FETCH_KEY
    const fetch_key_ptr = callRealGetenv("SECRETS_FETCH_KEY");
    if (fetch_key_ptr == null or std.mem.span(fetch_key_ptr.?).len == 0) {
        if (debug_mode) {
            std.debug.print("[secrets_injector_zig] SECRETS_FETCH_KEY not set; skipping vault fetch\n", .{});
        }
        secrets_initialized = true;
        return;
    }
    const fetch_key = std.mem.span(fetch_key_ptr.?);

    // Read SECRETS_VAULT_URL
    const vault_url: [:0]const u8 = if (callRealGetenv("SECRETS_VAULT_URL")) |v|
        std.mem.span(v)
    else
        "http://127.0.0.1:8080/secrets";

    // Read timeout
    var timeout: c_long = 5;
    if (callRealGetenv("SECRETS_VAULT_TIMEOUT")) |to_ptr| {
        if (std.fmt.parseInt(c_long, std.mem.span(to_ptr), 10) catch null) |t| {
            if (t > 0) timeout = t;
        }
    }

    // Read insecure ssl flag
    var insecure = false;
    if (callRealGetenv("SECRETS_VAULT_INSECURE")) |insec_ptr| {
        const s = std.mem.span(insec_ptr);
        if (std.mem.eql(u8, s, "1") or std.ascii.eqlIgnoreCase(s, "true")) {
            insecure = true;
        }
    }

    // Read custom auth header if any
    const auth_hdr: ?[:0]const u8 = if (callRealGetenv("SECRETS_AUTH_HEADER")) |ah|
        std.mem.span(ah)
    else
        null;

    const cfg = vault_client.VaultConfig{
        .url = vault_url,
        .fetch_key = fetch_key,
        .auth_header = auth_hdr,
        .timeout_seconds = timeout,
        .insecure_ssl = insecure,
        .debug = debug_mode,
    };

    if (vault_client.fetchSecrets(std.heap.c_allocator, cfg, &secrets_map)) |count| {
        // Populate setenv for runtimes snapshotting environ (Python, Node, Go, Rust, etc.)
        var iter = secrets_map.iterator();
        while (iter.next()) |entry| {
            _ = c.setenv(entry.key_ptr.*.ptr, entry.value_ptr.*.ptr, 1);
        }
        if (debug_mode) {
            std.debug.print("[secrets_injector_zig] Successfully loaded {d} secret(s) into environment\n", .{count});
        }
    } else |err| {
        if (debug_mode) {
            std.debug.print("[secrets_injector_zig] Vault fetch error: {any}\n", .{err});
        }
        if (callRealGetenv("SECRETS_INJECTOR_FAIL_FAST")) |ff| {
            const s = std.mem.span(ff);
            if (std.mem.eql(u8, s, "1") or std.ascii.eqlIgnoreCase(s, "true")) {
                std.debug.print("[secrets_injector_zig] FATAL: Failed to fetch secrets from vault (FAIL_FAST=1)\n", .{});
                c.exit(1);
            }
        }
    }

    // Scrub SECRETS_FETCH_KEY if enabled
    if (scrub_fetch_key) {
        if (c.environ) |env_ptr| {
            var idx: usize = 0;
            while (env_ptr[idx]) |entry| : (idx += 1) {
                const s = std.mem.span(entry);
                if (std.mem.startsWith(u8, s, "SECRETS_FETCH_KEY=")) {
                    @memset(s, 0);
                    break;
                }
            }
        }
        _ = c.unsetenv("SECRETS_FETCH_KEY");
        if (debug_mode) {
            std.debug.print("[secrets_injector_zig] SECRETS_FETCH_KEY scrubbed from process environment\n", .{});
        }
    }

    secrets_initialized = true;
}

pub export fn getenv(name: ?[*:0]const u8) callconv(.C) ?[*:0]u8 {
    const n = name orelse return null;

    if (in_fetch or resolving_real) {
        return callRealGetenv(name);
    }

    init_once.call();

    const name_slice = std.mem.span(n);
    if (scrub_fetch_key and std.mem.eql(u8, name_slice, "SECRETS_FETCH_KEY")) {
        return null;
    }

    if (secrets_initialized) {
        if (secrets_map.get(name_slice)) |val| {
            return @constCast(val.ptr);
        }
    }

    return callRealGetenv(name);
}

pub export fn secure_getenv(name: ?[*:0]const u8) callconv(.C) ?[*:0]u8 {
    const n = name orelse return null;

    if (in_fetch or resolving_real) {
        return callRealSecureGetenv(name);
    }

    init_once.call();

    const name_slice = std.mem.span(n);
    if (scrub_fetch_key and std.mem.eql(u8, name_slice, "SECRETS_FETCH_KEY")) {
        return null;
    }

    if (secrets_initialized) {
        if (secrets_map.get(name_slice)) |val| {
            return @constCast(val.ptr);
        }
    }

    return callRealSecureGetenv(name);
}

pub export fn __secure_getenv(name: ?[*:0]const u8) callconv(.C) ?[*:0]u8 {
    return secure_getenv(name);
}
