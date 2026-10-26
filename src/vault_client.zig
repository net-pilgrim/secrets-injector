const std = @import("std");
const json_parser = @import("json_parser.zig");

pub const VaultConfig = struct {
    url: [:0]const u8,
    fetch_key: [:0]const u8,
    auth_header: ?[:0]const u8 = null,
    timeout_seconds: c_long = 5,
    insecure_ssl: bool = false,
    debug: bool = false,
};

pub fn fetchSecrets(allocator: std.mem.Allocator, config: VaultConfig, map: *json_parser.SecretsMap) !usize {
    var client = std.http.Client{ .allocator = allocator };
    defer client.deinit();

    const uri = std.Uri.parse(config.url) catch |err| {
        if (config.debug) {
            std.debug.print("[secrets_injector_zig] Failed to parse URL: {s} (error: {})\n", .{ config.url, err });
        }
        return error.InvalidUrl;
    };

    var server_header_buffer: [8192]u8 = undefined;

    // Prepare headers
    var extra_headers_buf: [4]std.http.Header = undefined;
    var extra_headers_count: usize = 0;

    extra_headers_buf[extra_headers_count] = .{
        .name = "Accept",
        .value = "application/json, text/plain, */*",
    };
    extra_headers_count += 1;

    var custom_header_buf: [1024]u8 = undefined;
    var token_header_buf: [1024]u8 = undefined;
    var bearer_header_buf: [1024]u8 = undefined;

    if (config.auth_header) |hdr| {
        const val = try std.fmt.bufPrint(&custom_header_buf, "{s}", .{config.fetch_key});
        extra_headers_buf[extra_headers_count] = .{
            .name = hdr,
            .value = val,
        };
        extra_headers_count += 1;
    } else {
        const tok_val = try std.fmt.bufPrint(&token_header_buf, "{s}", .{config.fetch_key});
        extra_headers_buf[extra_headers_count] = .{
            .name = "X-Vault-Token",
            .value = tok_val,
        };
        extra_headers_count += 1;

        const bearer_val = try std.fmt.bufPrint(&bearer_header_buf, "Bearer {s}", .{config.fetch_key});
        extra_headers_buf[extra_headers_count] = .{
            .name = "Authorization",
            .value = bearer_val,
        };
        extra_headers_count += 1;
    }

    if (config.debug) {
        std.debug.print("[secrets_injector_zig] Fetching secrets from {s} ...\n", .{config.url});
    }

    var req = client.open(.GET, uri, .{
        .server_header_buffer = &server_header_buffer,
        .extra_headers = extra_headers_buf[0..extra_headers_count],
        .keep_alive = false,
    }) catch |err| {
        if (config.debug) {
            std.debug.print("[secrets_injector_zig] HTTP request connection failed: {}\n", .{err});
        }
        return error.CurlPerformFailed;
    };
    defer req.deinit();

    req.send() catch |err| {
        if (config.debug) {
            std.debug.print("[secrets_injector_zig] HTTP send failed: {}\n", .{err});
        }
        return error.CurlPerformFailed;
    };

    req.finish() catch |err| {
        if (config.debug) {
            std.debug.print("[secrets_injector_zig] HTTP finish failed: {}\n", .{err});
        }
        return error.CurlPerformFailed;
    };

    req.wait() catch |err| {
        if (config.debug) {
            std.debug.print("[secrets_injector_zig] HTTP wait failed: {}\n", .{err});
        }
        return error.CurlPerformFailed;
    };

    const status_code = @intFromEnum(req.response.status);
    var body_buffer = std.ArrayList(u8).init(allocator);
    defer body_buffer.deinit();

    var read_buf: [4096]u8 = undefined;
    while (true) {
        const bytes_read = req.read(&read_buf) catch |err| {
            if (config.debug) {
                std.debug.print("[secrets_injector_zig] Error reading body: {}\n", .{err});
            }
            return error.CurlPerformFailed;
        };
        if (bytes_read == 0) break;
        try body_buffer.appendSlice(read_buf[0..bytes_read]);
    }

    if (status_code >= 200 and status_code < 300) {
        if (config.debug) {
            std.debug.print("[secrets_injector_zig] Received {d} bytes (HTTP {d})\n", .{ body_buffer.items.len, status_code });
        }
        const count = try json_parser.parseSecrets(allocator, body_buffer.items, map);
        if (config.debug) {
            std.debug.print("[secrets_injector_zig] Parsed {d} secret(s)\n", .{count});
        }
        return count;
    } else {
        if (config.debug) {
            const preview_len = @min(body_buffer.items.len, 200);
            std.debug.print("[secrets_injector_zig] Vault returned HTTP {d}: {s}\n", .{ status_code, body_buffer.items[0..preview_len] });
        }
        return error.VaultHttpError;
    }
}
