const std = @import("std");
const json_parser = @import("json_parser.zig");

const c = @cImport({
    @cInclude("curl/curl.h");
});

pub const VaultConfig = struct {
    url: [:0]const u8,
    fetch_key: [:0]const u8,
    auth_header: ?[:0]const u8 = null,
    timeout_seconds: c_long = 5,
    insecure_ssl: bool = false,
    debug: bool = false,
};

fn writeCallback(contents: [*c]u8, size: usize, nmemb: usize, userp: ?*anyopaque) callconv(.C) usize {
    const total_bytes = size * nmemb;
    if (userp) |ctx| {
        const list: *std.ArrayList(u8) = @ptrCast(@alignCast(ctx));
        const slice = contents[0..total_bytes];
        list.appendSlice(slice) catch return 0;
    }
    return total_bytes;
}

pub fn fetchSecrets(allocator: std.mem.Allocator, config: VaultConfig, map: *json_parser.SecretsMap) !usize {
    const curl = c.curl_easy_init() orelse {
        if (config.debug) {
            std.debug.print("[secrets_injector_zig] Failed to initialize libcurl\n", .{});
        }
        return error.CurlInitFailed;
    };
    defer c.curl_easy_cleanup(curl);

    var response_buffer = std.ArrayList(u8).init(allocator);
    defer response_buffer.deinit();

    var headers: ?*c.curl_slist = null;
    defer {
        if (headers) |h| c.curl_slist_free_all(h);
    }

    headers = c.curl_slist_append(headers, "Accept: application/json, text/plain, */*");

    if (config.auth_header) |hdr| {
        var buf: [1024]u8 = undefined;
        const formatted = try std.fmt.bufPrintZ(&buf, "{s}: {s}", .{ hdr, config.fetch_key });
        headers = c.curl_slist_append(headers, formatted.ptr);
    } else {
        var token_buf: [1024]u8 = undefined;
        const token_hdr = try std.fmt.bufPrintZ(&token_buf, "X-Vault-Token: {s}", .{config.fetch_key});
        headers = c.curl_slist_append(headers, token_hdr.ptr);

        var bearer_buf: [1024]u8 = undefined;
        const bearer_hdr = try std.fmt.bufPrintZ(&bearer_buf, "Authorization: Bearer {s}", .{config.fetch_key});
        headers = c.curl_slist_append(headers, bearer_hdr.ptr);
    }

    _ = c.curl_easy_setopt(curl, c.CURLOPT_URL, config.url.ptr);
    _ = c.curl_easy_setopt(curl, c.CURLOPT_HTTPHEADER, headers);
    _ = c.curl_easy_setopt(curl, c.CURLOPT_WRITEFUNCTION, writeCallback);
    _ = c.curl_easy_setopt(curl, c.CURLOPT_WRITEDATA, @as(*anyopaque, @ptrCast(&response_buffer)));
    _ = c.curl_easy_setopt(curl, c.CURLOPT_FOLLOWLOCATION, @as(c_long, 1));

    const timeout = if (config.timeout_seconds > 0) config.timeout_seconds else 5;
    _ = c.curl_easy_setopt(curl, c.CURLOPT_TIMEOUT, timeout);
    _ = c.curl_easy_setopt(curl, c.CURLOPT_CONNECTTIMEOUT, if (timeout > 3) @as(c_long, 3) else timeout);

    if (config.insecure_ssl) {
        _ = c.curl_easy_setopt(curl, c.CURLOPT_SSL_VERIFYPEER, @as(c_long, 0));
        _ = c.curl_easy_setopt(curl, c.CURLOPT_SSL_VERIFYHOST, @as(c_long, 0));
    }

    if (config.debug) {
        std.debug.print("[secrets_injector_zig] Fetching secrets from {s} ...\n", .{config.url});
    }

    const res = c.curl_easy_perform(curl);
    if (res != c.CURLE_OK) {
        if (config.debug) {
            const err_str = c.curl_easy_strerror(res);
            std.debug.print("[secrets_injector_zig] Curl request failed: {s}\n", .{err_str});
        }
        return error.CurlPerformFailed;
    }

    var http_code: c_long = 0;
    _ = c.curl_easy_getinfo(curl, c.CURLINFO_RESPONSE_CODE, &http_code);

    if (http_code >= 200 and http_code < 300) {
        if (config.debug) {
            std.debug.print("[secrets_injector_zig] Received {d} bytes (HTTP {d})\n", .{ response_buffer.items.len, http_code });
        }
        const count = try json_parser.parseSecrets(allocator, response_buffer.items, map);
        if (config.debug) {
            std.debug.print("[secrets_injector_zig] Parsed {d} secret(s)\n", .{count});
        }
        return count;
    } else {
        if (config.debug) {
            const preview_len = @min(response_buffer.items.len, 200);
            std.debug.print("[secrets_injector_zig] Vault returned HTTP {d}: {s}\n", .{ http_code, response_buffer.items[0..preview_len] });
        }
        return error.VaultHttpError;
    }
}
