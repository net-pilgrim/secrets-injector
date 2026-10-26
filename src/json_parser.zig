const std = @import("std");

pub const SecretsMap = std.StringHashMap([:0]const u8);

pub fn parseSecrets(allocator: std.mem.Allocator, input: []const u8, map: *SecretsMap) !usize {
    const trimmed = std.mem.trim(u8, input, " \t\r\n");
    if (trimmed.len == 0) return 0;

    if (trimmed[0] == '{' or trimmed[0] == '[') {
        return parseJson(allocator, trimmed, map);
    } else {
        return parseDotenv(allocator, trimmed, map);
    }
}

fn valueToString(allocator: std.mem.Allocator, val: std.json.Value) !?[:0]const u8 {
    switch (val) {
        .string => |s| {
            return try allocator.dupeZ(u8, s);
        },
        .integer => |i| {
            var buf: [32]u8 = undefined;
            const formatted = try std.fmt.bufPrint(&buf, "{d}", .{i});
            return try allocator.dupeZ(u8, formatted);
        },
        .float => |f| {
            var buf: [64]u8 = undefined;
            const formatted = try std.fmt.bufPrint(&buf, "{d}", .{f});
            return try allocator.dupeZ(u8, formatted);
        },
        .bool => |b| {
            return try allocator.dupeZ(u8, if (b) "true" else "false");
        },
        .null => {
            return try allocator.dupeZ(u8, "");
        },
        else => return null,
    }
}

fn extractKeyValue(allocator: std.mem.Allocator, key_val: std.json.Value, val_val: std.json.Value, map: *SecretsMap) !bool {
    const key_str = switch (key_val) {
        .string => |s| s,
        else => return false,
    };

    if (key_str.len == 0) return false;

    if (try valueToString(allocator, val_val)) |vs| {
        const owned_key = try allocator.dupe(u8, key_str);
        try map.put(owned_key, vs);
        return true;
    }
    return false;
}

fn extractFlatObject(allocator: std.mem.Allocator, obj: std.json.ObjectMap, map: *SecretsMap) !usize {
    var count: usize = 0;
    var iter = obj.iterator();
    while (iter.next()) |entry| {
        const k = entry.key_ptr.*;
        const v = entry.value_ptr.*;
        if (try valueToString(allocator, v)) |vs| {
            const owned_key = try allocator.dupe(u8, k);
            try map.put(owned_key, vs);
            count += 1;
        }
    }
    return count;
}

fn extractSecretsFromValue(allocator: std.mem.Allocator, val: std.json.Value, map: *SecretsMap) !usize {
    var count: usize = 0;
    switch (val) {
        .object => |obj| {
            // Case 1: Bitwarden Secrets Manager format: {"data": [ {"key": "...", "value": "..."}, ... ]}
            if (obj.get("data")) |d| {
                if (d == .array) {
                    for (d.array.items) |item| {
                        if (item == .object) {
                            if (item.object.get("key")) |k| {
                                if (item.object.get("value")) |v| {
                                    if (try extractKeyValue(allocator, k, v, map)) {
                                        count += 1;
                                    }
                                }
                            }
                        }
                    }
                    if (count > 0) return count;
                }
                // Case 2: HashiCorp Vault format: {"data": {"data": { ... }}} or {"data": { ... }}
                if (d == .object) {
                    if (d.object.get("data")) |dd| {
                        if (dd == .object) {
                            return extractFlatObject(allocator, dd.object, map);
                        }
                    }
                    return extractFlatObject(allocator, d.object, map);
                }
            }

            // Case 3: 1Password Connect Item: {"fields": [ {"label": "...", "value": "..."}, ... ]}
            if (obj.get("fields")) |f| {
                if (f == .array) {
                    for (f.array.items) |field| {
                        if (field == .object) {
                            const key_field = field.object.get("label") orelse field.object.get("name");
                            if (key_field) |k| {
                                if (field.object.get("value")) |v| {
                                    if (try extractKeyValue(allocator, k, v, map)) {
                                        count += 1;
                                    }
                                }
                            }
                        }
                    }
                    if (count > 0) return count;
                }
            }

            // Case 4: Generic flat JSON object
            return extractFlatObject(allocator, obj, map);
        },
        .array => |arr| {
            // Case 5: Array of items (e.g. 1Password multiple items or Bitwarden array)
            for (arr.items) |item| {
                count += try extractSecretsFromValue(allocator, item, map);
            }
            return count;
        },
        else => return 0,
    }
}

fn parseJson(allocator: std.mem.Allocator, json_text: []const u8, map: *SecretsMap) !usize {
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, json_text, .{});
    defer parsed.deinit();

    return extractSecretsFromValue(allocator, parsed.value, map);
}

fn parseDotenv(allocator: std.mem.Allocator, text: []const u8, map: *SecretsMap) !usize {
    var count: usize = 0;
    var lines = std.mem.splitScalar(u8, text, '\n');

    while (lines.next()) |raw_line| {
        const line = std.mem.trim(u8, raw_line, " \t\r");
        if (line.len == 0 or line[0] == '#') continue;

        if (std.mem.indexOfScalar(u8, line, '=')) |eq_idx| {
            const raw_key = std.mem.trim(u8, line[0..eq_idx], " \t");
            var raw_val = std.mem.trim(u8, line[eq_idx + 1 ..], " \t");

            if (raw_key.len == 0) continue;

            if (raw_val.len >= 2 and ((raw_val[0] == '"' and raw_val[raw_val.len - 1] == '"') or
                (raw_val[0] == '\'' and raw_val[raw_val.len - 1] == '\'')))
            {
                raw_val = raw_val[1 .. raw_val.len - 1];
            }

            const owned_key = try allocator.dupe(u8, raw_key);
            const owned_val = try allocator.dupeZ(u8, raw_val);
            try map.put(owned_key, owned_val);
            count += 1;
        }
    }

    return count;
}

test "json parser - flat json" {
    const allocator = std.testing.allocator;
    const json = "{\"DB_USER\": \"postgres\", \"DB_PORT\": 5432, \"SECURE\": true, \"EMPTY\": null}";
    var map = SecretsMap.init(allocator);
    defer {
        var it = map.iterator();
        while (it.next()) |e| {
            allocator.free(e.key_ptr.*);
            allocator.free(e.value_ptr.*);
        }
        map.deinit();
    }
    const n = try parseSecrets(allocator, json, &map);
    try std.testing.expectEqual(@as(usize, 4), n);
    try std.testing.expectEqualStrings("postgres", map.get("DB_USER").?);
    try std.testing.expectEqualStrings("5432", map.get("DB_PORT").?);
    try std.testing.expectEqualStrings("true", map.get("SECURE").?);
    try std.testing.expectEqualStrings("", map.get("EMPTY").?);
}

test "json parser - HashiCorp Vault v2" {
    const allocator = std.testing.allocator;
    const json = "{\"data\": {\"data\": {\"API_KEY\": \"vault-secret-123\", \"PORT\": 8080}, \"metadata\": {\"v\": 2}}}";
    var map = SecretsMap.init(allocator);
    defer {
        var it = map.iterator();
        while (it.next()) |e| {
            allocator.free(e.key_ptr.*);
            allocator.free(e.value_ptr.*);
        }
        map.deinit();
    }
    const n = try parseSecrets(allocator, json, &map);
    try std.testing.expectEqual(@as(usize, 2), n);
    try std.testing.expectEqualStrings("vault-secret-123", map.get("API_KEY").?);
    try std.testing.expectEqualStrings("8080", map.get("PORT").?);
}

test "json parser - Bitwarden Secrets Manager" {
    const allocator = std.testing.allocator;
    const json =
        \\{
        \\  "data": [
        \\    {"id": "1", "key": "BW_DATABASE_URL", "value": "postgres://user:pass@localhost/db"},
        \\    {"id": "2", "key": "BW_API_KEY", "value": "bw_token_live_123"}
        \\  ]
        \\}
    ;
    var map = SecretsMap.init(allocator);
    defer {
        var it = map.iterator();
        while (it.next()) |e| {
            allocator.free(e.key_ptr.*);
            allocator.free(e.value_ptr.*);
        }
        map.deinit();
    }
    const n = try parseSecrets(allocator, json, &map);
    try std.testing.expectEqual(@as(usize, 2), n);
    try std.testing.expectEqualStrings("postgres://user:pass@localhost/db", map.get("BW_DATABASE_URL").?);
    try std.testing.expectEqualStrings("bw_token_live_123", map.get("BW_API_KEY").?);
}

test "json parser - 1Password Connect Item" {
    const allocator = std.testing.allocator;
    const json =
        \\{
        \\  "id": "item-abc",
        \\  "title": "Production Config",
        \\  "fields": [
        \\    {"label": "OP_USER", "value": "admin"},
        \\    {"name": "OP_TOKEN", "value": "ops_secret_token"}
        \\  ]
        \\}
    ;
    var map = SecretsMap.init(allocator);
    defer {
        var it = map.iterator();
        while (it.next()) |e| {
            allocator.free(e.key_ptr.*);
            allocator.free(e.value_ptr.*);
        }
        map.deinit();
    }
    const n = try parseSecrets(allocator, json, &map);
    try std.testing.expectEqual(@as(usize, 2), n);
    try std.testing.expectEqualStrings("admin", map.get("OP_USER").?);
    try std.testing.expectEqualStrings("ops_secret_token", map.get("OP_TOKEN").?);
}

test "json parser - dotenv format" {
    const allocator = std.testing.allocator;
    const text = "# comment\nFOO=bar\nBAZ=\"hello world\"\n";
    var map = SecretsMap.init(allocator);
    defer {
        var it = map.iterator();
        while (it.next()) |e| {
            allocator.free(e.key_ptr.*);
            allocator.free(e.value_ptr.*);
        }
        map.deinit();
    }
    const n = try parseSecrets(allocator, text, &map);
    try std.testing.expectEqual(@as(usize, 2), n);
    try std.testing.expectEqualStrings("bar", map.get("FOO").?);
    try std.testing.expectEqualStrings("hello world", map.get("BAZ").?);
}
