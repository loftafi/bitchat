pub const header_size: usize = 14;
pub const sender_id_size: usize = 8;
pub const recipient_id_size: usize = 8;
pub const signature_size: usize = 64;
pub const max_packet_size = header_size + sender_id_size + recipient_id_size + signature_size + std.math.maxInt(u16);
pub const broadcast_recipient: u64 = 0xFFFFFFFFFFFFFFFF;

pub const Packet = struct {
    version: u8,
    type: MessageType,
    ttl: u8,
    timestamp: u64,
    flags: packed struct {
        has_recipient: bool,
        has_signature: bool,
        is_compressed: bool,
        padding: u5,
    },
    payload: []const u8,
    payload_length: u16,
    sender_id: u64,
    recipient_id: ?u64,
    signature: ?[]const u8,

    pub fn init(message_type: MessageType, senderID: u64, recipientID: ?u64, timestamp: u64, payload: []const u8, signature: ?[]const u8, ttl: u8) error{PayloadTooLarge}!Packet {
        if (payload.len > std.math.maxInt(u16))
            return error.PayloadTooLarge;
        return .{
            .version = 1,
            .type = message_type,
            .ttl = ttl,
            .sender_id = senderID,
            .recipient_id = recipientID,
            .timestamp = timestamp,
            .payload = payload,
            .payload_length = @intCast(payload.len),
            .signature = signature,
            .flags = .{
                .has_recipient = recipientID != null,
                .has_signature = signature != null,
                .is_compressed = false,
                .padding = 0,
            },
        };
    }

    pub fn read(message: []const u8) error{
        InvalidPacketSize,
        InvalidPacketVersion,
        InvalidPacketDataLength,
        InvalidMessageType,
    }!Packet {
        if (message.len < header_size + sender_id_size)
            return error.InvalidPacketSize;

        var packet: Packet = undefined;
        var data = message;
        packet.version = data[0];
        data.ptr += 1;
        if (data.len < header_size + sender_id_size)
            return error.InvalidPacketVersion;

        packet.type = try MessageType.parse(data[0]);
        data.ptr += 1;

        packet.ttl = data[0];
        data.ptr += 1;

        packet.timestamp = std.mem.readInt(u64, data[0..8], .big);
        data.ptr += 8;

        packet.flags = @bitCast(data[0]);
        data.ptr += 1;

        packet.payload_length = std.mem.readInt(u16, data[0..2], .big);
        data.ptr += 2;

        var expected_size = header_size + sender_id_size + packet.payload_length;
        if (packet.flags.has_recipient) expected_size += recipient_id_size;
        if (packet.flags.has_signature) expected_size += signature_size;

        if (data.len != expected_size) {
            return error.InvalidPacketDataLength;
        }

        packet.sender_id = std.mem.readInt(u64, data[0..8], .big);
        data.ptr += 8;

        if (packet.flags.has_recipient) {
            packet.recipient_id = std.mem.readInt(u64, data[0..8], .big);
            data.ptr += 8;
        } else {
            packet.recipient_id = null;
        }

        packet.payload = data[0..packet.payload_length];
        data.ptr += packet.payload_length;

        if (packet.flags.has_signature) {
            packet.signature = data[0..64];
            data.ptr += 64;
        } else {
            packet.signature = null;
        }

        return packet;
    }

    pub fn write(packet: *Packet, buffer: *std.ArrayListUnmanaged(u8)) error{PayloadTooLarge}!void {
        if (packet.payload.len > std.math.maxInt(u16))
            return error.PayloadTooLarge;
        packet.payload_length = @intCast(packet.payload.len);

        packet.flags.has_signature = packet.signature != null;
        packet.flags.has_recipient = packet.recipient_id != null;

        var tmp: [8]u8 = undefined;
        buffer.appendAssumeCapacity(packet.version);
        buffer.appendAssumeCapacity(@intCast(@intFromEnum(packet.type)));
        buffer.appendAssumeCapacity(packet.ttl);
        std.mem.writeInt(u64, &tmp, packet.timestamp, .big);
        buffer.appendSliceAssumeCapacity(&tmp);
        buffer.appendAssumeCapacity(@bitCast(packet.flags));
        std.mem.writeInt(u16, tmp[0..2], packet.payload_length, .big);
        buffer.appendSliceAssumeCapacity(tmp[0..2]);
        std.mem.writeInt(u64, &tmp, packet.sender_id, .big);
        buffer.appendSliceAssumeCapacity(&tmp);
        if (packet.recipient_id) |recipient_id| {
            std.mem.writeInt(u64, &tmp, recipient_id, .big);
            buffer.appendSliceAssumeCapacity(&tmp);
        }
        buffer.appendSliceAssumeCapacity(packet.payload);
        if (packet.signature) |signature| {
            buffer.appendSliceAssumeCapacity(signature);
        }
    }
};

pub const MessageType = enum(u8) {
    unknown = 0,

    /// Peer announcement with public key
    announce = 1,

    /// Key exchange messages
    key_exchange = 2,

    /// Graceful disconnect
    leave = 3,

    /// Chat messages (private/broadcast)
    message = 4,

    /// Start of fragmented message
    fragment_start = 5,

    /// Continuation fragment
    fragment_continue = 6,

    /// Final fragment
    fragment_end = 7,

    /// Channel status announcement
    room_announce = 8,

    /// Channel retention policy
    room_retention = 9,

    /// Acknowledge message received
    delivery_ack = 10,

    /// Request delivery status update
    delivery_status_request = 11,

    /// Message has been read/viewed
    read_receipt = 12,

    pub fn parse(value: u8) error{InvalidMessageType}!MessageType {
        if (value > 0 and value <= 12)
            return @enumFromInt(value);
        return error.InvalidMessageType;
    }
};

const assert = std.debug.assert;
const std = @import("std");
const testing = std.testing;
const ArrayListUnmanaged = std.ArrayListUnmanaged;
const expect = std.testing.expect;
const expectEqual = std.testing.expectEqual;
const expectEqualSlices = std.testing.expectEqualSlices;
const expectEqualStrings = std.testing.expectEqualStrings;

test "packet_flags" {
    var packet: Packet = undefined;
    packet.flags.has_recipient = false;
    packet.flags.has_signature = false;
    packet.flags.is_compressed = false;
    packet.flags.padding = 0;
    try expectEqual(0, @as(u8, @bitCast(packet.flags)));
    packet.flags.has_recipient = true;
    packet.flags.has_signature = true;
    packet.flags.is_compressed = true;
    try expectEqual(7, @as(u8, @bitCast(packet.flags)));
    packet.flags.has_recipient = false;
    try expectEqual(6, @as(u8, @bitCast(packet.flags)));
}

test "read_packet_no_recipient" {
    const allocator = std.testing.allocator;

    // Packet without recipient
    const data: []const u8 = &[22]u8{
        1, 2, 3, 1, 2, 3, 4, 5, 6, 7, 8,
        0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8,
    };
    var packet = try Packet.read(data);
    try expectEqual(1, packet.version);
    try expectEqual(.key_exchange, packet.type);
    try expectEqual(3, packet.ttl);
    try expectEqual(72623859790382856, packet.timestamp);
    try expectEqual(false, packet.flags.has_recipient);
    try expectEqual(false, packet.flags.has_signature);
    try expectEqual(false, packet.flags.is_compressed);
    try expectEqual(0, packet.payload_length);
    try expectEqual(72623859790382856, packet.sender_id);
    try expectEqual(null, packet.recipient_id);
    try expectEqual(null, packet.signature);

    var buffer = try ArrayListUnmanaged(u8).initCapacity(allocator, max_packet_size);
    defer buffer.deinit(std.testing.allocator);
    try packet.write(&buffer);
    try expectEqualSlices(u8, data, buffer.items);
}

test "read_packet_with_recipient" {
    const allocator = std.testing.allocator;

    // Packet with recipient
    const data: []const u8 = &[94]u8{
        1, 2, 3, 1, 2, 3, 4, 5, 6, 7, 8, 255, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8,
        1, 2, 3, 4, 5, 6, 7, 8, 4, 4, 4, 4,   4, 4, 4, 4, 5, 5, 5, 5, 5, 5,
        5, 5, 6, 6, 6, 6, 6, 6, 6, 6, 9, 9,   9, 9, 9, 9, 9, 9, 4, 4, 4, 4,
        4, 4, 4, 4, 5, 5, 5, 5, 5, 5, 5, 5,   6, 6, 6, 6, 6, 6, 6, 6, 9, 9,
        9, 9, 9, 9, 9, 9,
    };
    var packet = try Packet.read(data);
    try expectEqual(1, packet.version);
    try expectEqual(.key_exchange, packet.type);
    try expectEqual(3, packet.ttl);
    try expectEqual(true, packet.flags.has_recipient);
    try expectEqual(true, packet.flags.has_signature);
    try expectEqual(true, packet.flags.is_compressed);
    try expectEqual(72623859790382856, packet.timestamp);
    try expectEqual(72623859790382856, packet.sender_id);
    try expect(packet.recipient_id != null);
    try expectEqual(72623859790382856, packet.recipient_id.?);
    try expect(packet.signature != null);
    try expectEqual(4, packet.signature.?[0]);
    try expectEqual(9, packet.signature.?[63]);

    var buffer = try std.ArrayListUnmanaged(u8).initCapacity(allocator, max_packet_size);
    defer buffer.deinit(std.testing.allocator);
    try packet.write(&buffer);
    try expectEqualSlices(u8, data, buffer.items);
}

test "read_packet_no_recipient_has_message" {
    const allocator = std.testing.allocator;

    // Packet without recipient
    const data: []const u8 = &[25]u8{
        1, 2, 3, 1, 2, 3, 4, 5, 6, 7,   8,   0,   0,
        3, 1, 2, 3, 4, 5, 6, 7, 8, 'A', 'B', 'C',
    };
    var packet = try Packet.read(data);
    try expectEqual(1, packet.version);
    try expectEqual(.key_exchange, packet.type);
    try expectEqual(3, packet.ttl);
    try expectEqual(72623859790382856, packet.timestamp);
    try expectEqual(false, packet.flags.has_recipient);
    try expectEqual(false, packet.flags.has_signature);
    try expectEqual(false, packet.flags.is_compressed);
    try expectEqual(3, packet.payload_length);
    try expectEqualStrings("ABC", packet.payload);
    try expectEqual(72623859790382856, packet.sender_id);
    try expectEqual(null, packet.recipient_id);
    try expectEqual(null, packet.signature);

    var buffer = try ArrayListUnmanaged(u8).initCapacity(allocator, max_packet_size);
    defer buffer.deinit(std.testing.allocator);
    try packet.write(&buffer);
    try expectEqualSlices(u8, data, buffer.items);
}

test "read_packet_with_recipient_and_message" {
    const allocator = std.testing.allocator;

    // Packet with recipient
    const data: []const u8 = &[97]u8{
        1, 12, 3, 1, 2, 3, 4, 5, 6,   7,   8,   255, 0, 3, 1, 2, 3, 4, 5, 6, 7, 8,
        1, 2,  3, 4, 5, 6, 7, 8, 'A', 'B', 'C', 4,   4, 4, 4, 4, 4, 4, 4, 5, 5, 5,
        5, 5,  5, 5, 5, 6, 6, 6, 6,   6,   6,   6,   6, 9, 9, 9, 9, 9, 9, 9, 9, 4,
        4, 4,  4, 4, 4, 4, 4, 5, 5,   5,   5,   5,   5, 5, 5, 6, 6, 6, 6, 6, 6, 6,
        6, 9,  9, 9, 9, 9, 9, 9, 9,
    };
    var packet = try Packet.read(data);
    try expectEqual(1, packet.version);
    try expectEqual(.read_receipt, packet.type);
    try expectEqual(3, packet.ttl);
    try expectEqual(true, packet.flags.has_recipient);
    try expectEqual(true, packet.flags.has_signature);
    try expectEqual(true, packet.flags.is_compressed);
    try expectEqual(72623859790382856, packet.timestamp);
    try expectEqual(72623859790382856, packet.sender_id);
    try expect(packet.recipient_id != null);
    try expectEqual(3, packet.payload_length);
    try expectEqualStrings("ABC", packet.payload);
    try expectEqual(72623859790382856, packet.recipient_id.?);
    try expect(packet.signature != null);
    try expectEqualStrings("ABC", packet.payload);
    try expectEqual(9, packet.signature.?[63]);

    var buffer = try ArrayListUnmanaged(u8).initCapacity(allocator, max_packet_size);
    defer buffer.deinit(std.testing.allocator);
    try packet.write(&buffer);
    try expectEqualSlices(u8, data, buffer.items);

    const sig: []const u8 = &[signature_size]u8{
        4, 4, 4, 4, 4, 4, 4, 4, 5, 5, 5, 5, 5, 5, 5, 5,
        6, 6, 6, 6, 6, 6, 6, 6, 9, 9, 9, 9, 9, 9, 9, 9,
        4, 4, 4, 4, 4, 4, 4, 4, 5, 5, 5, 5, 5, 5, 5, 5,
        6, 6, 6, 6, 6, 6, 6, 6, 9, 9, 9, 9, 9, 9, 9, 9,
    };
    const packet2 = try Packet.init(
        .read_receipt,
        72623859790382856,
        72623859790382856,
        72623859790382856,
        "ABC",
        sig,
        3,
    );
    try testing.expectEqual(1, packet2.version);
    try testing.expectEqual(.read_receipt, packet2.type);
    try testing.expectEqual(3, packet2.ttl);
    try testing.expectEqual(true, packet2.flags.has_recipient);
    try testing.expectEqual(true, packet2.flags.has_signature);
    try testing.expectEqual(false, packet2.flags.is_compressed);
    try testing.expectEqual(72623859790382856, packet2.timestamp);
    try testing.expectEqual(72623859790382856, packet2.sender_id);
    try testing.expect(packet2.recipient_id != null);
    try testing.expectEqual(3, packet2.payload_length);
    try testing.expectEqualStrings("ABC", packet2.payload);
    try testing.expectEqual(72623859790382856, packet2.recipient_id.?);
    try testing.expect(packet2.signature != null);
    try testing.expectEqualStrings("ABC", packet2.payload);
    try testing.expectEqual(9, packet2.signature.?[63]);
}
