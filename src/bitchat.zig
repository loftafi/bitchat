pub const HEADER_SIZE: usize = 14;
pub const SENDER_ID_SIZE: usize = 8;
pub const RECIPIENT_ID_SIZE: usize = 8;
pub const SIGNATURE_SIZE: usize = 64;
pub const MAX_PACKET_SIZE = HEADER_SIZE + SENDER_ID_SIZE + RECIPIENT_ID_SIZE + SIGNATURE_SIZE + std.math.maxInt(u16);
pub const BROADCAST_RECIPIENT: u64 = 0xFFFFFFFFFFFFFFFF;

pub const Packet = struct {
    version: u8,
    type: MessageType,
    ttl: u8,
    timestamp: u64,
    flags: packed struct {
        hasRecipient: bool,
        hasSignature: bool,
        isCompressed: bool,
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
                .hasRecipient = recipientID != null,
                .hasSignature = signature != null,
                .isCompressed = false,
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
        if (message.len < HEADER_SIZE + SENDER_ID_SIZE)
            return error.InvalidPacketSize;

        var packet: Packet = undefined;
        var data = message;
        packet.version = data[0];
        data.ptr += 1;
        if (data.len < HEADER_SIZE + SENDER_ID_SIZE)
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

        var expected_size = HEADER_SIZE + SENDER_ID_SIZE + packet.payload_length;
        if (packet.flags.hasRecipient) expected_size += RECIPIENT_ID_SIZE;
        if (packet.flags.hasSignature) expected_size += SIGNATURE_SIZE;

        if (data.len != expected_size) {
            //err(
            //    "Expected packet size {d}, found {d}",
            //    .{ expected_size, data.len },
            //);
            return error.InvalidPacketDataLength;
        }

        packet.sender_id = std.mem.readInt(u64, data[0..8], .big);
        data.ptr += 8;

        if (packet.flags.hasRecipient) {
            packet.recipient_id = std.mem.readInt(u64, data[0..8], .big);
            data.ptr += 8;
        } else {
            packet.recipient_id = null;
        }

        packet.payload = data[0..packet.payload_length];
        data.ptr += packet.payload_length;

        if (packet.flags.hasSignature) {
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

        packet.flags.hasSignature = packet.signature != null;
        packet.flags.hasRecipient = packet.recipient_id != null;

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
const err = std.log.err;
const debug = std.log.debug;
const testing = std.testing;
const expectEqual = std.testing.expectEqual;

test "packet_flags" {
    var packet: Packet = undefined;
    packet.flags.hasRecipient = false;
    packet.flags.hasSignature = false;
    packet.flags.isCompressed = false;
    packet.flags.padding = 0;
    try expectEqual(0, @as(u8, @bitCast(packet.flags)));
    packet.flags.hasRecipient = true;
    packet.flags.hasSignature = true;
    packet.flags.isCompressed = true;
    try expectEqual(7, @as(u8, @bitCast(packet.flags)));
    packet.flags.hasRecipient = false;
    try expectEqual(6, @as(u8, @bitCast(packet.flags)));
}

test "read_packet_no_recipient" {
    // Packet without recipient
    const data: []const u8 = &[22]u8{ 1, 2, 3, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8 };
    var packet = try Packet.read(data);
    try testing.expectEqual(1, packet.version);
    try testing.expectEqual(.key_exchange, packet.type);
    try testing.expectEqual(3, packet.ttl);
    try testing.expectEqual(72623859790382856, packet.timestamp);
    try testing.expectEqual(false, packet.flags.hasRecipient);
    try testing.expectEqual(false, packet.flags.hasSignature);
    try testing.expectEqual(false, packet.flags.isCompressed);
    try testing.expectEqual(0, packet.payload_length);
    try testing.expectEqual(72623859790382856, packet.sender_id);
    try testing.expectEqual(null, packet.recipient_id);
    try testing.expectEqual(null, packet.signature);

    var buffer = try std.ArrayListUnmanaged(u8).initCapacity(std.testing.allocator, MAX_PACKET_SIZE);
    defer buffer.deinit(std.testing.allocator);
    try packet.write(&buffer);
    try testing.expectEqualSlices(u8, data, buffer.items);
}

test "read_packet_with_recipient" {
    // Packet with recipient
    const data: []const u8 = &[94]u8{
        1, 2, 3, 1, 2, 3, 4, 5, 6, 7, 8, 255, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8,
        1, 2, 3, 4, 5, 6, 7, 8, 4, 4, 4, 4,   4, 4, 4, 4, 5, 5, 5, 5, 5, 5,
        5, 5, 6, 6, 6, 6, 6, 6, 6, 6, 9, 9,   9, 9, 9, 9, 9, 9, 4, 4, 4, 4,
        4, 4, 4, 4, 5, 5, 5, 5, 5, 5, 5, 5,   6, 6, 6, 6, 6, 6, 6, 6, 9, 9,
        9, 9, 9, 9, 9, 9,
    };
    var packet = try Packet.read(data);
    try testing.expectEqual(1, packet.version);
    try testing.expectEqual(.key_exchange, packet.type);
    try testing.expectEqual(3, packet.ttl);
    try testing.expectEqual(true, packet.flags.hasRecipient);
    try testing.expectEqual(true, packet.flags.hasSignature);
    try testing.expectEqual(true, packet.flags.isCompressed);
    try testing.expectEqual(72623859790382856, packet.timestamp);
    try testing.expectEqual(72623859790382856, packet.sender_id);
    try testing.expect(packet.recipient_id != null);
    try testing.expectEqual(72623859790382856, packet.recipient_id.?);
    try testing.expect(packet.signature != null);
    try testing.expectEqual(4, packet.signature.?[0]);
    try testing.expectEqual(9, packet.signature.?[63]);

    var buffer = try std.ArrayListUnmanaged(u8).initCapacity(std.testing.allocator, MAX_PACKET_SIZE);
    defer buffer.deinit(std.testing.allocator);
    try packet.write(&buffer);
    try testing.expectEqualSlices(u8, data, buffer.items);
}

test "read_packet_no_recipient_has_message" {
    // Packet without recipient
    const data: []const u8 = &[25]u8{ 1, 2, 3, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 3, 1, 2, 3, 4, 5, 6, 7, 8, 'A', 'B', 'C' };
    var packet = try Packet.read(data);
    try testing.expectEqual(1, packet.version);
    try testing.expectEqual(.key_exchange, packet.type);
    try testing.expectEqual(3, packet.ttl);
    try testing.expectEqual(72623859790382856, packet.timestamp);
    try testing.expectEqual(false, packet.flags.hasRecipient);
    try testing.expectEqual(false, packet.flags.hasSignature);
    try testing.expectEqual(false, packet.flags.isCompressed);
    try testing.expectEqual(3, packet.payload_length);
    try testing.expectEqualStrings("ABC", packet.payload);
    try testing.expectEqual(72623859790382856, packet.sender_id);
    try testing.expectEqual(null, packet.recipient_id);
    try testing.expectEqual(null, packet.signature);

    var buffer = try std.ArrayListUnmanaged(u8).initCapacity(std.testing.allocator, MAX_PACKET_SIZE);
    defer buffer.deinit(std.testing.allocator);
    try packet.write(&buffer);
    try testing.expectEqualSlices(u8, data, buffer.items);
}

test "read_packet_with_recipient_and_message" {
    // Packet with recipient
    const data: []const u8 = &[97]u8{
        1, 12, 3, 1, 2, 3, 4, 5, 6,   7,   8,   255, 0, 3, 1, 2, 3, 4, 5, 6, 7, 8,
        1, 2,  3, 4, 5, 6, 7, 8, 'A', 'B', 'C', 4,   4, 4, 4, 4, 4, 4, 4, 5, 5, 5,
        5, 5,  5, 5, 5, 6, 6, 6, 6,   6,   6,   6,   6, 9, 9, 9, 9, 9, 9, 9, 9, 4,
        4, 4,  4, 4, 4, 4, 4, 5, 5,   5,   5,   5,   5, 5, 5, 6, 6, 6, 6, 6, 6, 6,
        6, 9,  9, 9, 9, 9, 9, 9, 9,
    };
    var packet = try Packet.read(data);
    try testing.expectEqual(1, packet.version);
    try testing.expectEqual(.read_receipt, packet.type);
    try testing.expectEqual(3, packet.ttl);
    try testing.expectEqual(true, packet.flags.hasRecipient);
    try testing.expectEqual(true, packet.flags.hasSignature);
    try testing.expectEqual(true, packet.flags.isCompressed);
    try testing.expectEqual(72623859790382856, packet.timestamp);
    try testing.expectEqual(72623859790382856, packet.sender_id);
    try testing.expect(packet.recipient_id != null);
    try testing.expectEqual(3, packet.payload_length);
    try testing.expectEqualStrings("ABC", packet.payload);
    try testing.expectEqual(72623859790382856, packet.recipient_id.?);
    try testing.expect(packet.signature != null);
    try testing.expectEqualStrings("ABC", packet.payload);
    try testing.expectEqual(9, packet.signature.?[63]);

    var buffer = try std.ArrayListUnmanaged(u8).initCapacity(std.testing.allocator, MAX_PACKET_SIZE);
    defer buffer.deinit(std.testing.allocator);
    try packet.write(&buffer);
    try testing.expectEqualSlices(u8, data, buffer.items);

    const sig: []const u8 = &[64]u8{ 4, 4, 4, 4, 4, 4, 4, 4, 5, 5, 5, 5, 5, 5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 6, 9, 9, 9, 9, 9, 9, 9, 9, 4, 4, 4, 4, 4, 4, 4, 4, 5, 5, 5, 5, 5, 5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 6, 9, 9, 9, 9, 9, 9, 9, 9 };
    const packet2 = try Packet.init(.read_receipt, 72623859790382856, 72623859790382856, 72623859790382856, "ABC", sig, 3);
    try testing.expectEqual(1, packet2.version);
    try testing.expectEqual(.read_receipt, packet2.type);
    try testing.expectEqual(3, packet2.ttl);
    try testing.expectEqual(true, packet2.flags.hasRecipient);
    try testing.expectEqual(true, packet2.flags.hasSignature);
    try testing.expectEqual(false, packet2.flags.isCompressed);
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
