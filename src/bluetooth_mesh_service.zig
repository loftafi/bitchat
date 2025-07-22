/// A connected/reachable physical hardware device.
pub const Device = struct {
    //
};

/// A peer we can contact on or through a device.
pub const Peer = struct {
    id: u64,
    nickname: []const u8,
    //public_key: []const u8,
    active: bool,
    last_message_time: i64,
    last_seen_time: i64,
};

pub const StoredMessage = struct {
    packet: Packet,
    timestamp: i64,
    message_id: []const u8,

    ///Messages for favourites are stored permanently
    is_for_favourite: bool,
};

pub const BluetoothMeshService = struct {
    pub const Self = @This();

    pub const service_uuid: []const u8 = "F47B5E2D-4A9E-4C5A-9B3F-8E1D2C3A4B5C";
    pub const characteristic_uuid: []const u8 = "A1B2C3D4-E5F6-4A5B-8C9D-0E1F2A3B4C5D";

    my_peer_id: u64 = undefined,
    connected_devices: ArrayListUnmanaged(u8) = undefined,
    peers: std.HashMap(u64, *Peer),
    message_queue: ArrayList(StoredMessage) = undefined,

    favorite_message_queue: StringHashMap(StoredMessage) = undefined, // Per-favorite message queues
    delivered_messages: StringHashMap(bool) = undefined, // Track delivered message IDs to prevent duplicates
    cached_messages_sent_to_peer: StringHashMap(bool) = undefined, // Track which peers have already received cached messages
    received_message_timestamps: StringHashMap(i64) = undefined, // Track timestamps of received messages for debugging
    recently_sent_messages: StringHashMap(bool) = undefined, // Short-term cache to prevent any duplicate sends

    pub fn init(allocator: Allocator) error{OutOfMemory}!BluetoothMeshService {
        // bitchat assigns a new random peer_id to a user
        // each time they startup the `BluetoothMeshService`
        seed();
        return .{
            .my_peer_id = random_u64(),
            .message_cache = try ArrayList(StoredMessage).initCapacity(allocator),
            .connected_devices = try ArrayListUnmanaged(Device).initCapacity(allocator, max_connected_devices),
            .peers = try HashMap(u64, Peer).init(allocator),
            .message_queue = try HashMap(u64, StoredMessage).init(allocator),
            .favourite_message_queue = try StringHashMap(StoredMessage).init(allocator),
            .delivered_messages = try HashMap(bool).init(allocator),
            .cached_messages_sent_to_peer = try HashMap(bool).init(allocator),
            .received_message_timestamps = try HashMap(i64).init(allocator),
            .recently_sent_messages = try StringHashMap(bool).init(allocator),
        };
    }

    pub fn deinit(self: *Self, allocator: Allocator) void {
        self.connected_devices.deinit(allocator);
        self.peers.deinit(allocator);
        self.message_queue.deinit(allocator);
        self.favorite_message_queue.deinit(allocator);
        self.delivered_messages.deinit(allocator);
        self.cached_messages_sent_to_peer.deinit(allocator);
        self.received_message_timestamps.deinit(allocator);
        self.recently_sent_messages.deinit(allocator);
    }

    fn startServices() void {
        // Starting services
        // Start both central and peripheral services
        //if centralManager?.state == .poweredOn {
        //    startScanning()
        //}
        //if peripheralManager?.state == .poweredOn {
        //    setupPeripheral()
        //    startAdvertising()
        //}

        // Send initial announces after services are ready
        //DispatchQueue.main.asyncAfter(deadline: .now() + 0.2) { [weak self] in
        //    self?.sendBroadcastAnnounce()
        //}

        // Setup battery optimizer
        //setupBatteryOptimizer()

        // Start cover traffic for privacy
        //startCoverTraffic()
    }

    pub fn cleanup(self: *Self) void {
        self.sendLeaveAnnouncement();

        // Give the leave message time to send. The app is likely
        // in the background by now, so its safe to pause.
        //Thread.sleep(forTimeInterval: 0.2)

        // First, disconnect all peripherals which will trigger disconnect delegates
        for (self.connected_devices) |device| {
            //for (_, peripheral) in connectedPeripherals {
            //centralManager?.cancelPeripheralConnection(peripheral)
            //self.device_manager.cancelDeviceConnection(device);
        }

        // Stop advertising
        //if peripheralManager?.isAdvertising == true {
        //    peripheralManager?.stopAdvertising()
        //}

        // Stop scanning
        //centralManager?.stopScan()

        // Remove all services - this will disconnect any connected centrals
        //if peripheralManager?.state == .poweredOn {
        //    peripheralManager?.removeAllServices()
        //}

    }

    fn startAdvertising() void {
        //guard peripheralManager?.state == .poweredOn else {
        //    return
        //}

        // Use generic advertising to avoid identification
        // No identifying prefixes or app names for activist safety

        // Only use allowed advertisement keys
        //advertisementData = [
        //    CBAdvertisementDataServiceUUIDsKey: [BluetoothMeshService.serviceUUID],
        // Use only peer ID without any identifying prefix
        //    CBAdvertisementDataLocalNameKey: myPeerID
        //]

        //isAdvertising = true
        //peripheralManager?.startAdvertising(advertisementData)
    }

    fn startScanning() void {
        //guard centralManager?.state == .poweredOn else {
        //    return
        //}

        // Enable duplicate detection for RSSI tracking
        //let scanOptions: [String: Any] = [
        //    CBCentralManagerScanOptionAllowDuplicatesKey: true
        //]

        //centralManager?.scanForPeripherals(
        //    withServices: [BluetoothMeshService.serviceUUID],
        //    options: scanOptions
        //)

        // Update scan parameters based on battery before starting
        //updateScanParametersForBattery()

        // Implement scan duty cycling for battery efficiency
        // TEMPORARILY DISABLED FOR DEBUGGING
        //scheduleScanDutyCycle()
    }

    pub fn sendBroadcastAnnounce(self: *Self) void {
        //assert let vm = delegate as? ChatViewModel else { return };

        const packet = Packet.init(
            .announce,
            self.my_peer_id,
            null,
            0,
            self.nickname,
            null,
            3,
        );

        // Initial send with random delay
        //let initialDelay = self.randomDelay()
        //DispatchQueue.main.asyncAfter(deadline: .now() + initialDelay) { [weak self] in
        //    self?.broadcastPacket(announcePacket)
        //}

        // Send multiple times for reliability with jittered delays
        //for baseDelay in [0.2, 0.5, 1.0] {
        //    let jitteredDelay = baseDelay + self.randomDelay()
        //    DispatchQueue.main.asyncAfter(deadline: .now() + jitteredDelay) { [weak self] in
        //        guard let self = self else { return }
        //        self.broadcastPacket(announcePacket)
        //    }
        //}
        self.broadcastPacket(packet);
    }

    //fn sendDeliveryAck(ack: DeliveryAck, recipient_id: u64) void {
    //}

    //fn sendReadReceipt(receipt: ReadReceipt, recipient_id: u64) void {
    //}

    pub fn broadcastPacket(self: *Self, packet: *Packet) void {
        //var buffer = try ArrayListUnmanaged(u8).initCapacit(bitchat.max_packet_size);
        //var data = try packet.write(&buffer);
        _ = packet;

        for (self.connected_devices) |device| {
            _ = device;
        }
    }
};

// Placeholder hard limits. Need to determine what defined
// specific behavious should occur when we hit the maximum
// values for a given device type.

pub const max_connected_devices: usize = 100;
pub const max_cached_messages: usize = 100;
pub const max_favourite_cached_messages: usize = 1000;
pub const max_stored_messages: usize = 1000000;

pub const std = @import("std");
pub const Allocator = std.mem.Allocator;
pub const ArrayList = std.ArrayList;
pub const ArrayListUnmanaged = std.ArrayListUnmanaged;
pub const HashMap = std.HashMap;
pub const StringHashMap = std.StringHashMap;

pub const bitchat = @import("bitchat");
pub const MessageType = bitchat.MessageType;
pub const Packet = bitchat.Packet;

const seed = @import("random.zig").seed();
const random_u64 = @import("random.zig").random_u64();
