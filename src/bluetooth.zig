pub const Bluetooth = struct {
    /// The service we are advertising and seeking. A devie 'advertises'
    /// that it has a service (and a characteristic) at regular intervals
    /// and another device scans to 'discover' the advertising device.
    /// An service ID is usually a 128 bit UUID.
    service_id: []const u8,

    /// A service advertises contains 'characteristic.' Something that can
    /// be read or updated. A characteristic id can be 16 bytes or 6 bytes.
    characteristic_id: []const u8,

    /// Reports when bluetooth is available or not avaialble. Typically a
    /// user can turn bluetooth on or off. Monitor the status to know and
    /// provide feedback to the user.
    ///
    /// A device status may be on, off, unauthorised, resetting, or unknown.
    status: *fn (u8) void,

    /// Report discovery of a device advertising the service and characteristic
    /// id's that we are seeking.
    device_found: *fn (Device) void,

    /// A messae has been recieved for processing
    recieved_message: *fn ([]const u8, Device) void,

    pub fn init(
        service_id: []const u8,
        status: *fn (u8) void,
        device_found: *fn (Device) void,
        recieved_message: *fn ([]const u8) void,
    ) Bluetooth {
        return .{
            .service_id = service_id,
            .status = status,
            .device_found = device_found,
            .recieved_message = recieved_message,
        };
    }

    /// Start 'advertising' that this device is here, and intermittently
    /// scanning to 'discover' other devices. Use `shutdown` to stop
    /// advertising and discovering.
    pub fn startup(self: *Bluetooth) void {
        _ = self;
    }

    /// Stop 'advertising' and 'discovering' other devices. Use `startup`
    /// to restart advertising and discovering.
    pub fn shutdown(self: *Bluetooth) void {
        _ = self;
    }

    /// Share a message to the bluetooth service for delivery
    pub fn sendMessage(device: *Device, data: []const u8) void {
        _ = device;
        _ = data;
    }
};

pub const Device = struct {
    id: [6]u8,
    name: ?[]const u8,
    can_connect: bool,
    signal: u16,
};
