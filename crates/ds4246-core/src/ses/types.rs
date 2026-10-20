use serde::Serialize;

/// SES-3 element type codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub struct ElementType(pub u8);

impl ElementType {
    pub const UNSPECIFIED: u8 = 0x00;
    pub const DEVICE_SLOT: u8 = 0x01;
    pub const POWER_SUPPLY: u8 = 0x02;
    pub const COOLING: u8 = 0x03;
    pub const TEMPERATURE: u8 = 0x04;
    pub const DOOR: u8 = 0x05;
    pub const AUDIBLE_ALARM: u8 = 0x06;
    pub const ESC_ELECTRONICS: u8 = 0x07;
    pub const SCC_ELECTRONICS: u8 = 0x08;
    pub const NV_CACHE: u8 = 0x09;
    pub const INVALID_OP: u8 = 0x0A;
    pub const UPS: u8 = 0x0B;
    pub const DISPLAY: u8 = 0x0C;
    pub const KEYPAD: u8 = 0x0D;
    pub const ENCLOSURE: u8 = 0x0E;
    pub const SCSI_PORT_XCVR: u8 = 0x0F;
    pub const LANGUAGE: u8 = 0x10;
    pub const COMM_PORT: u8 = 0x11;
    pub const VOLTAGE: u8 = 0x12;
    pub const CURRENT: u8 = 0x13;
    pub const SCSI_TARGET_PORT: u8 = 0x14;
    pub const SCSI_INITIATOR_PORT: u8 = 0x15;
    pub const SIMPLE_SUBENCLOSURE: u8 = 0x16;
    pub const ARRAY_DEVICE_SLOT: u8 = 0x17;
    pub const SAS_EXPANDER: u8 = 0x18;
    pub const SAS_CONNECTOR: u8 = 0x19;

    pub fn is_slot(self) -> bool {
        self.0 == Self::DEVICE_SLOT || self.0 == Self::ARRAY_DEVICE_SLOT
    }

    /// Element types that may carry additional element status (page 0x0A).
    pub fn has_addl_status(self) -> bool {
        matches!(
            self.0,
            Self::DEVICE_SLOT
                | Self::ARRAY_DEVICE_SLOT
                | Self::SAS_EXPANDER
                | Self::SCSI_INITIATOR_PORT
                | Self::SCSI_TARGET_PORT
                | Self::ESC_ELECTRONICS
        )
    }
}

pub fn element_type_name(t: u8) -> &'static str {
    match t {
        0x00 => "Unspecified",
        0x01 => "Device slot",
        0x02 => "Power supply",
        0x03 => "Cooling",
        0x04 => "Temperature sensor",
        0x05 => "Door",
        0x06 => "Audible alarm",
        0x07 => "Enclosure services controller electronics",
        0x08 => "SCC controller electronics",
        0x09 => "Nonvolatile cache",
        0x0A => "Invalid operation reason",
        0x0B => "Uninterruptible power supply",
        0x0C => "Display",
        0x0D => "Key pad entry",
        0x0E => "Enclosure",
        0x0F => "SCSI port/transceiver",
        0x10 => "Language",
        0x11 => "Communication port",
        0x12 => "Voltage sensor",
        0x13 => "Current sensor",
        0x14 => "SCSI target port",
        0x15 => "SCSI initiator port",
        0x16 => "Simple subenclosure",
        0x17 => "Array device slot",
        0x18 => "SAS expander",
        0x19 => "SAS connector",
        0x80..=0xFF => "Vendor specific",
        _ => "Reserved",
    }
}

/// Short label used in the UI ("Fan", "PSU", ...).
pub fn element_short_name(t: u8) -> &'static str {
    match t {
        0x01 | 0x17 => "Bay",
        0x02 => "PSU",
        0x03 => "Fan",
        0x04 => "Temp",
        0x06 => "Alarm",
        0x07 => "IOM",
        0x0C => "Display",
        0x0E => "Enclosure",
        0x12 => "Voltage",
        0x13 => "Current",
        0x18 => "Expander",
        0x19 => "Connector",
        _ => element_type_name(t),
    }
}

pub fn page_name(p: u8) -> &'static str {
    match p {
        0x00 => "Supported diagnostic pages",
        0x01 => "Configuration",
        0x02 => "Enclosure status",
        0x03 => "Help text",
        0x04 => "String in",
        0x05 => "Threshold in",
        0x06 => "Array status (obsolete)",
        0x07 => "Element descriptor",
        0x08 => "Short enclosure status",
        0x09 => "Enclosure busy",
        0x0A => "Additional element status",
        0x0B => "Subenclosure help text",
        0x0C => "Subenclosure string in",
        0x0D => "Supported SES diagnostic pages",
        0x0E => "Download microcode status",
        0x0F => "Subenclosure nickname status",
        0x10..=0x1F => "Vendor specific (SES)",
        0x3F => "Protocol specific",
        0x40 => "Translate address",
        0x41 => "Device status",
        0x42 => "Rebuild assist",
        0x80..=0xFF => "Vendor specific",
        _ => "Reserved",
    }
}

/// True for pages we don't have a standard decoder for — reverse engineering targets.
pub fn is_vendor_page(p: u8) -> bool {
    (0x10..=0x1F).contains(&p) || p >= 0x80
}
