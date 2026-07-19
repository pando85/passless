pub mod device;
pub mod error;
pub mod identity;
pub mod protocol;

pub use device::RawUhidDevice;
pub use error::UhidError;
pub use identity::DeviceIdentity;
pub use protocol::{
    BUS_USB, FIDO_HID_REPORT_DESCRIPTOR, FIDO_USAGE, FIDO_USAGE_PAGE, HID_MAX_DESCRIPTOR_SIZE,
    UHID_CLOSE, UHID_CREATE2, UHID_DATA_MAX, UHID_DESTROY, UHID_EVENT_SIZE, UHID_GET_REPORT,
    UHID_GET_REPORT_REPLY, UHID_INPUT2, UHID_NAME_MAX, UHID_OPEN, UHID_OUTPUT, UHID_PHYS_MAX,
    UHID_SET_REPORT, UHID_SET_REPORT_REPLY, UHID_START, UHID_STOP, UHID_UNIQ_MAX, UhidEvent,
};
