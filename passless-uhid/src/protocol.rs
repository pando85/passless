pub const UHID_DESTROY: u32 = 1;
pub const UHID_START: u32 = 2;
pub const UHID_STOP: u32 = 3;
pub const UHID_OPEN: u32 = 4;
pub const UHID_CLOSE: u32 = 5;
pub const UHID_OUTPUT: u32 = 6;
pub const UHID_GET_REPORT: u32 = 9;
pub const UHID_GET_REPORT_REPLY: u32 = 10;
pub const UHID_CREATE2: u32 = 11;
pub const UHID_INPUT2: u32 = 12;
pub const UHID_SET_REPORT: u32 = 13;
pub const UHID_SET_REPORT_REPLY: u32 = 14;

pub const BUS_USB: u16 = 0x03;

pub const FIDO_USAGE_PAGE: u16 = 0xF1D0;
pub const FIDO_USAGE: u16 = 0x01;

pub const HID_MAX_DESCRIPTOR_SIZE: usize = 4096;
pub const UHID_DATA_MAX: usize = 4096;

pub const UHID_EVENT_SIZE: usize = 4376;

pub const UHID_NAME_MAX: usize = 128;
pub const UHID_PHYS_MAX: usize = 64;
pub const UHID_UNIQ_MAX: usize = 64;

pub const FIDO_HID_REPORT_DESCRIPTOR: &[u8] = &[
    0x06, 0xD0, 0xF1, 0x09, 0x01, 0xA1, 0x01, 0x09, 0x20, 0x15, 0x00, 0x26, 0xFF, 0x00, 0x75, 0x08,
    0x95, 0x40, 0x81, 0x02, 0x09, 0x21, 0x15, 0x00, 0x26, 0xFF, 0x00, 0x75, 0x08, 0x95, 0x40, 0x91,
    0x02, 0xC0,
];

#[repr(C, packed)]
pub struct UhidCreate2Req {
    pub name: [u8; UHID_NAME_MAX],
    pub phys: [u8; UHID_PHYS_MAX],
    pub uniq: [u8; UHID_UNIQ_MAX],
    pub rd_size: u16,
    pub bus: u16,
    pub vendor: u32,
    pub product: u32,
    pub version: u32,
    pub country: u32,
    pub rd_data: [u8; HID_MAX_DESCRIPTOR_SIZE],
}

#[repr(C, packed)]
pub struct UhidOutputReq {
    pub data: [u8; UHID_DATA_MAX],
    pub size: u16,
    pub rtype: u8,
}

#[repr(C, packed)]
pub struct UhidInput2Req {
    pub size: u16,
    pub data: [u8; UHID_DATA_MAX],
}

#[repr(C, packed)]
pub struct UhidGetReportReq {
    pub id: u32,
    pub rnum: u8,
    pub rtype: u8,
}

#[repr(C, packed)]
pub struct UhidGetReportReplyReq {
    pub id: u32,
    pub err: u16,
    pub size: u16,
    pub data: [u8; UHID_DATA_MAX],
}

#[repr(C, packed)]
pub struct UhidSetReportReq {
    pub id: u32,
    pub rnum: u8,
    pub rtype: u8,
    pub size: u16,
    pub data: [u8; UHID_DATA_MAX],
}

#[repr(C, packed)]
pub struct UhidSetReportReplyReq {
    pub id: u32,
    pub err: u16,
}

#[repr(C, packed)]
pub struct UhidStartReq {
    pub dev_flags: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UhidEvent {
    Start {
        dev_flags: u64,
    },
    Stop,
    Open,
    Close,
    Output {
        data: Vec<u8>,
        rtype: u8,
    },
    GetReport {
        id: u32,
        rnum: u8,
        rtype: u8,
    },
    SetReport {
        id: u32,
        rnum: u8,
        rtype: u8,
        data: Vec<u8>,
    },
    Unknown(u32),
}

pub(crate) fn parse_event(event_type: u32, buffer: &[u8], n: usize) -> UhidEvent {
    match event_type {
        UHID_START => {
            let dev_flags = if n >= 12 {
                let mut bytes = [0u8; 8];
                bytes.copy_from_slice(&buffer[4..12]);
                u64::from_ne_bytes(bytes)
            } else {
                0
            };
            UhidEvent::Start { dev_flags }
        }
        UHID_STOP => UhidEvent::Stop,
        UHID_OPEN => UhidEvent::Open,
        UHID_CLOSE => UhidEvent::Close,
        UHID_OUTPUT => {
            let output_start = 4;
            let data_offset = output_start;
            let size_offset = data_offset + UHID_DATA_MAX;
            let rtype_offset = size_offset + 2;

            if n > rtype_offset {
                let mut size_bytes = [0u8; 2];
                size_bytes.copy_from_slice(&buffer[size_offset..size_offset + 2]);
                let size = u16::from_ne_bytes(size_bytes) as usize;
                let rtype = buffer[rtype_offset];
                let data_end = (data_offset + size).min(data_offset + UHID_DATA_MAX).min(n);
                let data = if data_end > data_offset {
                    buffer[data_offset..data_end].to_vec()
                } else {
                    Vec::new()
                };
                UhidEvent::Output { data, rtype }
            } else {
                UhidEvent::Output {
                    data: Vec::new(),
                    rtype: 0,
                }
            }
        }
        UHID_GET_REPORT => {
            let req_start = 4;
            let id_offset = req_start;
            let rnum_offset = id_offset + 4;
            let rtype_offset = rnum_offset + 1;

            if n > rtype_offset {
                let mut id_bytes = [0u8; 4];
                id_bytes.copy_from_slice(&buffer[id_offset..id_offset + 4]);
                let id = u32::from_ne_bytes(id_bytes);
                let rnum = buffer[rnum_offset];
                let rtype = buffer[rtype_offset];
                UhidEvent::GetReport { id, rnum, rtype }
            } else {
                UhidEvent::Unknown(UHID_GET_REPORT)
            }
        }
        UHID_SET_REPORT => {
            let req_start = 4;
            let id_offset = req_start;
            let rnum_offset = id_offset + 4;
            let rtype_offset = rnum_offset + 1;
            let size_offset = rtype_offset + 1;
            let data_offset = size_offset + 2;

            if n > size_offset + 1 {
                let mut id_bytes = [0u8; 4];
                id_bytes.copy_from_slice(&buffer[id_offset..id_offset + 4]);
                let id = u32::from_ne_bytes(id_bytes);
                let rnum = buffer[rnum_offset];
                let rtype = buffer[rtype_offset];
                let mut size_bytes = [0u8; 2];
                size_bytes.copy_from_slice(&buffer[size_offset..size_offset + 2]);
                let size = u16::from_ne_bytes(size_bytes) as usize;
                let data_end = (data_offset + size).min(data_offset + UHID_DATA_MAX).min(n);
                let data = if data_end > data_offset {
                    buffer[data_offset..data_end].to_vec()
                } else {
                    Vec::new()
                };
                UhidEvent::SetReport {
                    id,
                    rnum,
                    rtype,
                    data,
                }
            } else {
                UhidEvent::Unknown(UHID_SET_REPORT)
            }
        }
        other => UhidEvent::Unknown(other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uhid_create2_req_size() {
        assert_eq!(
            std::mem::size_of::<UhidCreate2Req>(),
            4372,
            "uhid_create2_req must be 4372 bytes per linux/uhid.h"
        );
    }

    #[test]
    fn test_uhid_output_req_size() {
        assert_eq!(
            std::mem::size_of::<UhidOutputReq>(),
            4099,
            "uhid_output_req must be 4099 bytes per linux/uhid.h"
        );
    }

    #[test]
    fn test_uhid_output_req_field_offsets() {
        let req = UhidOutputReq {
            data: [0u8; UHID_DATA_MAX],
            size: 0xABCD,
            rtype: 0x42,
        };
        let ptr = &req as *const _ as *const u8;
        unsafe {
            let size_ptr = ptr.add(UHID_DATA_MAX);
            let mut size_bytes = [0u8; 2];
            size_bytes.copy_from_slice(std::slice::from_raw_parts(size_ptr, 2));
            assert_eq!(u16::from_ne_bytes(size_bytes), 0xABCD);

            let rtype_ptr = ptr.add(UHID_DATA_MAX + 2);
            assert_eq!(*rtype_ptr, 0x42);
        }
    }

    #[test]
    fn test_uhid_input2_req_size() {
        assert_eq!(
            std::mem::size_of::<UhidInput2Req>(),
            4098,
            "uhid_input2_req must be 4098 bytes per linux/uhid.h"
        );
    }

    #[test]
    fn test_uhid_get_report_req_size() {
        assert_eq!(
            std::mem::size_of::<UhidGetReportReq>(),
            6,
            "uhid_get_report_req must be 6 bytes per linux/uhid.h"
        );
    }

    #[test]
    fn test_uhid_get_report_reply_req_size() {
        assert_eq!(
            std::mem::size_of::<UhidGetReportReplyReq>(),
            4104,
            "uhid_get_report_reply_req must be 4104 bytes per linux/uhid.h"
        );
    }

    #[test]
    fn test_uhid_set_report_req_size() {
        assert_eq!(
            std::mem::size_of::<UhidSetReportReq>(),
            4104,
            "uhid_set_report_req must be 4104 bytes per linux/uhid.h"
        );
    }

    #[test]
    fn test_uhid_set_report_reply_req_size() {
        assert_eq!(
            std::mem::size_of::<UhidSetReportReplyReq>(),
            6,
            "uhid_set_report_reply_req must be 6 bytes per linux/uhid.h"
        );
    }

    #[test]
    fn test_uhid_start_req_size() {
        assert_eq!(
            std::mem::size_of::<UhidStartReq>(),
            8,
            "uhid_start_req must be 8 bytes per linux/uhid.h"
        );
    }

    #[test]
    fn test_uhid_event_size() {
        assert_eq!(
            UHID_EVENT_SIZE, 4376,
            "uhid_event must be 4376 bytes (4 + max union member 4372)"
        );
    }

    #[test]
    fn test_uhid_event_size_is_type_plus_largest_union() {
        let largest = std::mem::size_of::<UhidCreate2Req>();
        assert_eq!(UHID_EVENT_SIZE, 4 + largest);
    }

    #[test]
    fn test_fido_report_descriptor_length() {
        assert_eq!(FIDO_HID_REPORT_DESCRIPTOR.len(), 34);
    }

    #[test]
    fn test_parse_event_start() {
        let mut buf = [0u8; UHID_EVENT_SIZE];
        buf[..4].copy_from_slice(&UHID_START.to_ne_bytes());
        buf[4..12].copy_from_slice(&0u64.to_ne_bytes());
        let event = parse_event(UHID_START, &buf, UHID_EVENT_SIZE);
        assert_eq!(event, UhidEvent::Start { dev_flags: 0 });
    }

    #[test]
    fn test_parse_event_start_with_flags() {
        let mut buf = [0u8; UHID_EVENT_SIZE];
        buf[..4].copy_from_slice(&UHID_START.to_ne_bytes());
        buf[4..12].copy_from_slice(&42u64.to_ne_bytes());
        let event = parse_event(UHID_START, &buf, UHID_EVENT_SIZE);
        assert_eq!(event, UhidEvent::Start { dev_flags: 42 });
    }

    #[test]
    fn test_parse_event_stop() {
        let buf = [0u8; UHID_EVENT_SIZE];
        assert_eq!(parse_event(UHID_STOP, &buf, 4), UhidEvent::Stop);
    }

    #[test]
    fn test_parse_event_open() {
        let buf = [0u8; UHID_EVENT_SIZE];
        assert_eq!(parse_event(UHID_OPEN, &buf, 4), UhidEvent::Open);
    }

    #[test]
    fn test_parse_event_close() {
        let buf = [0u8; UHID_EVENT_SIZE];
        assert_eq!(parse_event(UHID_CLOSE, &buf, 4), UhidEvent::Close);
    }

    #[test]
    fn test_parse_event_output() {
        let mut buf = [0u8; UHID_EVENT_SIZE];
        buf[..4].copy_from_slice(&UHID_OUTPUT.to_ne_bytes());
        buf[4] = 0xAA;
        buf[5] = 0xBB;
        buf[6] = 0xCC;
        let size_offset = 4 + UHID_DATA_MAX;
        buf[size_offset..size_offset + 2].copy_from_slice(&3u16.to_ne_bytes());
        buf[size_offset + 2] = 0x02;
        let event = parse_event(UHID_OUTPUT, &buf, UHID_EVENT_SIZE);
        assert_eq!(
            event,
            UhidEvent::Output {
                data: vec![0xAA, 0xBB, 0xCC],
                rtype: 0x02,
            }
        );
    }

    #[test]
    fn test_parse_event_output_short_buffer() {
        let buf = [0u8; 4];
        let event = parse_event(UHID_OUTPUT, &buf, 4);
        assert_eq!(
            event,
            UhidEvent::Output {
                data: Vec::new(),
                rtype: 0,
            }
        );
    }

    #[test]
    fn test_parse_event_get_report() {
        let mut buf = [0u8; UHID_EVENT_SIZE];
        buf[..4].copy_from_slice(&UHID_GET_REPORT.to_ne_bytes());
        buf[4..8].copy_from_slice(&7u32.to_ne_bytes());
        buf[8] = 0x01;
        buf[9] = 0x03;
        let event = parse_event(UHID_GET_REPORT, &buf, UHID_EVENT_SIZE);
        assert_eq!(
            event,
            UhidEvent::GetReport {
                id: 7,
                rnum: 0x01,
                rtype: 0x03,
            }
        );
    }

    #[test]
    fn test_parse_event_set_report() {
        let mut buf = [0u8; UHID_EVENT_SIZE];
        buf[..4].copy_from_slice(&UHID_SET_REPORT.to_ne_bytes());
        buf[4..8].copy_from_slice(&99u32.to_ne_bytes());
        buf[8] = 0x05;
        buf[9] = 0x01;
        let size_offset = 10;
        buf[size_offset..size_offset + 2].copy_from_slice(&2u16.to_ne_bytes());
        buf[12] = 0xDE;
        buf[13] = 0xAD;
        let event = parse_event(UHID_SET_REPORT, &buf, UHID_EVENT_SIZE);
        assert_eq!(
            event,
            UhidEvent::SetReport {
                id: 99,
                rnum: 0x05,
                rtype: 0x01,
                data: vec![0xDE, 0xAD],
            }
        );
    }

    #[test]
    fn test_parse_event_unknown() {
        assert_eq!(parse_event(99, &[0; 64], 4), UhidEvent::Unknown(99));
    }

    #[test]
    fn test_event_constants_match_kernel_enum() {
        assert_eq!(UHID_DESTROY, 1);
        assert_eq!(UHID_START, 2);
        assert_eq!(UHID_STOP, 3);
        assert_eq!(UHID_OPEN, 4);
        assert_eq!(UHID_CLOSE, 5);
        assert_eq!(UHID_OUTPUT, 6);
        assert_eq!(UHID_GET_REPORT, 9);
        assert_eq!(UHID_GET_REPORT_REPLY, 10);
        assert_eq!(UHID_CREATE2, 11);
        assert_eq!(UHID_INPUT2, 12);
        assert_eq!(UHID_SET_REPORT, 13);
        assert_eq!(UHID_SET_REPORT_REPLY, 14);
    }

    #[test]
    fn test_event_constants_are_distinct() {
        let events = [
            UHID_DESTROY,
            UHID_START,
            UHID_STOP,
            UHID_OPEN,
            UHID_CLOSE,
            UHID_OUTPUT,
            UHID_GET_REPORT,
            UHID_GET_REPORT_REPLY,
            UHID_CREATE2,
            UHID_INPUT2,
            UHID_SET_REPORT,
            UHID_SET_REPORT_REPLY,
        ];
        for (i, a) in events.iter().enumerate() {
            for (j, b) in events.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b, "event constants {} and {} collide", i, j);
                }
            }
        }
    }
}
