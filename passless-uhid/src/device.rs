use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::io::{AsRawFd, RawFd};

use crate::error::UhidError;
use crate::identity::DeviceIdentity;
use crate::protocol::*;

const START_TIMEOUT_ITERS: u32 = 50;
const START_POLL_INTERVAL_MS: u64 = 100;
const DRAIN_MAX_EVENTS: usize = 256;

pub struct RawUhidDevice {
    file: File,
    identity: DeviceIdentity,
    started: bool,
}

impl RawUhidDevice {
    pub fn open() -> Result<Self, UhidError> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/uhid")
            .map_err(UhidError::Open)?;

        Ok(Self {
            file,
            identity: DeviceIdentity::default(),
            started: false,
        })
    }

    pub fn create(identity: DeviceIdentity) -> Result<Self, UhidError> {
        let mut device = Self::open()?;
        device.identity = identity;
        device.send_create2(FIDO_HID_REPORT_DESCRIPTOR)?;
        device.wait_for_start()?;
        Ok(device)
    }

    pub fn create_with_descriptor(
        identity: DeviceIdentity,
        descriptor: &[u8],
    ) -> Result<Self, UhidError> {
        let mut device = Self::open()?;
        device.identity = identity;
        device.send_create2(descriptor)?;
        device.wait_for_start()?;
        Ok(device)
    }

    fn send_create2(&mut self, rd: &[u8]) -> Result<(), UhidError> {
        self.identity.validate()?;

        if rd.len() > HID_MAX_DESCRIPTOR_SIZE {
            return Err(UhidError::DescriptorTooLarge(rd.len()));
        }

        let mut buf = [0u8; UHID_EVENT_SIZE];
        buf[0..4].copy_from_slice(&UHID_CREATE2.to_ne_bytes());

        let payload = &mut buf[4..4 + std::mem::size_of::<UhidCreate2Req>()];

        let name_bytes = self.identity.name.as_bytes();
        let name_len = name_bytes.len().min(UHID_NAME_MAX);
        payload[..name_len].copy_from_slice(&name_bytes[..name_len]);

        let phys_start = UHID_NAME_MAX;
        let phys_bytes = self.identity.phys.as_bytes();
        let phys_len = phys_bytes.len().min(UHID_PHYS_MAX);
        payload[phys_start..phys_start + phys_len].copy_from_slice(&phys_bytes[..phys_len]);

        let uniq_start = phys_start + UHID_PHYS_MAX;
        let uniq_bytes = self.identity.uniq.as_bytes();
        let uniq_len = uniq_bytes.len().min(UHID_UNIQ_MAX);
        payload[uniq_start..uniq_start + uniq_len].copy_from_slice(&uniq_bytes[..uniq_len]);

        let rd_size_offset = uniq_start + UHID_UNIQ_MAX;
        payload[rd_size_offset..rd_size_offset + 2]
            .copy_from_slice(&(rd.len() as u16).to_ne_bytes());

        let bus_offset = rd_size_offset + 2;
        payload[bus_offset..bus_offset + 2].copy_from_slice(&BUS_USB.to_ne_bytes());

        let vendor_offset = bus_offset + 2;
        payload[vendor_offset..vendor_offset + 4]
            .copy_from_slice(&self.identity.vendor.to_ne_bytes());

        let product_offset = vendor_offset + 4;
        payload[product_offset..product_offset + 4]
            .copy_from_slice(&self.identity.product.to_ne_bytes());

        let version_offset = product_offset + 4;
        payload[version_offset..version_offset + 4]
            .copy_from_slice(&self.identity.version.to_ne_bytes());

        let country_offset = version_offset + 4;
        payload[country_offset..country_offset + 4].copy_from_slice(&0u32.to_ne_bytes());

        let rd_data_offset = country_offset + 4;
        payload[rd_data_offset..rd_data_offset + rd.len()].copy_from_slice(rd);

        self.write_event(&buf).map_err(UhidError::Create2)
    }

    fn wait_for_start(&mut self) -> Result<(), UhidError> {
        let was_nonblocking = self.is_nonblocking()?;
        if !was_nonblocking {
            self.set_nonblocking(true)?;
        }

        let result = self.wait_for_start_inner();

        if !was_nonblocking {
            self.set_nonblocking(false)?;
        }

        result
    }

    fn wait_for_start_inner(&mut self) -> Result<(), UhidError> {
        let mut buf = [0u8; UHID_EVENT_SIZE];

        for _ in 0..START_TIMEOUT_ITERS {
            match self.read_event_from_fd(&mut buf) {
                Ok(Some(UhidEvent::Open)) | Ok(Some(UhidEvent::Start { .. })) => {
                    self.started = true;
                    return Ok(());
                }
                Ok(_) => {
                    std::thread::sleep(std::time::Duration::from_millis(START_POLL_INTERVAL_MS));
                }
                Err(e) => return Err(e),
            }
        }

        Err(UhidError::StartTimeout)
    }

    fn is_nonblocking(&self) -> Result<bool, UhidError> {
        let fd = self.file.as_raw_fd();
        let flags = Self::fcntl_get_flags(fd)?;
        Ok((flags & libc::O_NONBLOCK) != 0)
    }

    fn fcntl_get_flags(fd: RawFd) -> Result<i32, UhidError> {
        let flags = unsafe {
            // SAFETY: fd is a valid open file descriptor from File.
            // F_GETFL takes no third argument.
            libc::fcntl(fd, libc::F_GETFL)
        };
        if flags < 0 {
            return Err(UhidError::Fcntl("F_GETFL".to_string()));
        }
        Ok(flags)
    }

    fn fcntl_set_flags(fd: RawFd, flags: i32) -> Result<(), UhidError> {
        let ret = unsafe {
            // SAFETY: fd is a valid open file descriptor from File.
            // F_SETFL with O_NONBLOCK is a standard flags modification.
            libc::fcntl(fd, libc::F_SETFL, flags)
        };
        if ret < 0 {
            return Err(UhidError::Fcntl("F_SETFL".to_string()));
        }
        Ok(())
    }

    pub fn set_nonblocking(&self, nonblocking: bool) -> Result<(), UhidError> {
        let fd = self.file.as_raw_fd();
        let flags = Self::fcntl_get_flags(fd)?;
        let new_flags = if nonblocking {
            flags | libc::O_NONBLOCK
        } else {
            flags & !libc::O_NONBLOCK
        };
        Self::fcntl_set_flags(fd, new_flags)
    }

    pub fn destroy(&mut self) -> Result<(), UhidError> {
        let mut buf = [0u8; UHID_EVENT_SIZE];
        buf[0..4].copy_from_slice(&UHID_DESTROY.to_ne_bytes());

        self.write_event(&buf).map_err(UhidError::Destroy)?;

        self.started = false;
        Ok(())
    }

    pub fn drain(&mut self) -> Result<Vec<UhidEvent>, UhidError> {
        let was_nonblocking = self.is_nonblocking()?;
        if !was_nonblocking {
            self.set_nonblocking(true)?;
        }

        let mut events = Vec::new();
        let mut buf = [0u8; UHID_EVENT_SIZE];

        let result = (|| {
            for _ in 0..DRAIN_MAX_EVENTS {
                match self.read_event_from_fd(&mut buf)? {
                    Some(event) => events.push(event),
                    None => break,
                }
            }
            Ok::<(), UhidError>(())
        })();

        if !was_nonblocking {
            self.set_nonblocking(false)?;
        }

        result?;
        Ok(events)
    }

    pub fn write_packet(&mut self, data: &[u8]) -> Result<(), UhidError> {
        if data.len() > UHID_DATA_MAX {
            return Err(UhidError::PacketTooLarge(data.len()));
        }

        let mut buf = [0u8; UHID_EVENT_SIZE];
        buf[0..4].copy_from_slice(&UHID_INPUT2.to_ne_bytes());

        let payload = &mut buf[4..4 + std::mem::size_of::<UhidInput2Req>()];
        payload[0..2].copy_from_slice(&(data.len() as u16).to_ne_bytes());
        payload[2..2 + data.len()].copy_from_slice(data);

        self.write_event(&buf).map_err(UhidError::Input2)
    }

    pub fn send_get_report_reply(
        &mut self,
        id: u32,
        err: u16,
        data: &[u8],
    ) -> Result<(), UhidError> {
        if data.len() > UHID_DATA_MAX {
            return Err(UhidError::PacketTooLarge(data.len()));
        }

        let mut buf = [0u8; UHID_EVENT_SIZE];
        buf[0..4].copy_from_slice(&UHID_GET_REPORT_REPLY.to_ne_bytes());

        let payload = &mut buf[4..4 + std::mem::size_of::<UhidGetReportReplyReq>()];
        payload[0..4].copy_from_slice(&id.to_ne_bytes());
        payload[4..6].copy_from_slice(&err.to_ne_bytes());
        payload[6..8].copy_from_slice(&(data.len() as u16).to_ne_bytes());
        payload[8..8 + data.len()].copy_from_slice(data);

        self.write_event(&buf).map_err(UhidError::GetReportReply)
    }

    pub fn send_set_report_reply(&mut self, id: u32, err: u16) -> Result<(), UhidError> {
        let mut buf = [0u8; UHID_EVENT_SIZE];
        buf[0..4].copy_from_slice(&UHID_SET_REPORT_REPLY.to_ne_bytes());

        let payload = &mut buf[4..4 + std::mem::size_of::<UhidSetReportReplyReq>()];
        payload[0..4].copy_from_slice(&id.to_ne_bytes());
        payload[4..6].copy_from_slice(&err.to_ne_bytes());

        self.write_event(&buf).map_err(UhidError::SetReportReply)
    }

    pub fn read_event(&mut self) -> Result<Option<UhidEvent>, UhidError> {
        let mut buf = [0u8; UHID_EVENT_SIZE];
        self.read_event_from_fd(&mut buf)
    }

    fn read_event_from_fd(
        &self,
        buf: &mut [u8; UHID_EVENT_SIZE],
    ) -> Result<Option<UhidEvent>, UhidError> {
        let fd = self.file.as_raw_fd();
        let n = unsafe {
            // SAFETY: fd is a valid open file descriptor. buf points to a
            // UHID_EVENT_SIZE-byte stack buffer which is the exact kernel
            // struct uhid_event size. The kernel will write at most
            // UHID_EVENT_SIZE bytes.
            libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len())
        };

        if n < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::WouldBlock {
                return Ok(None);
            }
            return Err(UhidError::Read(err));
        }

        let n = n as usize;
        if n < 4 {
            return Ok(None);
        }

        let event_type = u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]);
        Ok(Some(parse_event(event_type, buf, n)))
    }

    fn write_event(&self, buf: &[u8; UHID_EVENT_SIZE]) -> Result<(), io::Error> {
        let fd = self.file.as_raw_fd();
        let ret = unsafe {
            // SAFETY: fd is a valid open file descriptor. buf is a
            // UHID_EVENT_SIZE-byte aligned stack buffer containing a valid
            // struct uhid_event layout. We issue a single write(2) syscall
            // to ensure the kernel receives the complete event atomically.
            libc::write(fd, buf.as_ptr() as *const libc::c_void, buf.len())
        };

        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        let written = ret as usize;
        if written != buf.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                format!("short write: {} of {} bytes", written, buf.len()),
            ));
        }

        Ok(())
    }

    pub fn is_started(&self) -> bool {
        self.started
    }

    pub fn identity(&self) -> &DeviceIdentity {
        &self.identity
    }

    pub fn as_raw_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }
}

impl Drop for RawUhidDevice {
    fn drop(&mut self) {
        if self.started {
            let _ = self.destroy();
        }
    }
}
