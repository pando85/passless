use soft_fido2_transport::{CommandHandler, CtapHidHandler, Packet, UhidDevice};

#[cfg(feature = "agent")]
use passless_uhid::{RawUhidDevice, UhidEvent};

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use log::{debug, error, info};

#[derive(Debug, Clone)]
pub enum WorkerError {
    Read(String),
    Write(String),
}

impl std::fmt::Display for WorkerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WorkerError::Read(msg) => write!(f, "read error: {}", msg),
            WorkerError::Write(msg) => write!(f, "write error: {}", msg),
        }
    }
}

impl std::error::Error for WorkerError {}

pub enum WorkerOutcome {
    Clean,
    Error(WorkerError),
    Panicked,
}

#[cfg(feature = "agent")]
pub enum JoinOutcome {
    Finished(WorkerOutcome),
    TimedOut,
}

pub trait HidEndpoint: Send {
    fn read_packet(&mut self, buffer: &mut [u8; 64]) -> Result<Option<usize>, WorkerError>;
    fn write_packet(&mut self, data: &[u8; 64]) -> Result<(), WorkerError>;
}

impl HidEndpoint for Box<dyn HidEndpoint> {
    fn read_packet(&mut self, buffer: &mut [u8; 64]) -> Result<Option<usize>, WorkerError> {
        (**self).read_packet(buffer)
    }

    fn write_packet(&mut self, data: &[u8; 64]) -> Result<(), WorkerError> {
        (**self).write_packet(data)
    }
}

pub struct UhidEndpoint(UhidDevice);

impl UhidEndpoint {
    pub fn new(device: UhidDevice) -> Self {
        Self(device)
    }
}

impl HidEndpoint for UhidEndpoint {
    fn read_packet(&mut self, buffer: &mut [u8; 64]) -> Result<Option<usize>, WorkerError> {
        self.0
            .read_packet(buffer)
            .map_err(|e| WorkerError::Read(format!("{:?}", e)))
    }

    fn write_packet(&mut self, data: &[u8; 64]) -> Result<(), WorkerError> {
        self.0
            .write_packet(data)
            .map_err(|e| WorkerError::Write(format!("{:?}", e)))
    }
}

#[cfg(feature = "agent")]
pub struct RawUhidEndpoint(RawUhidDevice);

#[cfg(feature = "agent")]
impl RawUhidEndpoint {
    pub fn new_nonblocking(device: RawUhidDevice) -> Self {
        let _ = device.set_nonblocking(true);
        Self(device)
    }
}

#[cfg(feature = "agent")]
impl HidEndpoint for RawUhidEndpoint {
    fn read_packet(&mut self, buffer: &mut [u8; 64]) -> Result<Option<usize>, WorkerError> {
        loop {
            match self.0.read_event() {
                Ok(Some(UhidEvent::Output { data, .. })) => {
                    if data.len() == 65 && data[0] == 0x00 {
                        buffer[..64].copy_from_slice(&data[1..65]);
                        return Ok(Some(64));
                    } else if data.len() <= 64 {
                        let len = data.len();
                        buffer[..len].copy_from_slice(&data[..len]);
                        return Ok(Some(len));
                    }
                    continue;
                }
                Ok(Some(_)) => continue,
                Ok(None) => return Ok(None),
                Err(e) => return Err(WorkerError::Read(format!("{:?}", e))),
            }
        }
    }

    fn write_packet(&mut self, data: &[u8; 64]) -> Result<(), WorkerError> {
        self.0
            .write_packet(data)
            .map_err(|e| WorkerError::Write(format!("{:?}", e)))
    }
}

#[derive(Clone)]
pub struct WorkerConfig {
    pub poll_interval: Duration,
    pub cache_cleanup_interval: Duration,
}

impl Default for WorkerConfig {
    fn default() -> Self {
        Self {
            poll_interval: Duration::from_millis(10),
            cache_cleanup_interval: Duration::from_secs(5),
        }
    }
}

pub struct WorkerHandle {
    cancel: Arc<AtomicBool>,
    thread: Option<JoinHandle<Result<(), WorkerError>>>,
    pending_rx: Option<mpsc::Receiver<WorkerOutcome>>,
}

impl WorkerHandle {
    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::Relaxed);
    }

    #[cfg(feature = "agent")]
    pub fn join_timeout(&mut self, timeout: Duration) -> JoinOutcome {
        if let Some(rx) = self.pending_rx.take() {
            return match rx.recv_timeout(timeout) {
                Ok(outcome) => JoinOutcome::Finished(outcome),
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    self.pending_rx = Some(rx);
                    JoinOutcome::TimedOut
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    JoinOutcome::Finished(WorkerOutcome::Clean)
                }
            };
        }

        let thread = match self.thread.take() {
            Some(t) => t,
            None => return JoinOutcome::Finished(WorkerOutcome::Clean),
        };

        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let result = match thread.join() {
                Ok(Ok(())) => WorkerOutcome::Clean,
                Ok(Err(e)) => WorkerOutcome::Error(e),
                Err(_) => WorkerOutcome::Panicked,
            };
            let _ = tx.send(result);
        });

        match rx.recv_timeout(timeout) {
            Ok(outcome) => JoinOutcome::Finished(outcome),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                self.pending_rx = Some(rx);
                JoinOutcome::TimedOut
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                JoinOutcome::Finished(WorkerOutcome::Clean)
            }
        }
    }

    #[cfg(feature = "agent")]
    pub fn try_join(&mut self) -> Option<WorkerOutcome> {
        if let Some(rx) = self.pending_rx.take() {
            return match rx.try_recv() {
                Ok(outcome) => Some(outcome),
                Err(mpsc::TryRecvError::Empty) => {
                    self.pending_rx = Some(rx);
                    None
                }
                Err(mpsc::TryRecvError::Disconnected) => Some(WorkerOutcome::Clean),
            };
        }

        let thread = match self.thread.take() {
            Some(t) => t,
            None => return Some(WorkerOutcome::Clean),
        };

        if !thread.is_finished() {
            self.thread = Some(thread);
            return None;
        }

        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let result = match thread.join() {
                Ok(Ok(())) => WorkerOutcome::Clean,
                Ok(Err(e)) => WorkerOutcome::Error(e),
                Err(_) => WorkerOutcome::Panicked,
            };
            let _ = tx.send(result);
        });

        match rx.try_recv() {
            Ok(outcome) => Some(outcome),
            Err(mpsc::TryRecvError::Empty) => {
                self.pending_rx = Some(rx);
                None
            }
            Err(mpsc::TryRecvError::Disconnected) => Some(WorkerOutcome::Clean),
        }
    }

    pub fn join(mut self) -> WorkerOutcome {
        if let Some(rx) = self.pending_rx.take() {
            return rx.recv().unwrap_or(WorkerOutcome::Clean);
        }

        let thread = match self.thread.take() {
            Some(t) => t,
            None => return WorkerOutcome::Clean,
        };
        match thread.join() {
            Ok(Ok(())) => WorkerOutcome::Clean,
            Ok(Err(e)) => WorkerOutcome::Error(e),
            Err(_) => WorkerOutcome::Panicked,
        }
    }
}

impl Drop for WorkerHandle {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        if let Some(rx) = self.pending_rx.take() {
            let _ = rx.recv();
        }
    }
}

pub struct WorkerHooks {
    pub on_response_sent: Option<Box<dyn FnMut() + Send + 'static>>,
}

impl WorkerHooks {
    pub fn noop() -> Self {
        Self {
            on_response_sent: None,
        }
    }
}

pub fn spawn<E, H>(
    endpoint: E,
    ctaphid: CtapHidHandler<H>,
    config: WorkerConfig,
    cancel: Arc<AtomicBool>,
    cache_cleanup: Box<dyn FnMut() + Send + 'static>,
) -> WorkerHandle
where
    E: HidEndpoint + 'static,
    H: CommandHandler + Send + 'static,
{
    spawn_with_hooks(
        endpoint,
        ctaphid,
        config,
        cancel,
        cache_cleanup,
        WorkerHooks::noop(),
    )
}

pub fn spawn_with_hooks<E, H>(
    endpoint: E,
    ctaphid: CtapHidHandler<H>,
    config: WorkerConfig,
    cancel: Arc<AtomicBool>,
    mut cache_cleanup: Box<dyn FnMut() + Send + 'static>,
    mut hooks: WorkerHooks,
) -> WorkerHandle
where
    E: HidEndpoint + 'static,
    H: CommandHandler + Send + 'static,
{
    let cancel_for_thread = Arc::clone(&cancel);
    let thread = std::thread::spawn(move || {
        run_loop(
            endpoint,
            ctaphid,
            &config,
            &cancel_for_thread,
            &mut cache_cleanup,
            &mut hooks,
        )
    });

    WorkerHandle {
        cancel,
        thread: Some(thread),
        pending_rx: None,
    }
}

fn run_loop<E: HidEndpoint, H: CommandHandler>(
    mut endpoint: E,
    mut ctaphid: CtapHidHandler<H>,
    config: &WorkerConfig,
    cancel: &AtomicBool,
    cache_cleanup: &mut dyn FnMut(),
    hooks: &mut WorkerHooks,
) -> Result<(), WorkerError> {
    let mut buffer = [0u8; 64];
    let mut last_cache_cleanup = Instant::now();
    let mut draining = false;

    info!("Worker started");

    'outer: loop {
        if cancel.load(Ordering::Relaxed) && !draining {
            info!("Worker received cancellation, draining...");
            draining = true;
        }

        if last_cache_cleanup.elapsed() >= config.cache_cleanup_interval {
            cache_cleanup();
            last_cache_cleanup = Instant::now();
        }

        match endpoint.read_packet(&mut buffer) {
            Ok(Some(_)) => {
                debug!("Worker received packet from host");
                let packet = Packet::from_bytes(buffer);

                match ctaphid.process_packet(packet) {
                    Ok(response_packets) => {
                        let batch_len = response_packets.len();
                        if batch_len == 0 {
                            debug!("Worker no response packets to send");
                            continue;
                        }

                        debug!("Worker sending {} response packets", batch_len);
                        for response_packet in &response_packets {
                            if let Err(e) = endpoint.write_packet(response_packet.as_bytes()) {
                                error!("Worker failed to write response packet: {}", e);
                                if draining {
                                    break 'outer;
                                }
                                return Err(e);
                            }
                        }

                        debug!("Worker response sent successfully");
                        if let Some(ref mut cb) = hooks.on_response_sent {
                            cb();
                        }
                    }
                    Err(e) => {
                        error!("Worker CTAP HID processing failed: {:?}", e);
                        if draining {
                            break;
                        }
                    }
                }
            }
            Ok(None) => {
                if draining {
                    info!("Worker drain complete");
                    break;
                }
                std::thread::sleep(config.poll_interval);
            }
            Err(e) => {
                if draining {
                    info!("Worker drain ended on read error: {}", e);
                    break;
                }
                error!("Worker read error: {}", e);
                return Err(e);
            }
        }
    }

    cache_cleanup();
    info!("Worker stopped gracefully");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use soft_fido2_transport::{Cmd, Message};

    use std::collections::VecDeque;
    use std::sync::Mutex;

    #[derive(Clone)]
    struct FakeEndpoint {
        inner: Arc<FakeEndpointInner>,
    }

    struct FakeEndpointInner {
        inbound: Mutex<VecDeque<[u8; 64]>>,
        outbound: Mutex<Vec<[u8; 64]>>,
        read_errors: Mutex<VecDeque<WorkerError>>,
        write_errors: Mutex<VecDeque<WorkerError>>,
    }

    impl FakeEndpoint {
        fn new() -> Self {
            Self {
                inner: Arc::new(FakeEndpointInner {
                    inbound: Mutex::new(VecDeque::new()),
                    outbound: Mutex::new(Vec::new()),
                    read_errors: Mutex::new(VecDeque::new()),
                    write_errors: Mutex::new(VecDeque::new()),
                }),
            }
        }

        fn push_packet(&self, packet: &Packet) {
            self.inner
                .inbound
                .lock()
                .unwrap()
                .push_back(*packet.as_bytes());
        }

        fn outbound_packets(&self) -> Vec<[u8; 64]> {
            self.inner.outbound.lock().unwrap().clone()
        }

        fn push_read_error(&self, err: WorkerError) {
            self.inner.read_errors.lock().unwrap().push_back(err);
        }
    }

    impl HidEndpoint for FakeEndpoint {
        fn read_packet(&mut self, buffer: &mut [u8; 64]) -> Result<Option<usize>, WorkerError> {
            {
                let mut errors = self.inner.read_errors.lock().unwrap();
                if let Some(err) = errors.pop_front() {
                    return Err(err);
                }
            }

            let maybe = self.inner.inbound.lock().unwrap().pop_front();

            match maybe {
                Some(pkt) => {
                    buffer.copy_from_slice(&pkt);
                    Ok(Some(64))
                }
                None => Ok(None),
            }
        }

        fn write_packet(&mut self, data: &[u8; 64]) -> Result<(), WorkerError> {
            {
                let mut errors = self.inner.write_errors.lock().unwrap();
                if let Some(err) = errors.pop_front() {
                    return Err(err);
                }
            }
            self.inner.outbound.lock().unwrap().push(*data);
            Ok(())
        }
    }

    #[derive(Clone)]
    struct FakeHandler {
        inner: Arc<FakeHandlerInner>,
    }

    struct FakeHandlerInner {
        commands: Mutex<Vec<(Cmd, Vec<u8>)>>,
        responses: Mutex<VecDeque<Vec<u8>>>,
    }

    impl FakeHandler {
        fn new() -> Self {
            Self {
                inner: Arc::new(FakeHandlerInner {
                    commands: Mutex::new(Vec::new()),
                    responses: Mutex::new(VecDeque::new()),
                }),
            }
        }

        fn enqueue_response(&self, data: Vec<u8>) {
            self.inner.responses.lock().unwrap().push_back(data);
        }

        fn received_commands(&self) -> Vec<(Cmd, Vec<u8>)> {
            self.inner.commands.lock().unwrap().clone()
        }
    }

    impl CommandHandler for FakeHandler {
        fn handle_command(
            &mut self,
            cmd: Cmd,
            data: &[u8],
        ) -> soft_fido2_transport::Result<Vec<u8>> {
            self.inner
                .commands
                .lock()
                .unwrap()
                .push((cmd, data.to_vec()));

            let response = self
                .inner
                .responses
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_default();
            Ok(response)
        }
    }

    fn make_cbor_packet(cid: u32, data: &[u8]) -> Packet {
        let msg = Message::new(cid, Cmd::Cbor, data.to_vec(), None);
        let packets = msg.to_packets().unwrap();
        packets.into_iter().next().unwrap()
    }

    fn extract_response_message(packets: &[[u8; 64]]) -> Option<Message> {
        let owned: Vec<Packet> = packets.iter().map(|p| Packet::from_bytes(*p)).collect();
        Message::from_packets(&owned, None).ok()
    }

    #[test]
    fn test_routing_delivers_to_injected_handler() {
        let endpoint = FakeEndpoint::new();
        let handler = FakeHandler::new();
        let handler_ref = handler.clone();

        let payload = vec![0xA1, 0x01, 0x02];
        handler.enqueue_response(vec![0x00]);

        let packet = make_cbor_packet(0x12345678, &payload);
        endpoint.push_packet(&packet);

        let cancel = Arc::new(AtomicBool::new(false));

        let handle = spawn(
            endpoint.clone(),
            CtapHidHandler::new(handler),
            WorkerConfig {
                poll_interval: Duration::from_millis(1),
                cache_cleanup_interval: Duration::from_secs(3600),
            },
            cancel,
            Box::new(|| {}),
        );

        std::thread::sleep(Duration::from_millis(50));
        handle.cancel();
        let outcome = handle.join();

        assert!(matches!(outcome, WorkerOutcome::Clean));

        let cmds = handler_ref.received_commands();
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].0, Cmd::Cbor);
        assert_eq!(cmds[0].1, payload);
    }

    #[test]
    fn test_cancellation_stops_worker() {
        let endpoint = FakeEndpoint::new();
        let handler = FakeHandler::new();

        let cancel = Arc::new(AtomicBool::new(false));

        let handle = spawn(
            endpoint,
            CtapHidHandler::new(handler),
            WorkerConfig {
                poll_interval: Duration::from_millis(1),
                cache_cleanup_interval: Duration::from_secs(3600),
            },
            cancel.clone(),
            Box::new(|| {}),
        );

        std::thread::sleep(Duration::from_millis(20));

        handle.cancel();
        assert!(cancel.load(Ordering::Relaxed));

        let outcome = handle.join();
        assert!(matches!(outcome, WorkerOutcome::Clean));
    }

    #[test]
    fn test_daemon_shutdown_via_shared_cancel() {
        let endpoint = FakeEndpoint::new();
        let handler = FakeHandler::new();

        let daemon_cancel = Arc::new(AtomicBool::new(false));

        let handle = spawn(
            endpoint,
            CtapHidHandler::new(handler),
            WorkerConfig {
                poll_interval: Duration::from_millis(1),
                cache_cleanup_interval: Duration::from_secs(3600),
            },
            daemon_cancel.clone(),
            Box::new(|| {}),
        );

        std::thread::sleep(Duration::from_millis(20));
        daemon_cancel.store(true, Ordering::Relaxed);

        let outcome = handle.join();
        assert!(matches!(outcome, WorkerOutcome::Clean));
    }

    #[test]
    fn test_error_isolation_on_handler_error() {
        let endpoint = FakeEndpoint::new();
        let handler = FakeHandler::new();

        handler.enqueue_response(vec![0x00]);

        let packet = make_cbor_packet(0xAABBCCDD, &[0x01, 0x02]);
        endpoint.push_packet(&packet);

        let cancel = Arc::new(AtomicBool::new(false));

        let handle = spawn(
            endpoint,
            CtapHidHandler::new(handler),
            WorkerConfig {
                poll_interval: Duration::from_millis(1),
                cache_cleanup_interval: Duration::from_secs(3600),
            },
            cancel,
            Box::new(|| {}),
        );

        std::thread::sleep(Duration::from_millis(50));
        handle.cancel();
        let outcome = handle.join();

        assert!(matches!(outcome, WorkerOutcome::Clean));
    }

    #[test]
    fn test_error_isolation_on_read_error() {
        let endpoint = FakeEndpoint::new();
        let handler = FakeHandler::new();

        endpoint.push_read_error(WorkerError::Read("device disconnected".into()));

        let cancel = Arc::new(AtomicBool::new(false));

        let handle = spawn(
            endpoint,
            CtapHidHandler::new(handler),
            WorkerConfig {
                poll_interval: Duration::from_millis(1),
                cache_cleanup_interval: Duration::from_secs(3600),
            },
            cancel,
            Box::new(|| {}),
        );

        let outcome = handle.join();
        match outcome {
            WorkerOutcome::Error(WorkerError::Read(msg)) => {
                assert!(msg.contains("device disconnected"));
            }
            _other => panic!("expected Error(Read), got other outcome"),
        }
    }

    #[test]
    fn test_response_completion() {
        let endpoint = FakeEndpoint::new();
        let handler = FakeHandler::new();

        let response_data = vec![0xBE, 0xEF];
        handler.enqueue_response(response_data.clone());

        let packet = make_cbor_packet(0x99999999, &[0xDE, 0xAD]);
        endpoint.push_packet(&packet);

        let cancel = Arc::new(AtomicBool::new(false));

        let handle = spawn(
            endpoint.clone(),
            CtapHidHandler::new(handler),
            WorkerConfig {
                poll_interval: Duration::from_millis(1),
                cache_cleanup_interval: Duration::from_secs(3600),
            },
            cancel,
            Box::new(|| {}),
        );

        std::thread::sleep(Duration::from_millis(50));
        handle.cancel();
        let _ = handle.join();

        let outbound = endpoint.outbound_packets();
        assert!(
            !outbound.is_empty(),
            "expected at least one response packet"
        );

        let msg = extract_response_message(&outbound);
        assert!(
            msg.is_some(),
            "response packets should form a valid message"
        );
        let msg = msg.unwrap();
        assert_eq!(msg.cmd, Cmd::Cbor);
        assert_eq!(msg.data, response_data);
    }

    #[test]
    fn test_drain_before_destroy() {
        let endpoint = FakeEndpoint::new();
        let handler = FakeHandler::new();
        let handler_ref = handler.clone();

        for i in 0u8..3 {
            handler.enqueue_response(vec![i]);
            let pkt = make_cbor_packet(0x11111111, &[i]);
            endpoint.push_packet(&pkt);
        }

        let cancel = Arc::new(AtomicBool::new(false));

        let handle = spawn(
            endpoint,
            CtapHidHandler::new(handler),
            WorkerConfig {
                poll_interval: Duration::from_millis(1),
                cache_cleanup_interval: Duration::from_secs(3600),
            },
            cancel,
            Box::new(|| {}),
        );

        std::thread::sleep(Duration::from_millis(50));
        handle.cancel();
        let outcome = handle.join();

        assert!(matches!(outcome, WorkerOutcome::Clean));

        let cmds = handler_ref.received_commands();
        assert_eq!(cmds.len(), 3, "all queued packets should be drained");
    }

    #[test]
    fn test_cache_cleanup_called_periodically() {
        let endpoint = FakeEndpoint::new();
        let handler = FakeHandler::new();

        let cleanup_count = Arc::new(Mutex::new(0u32));
        let cleanup_count_clone = cleanup_count.clone();

        let cancel = Arc::new(AtomicBool::new(false));

        let handle = spawn(
            endpoint,
            CtapHidHandler::new(handler),
            WorkerConfig {
                poll_interval: Duration::from_millis(1),
                cache_cleanup_interval: Duration::from_millis(10),
            },
            cancel,
            Box::new(move || {
                *cleanup_count_clone.lock().unwrap() += 1;
            }),
        );

        std::thread::sleep(Duration::from_millis(80));
        handle.cancel();
        let _ = handle.join();

        let count = *cleanup_count.lock().unwrap();
        assert!(
            count >= 2,
            "cache cleanup should have been called multiple times, got {}",
            count
        );
    }

    #[test]
    fn test_thread_join_outcome_clean() {
        let endpoint = FakeEndpoint::new();
        let handler = FakeHandler::new();

        let cancel = Arc::new(AtomicBool::new(false));

        let handle = spawn(
            endpoint,
            CtapHidHandler::new(handler),
            WorkerConfig {
                poll_interval: Duration::from_millis(1),
                cache_cleanup_interval: Duration::from_secs(3600),
            },
            cancel,
            Box::new(|| {}),
        );

        std::thread::sleep(Duration::from_millis(10));
        handle.cancel();

        assert!(matches!(handle.join(), WorkerOutcome::Clean));
    }

    #[test]
    fn test_thread_join_outcome_error() {
        let endpoint = FakeEndpoint::new();
        let handler = FakeHandler::new();

        endpoint.push_read_error(WorkerError::Read("fatal".into()));

        let cancel = Arc::new(AtomicBool::new(false));

        let handle = spawn(
            endpoint,
            CtapHidHandler::new(handler),
            WorkerConfig {
                poll_interval: Duration::from_millis(1),
                cache_cleanup_interval: Duration::from_secs(3600),
            },
            cancel,
            Box::new(|| {}),
        );

        assert!(matches!(handle.join(), WorkerOutcome::Error(_)));
    }

    #[test]
    fn test_multiple_packets_routed_sequentially() {
        let endpoint = FakeEndpoint::new();
        let handler = FakeHandler::new();
        let handler_ref = handler.clone();

        let payloads: Vec<Vec<u8>> = (0..5).map(|i| vec![i as u8]).collect();
        for p in &payloads {
            handler.enqueue_response(p.clone());
        }
        for (i, p) in payloads.iter().enumerate() {
            let pkt = make_cbor_packet(0xAAAA0000 + i as u32, p);
            endpoint.push_packet(&pkt);
        }

        let cancel = Arc::new(AtomicBool::new(false));

        let handle = spawn(
            endpoint.clone(),
            CtapHidHandler::new(handler),
            WorkerConfig {
                poll_interval: Duration::from_millis(1),
                cache_cleanup_interval: Duration::from_secs(3600),
            },
            cancel,
            Box::new(|| {}),
        );

        std::thread::sleep(Duration::from_millis(100));
        handle.cancel();
        let _ = handle.join();

        let outbound = endpoint.outbound_packets();
        assert!(outbound.len() >= payloads.len());

        let cmds = handler_ref.received_commands();
        assert_eq!(cmds.len(), payloads.len());
        for (i, (cmd, data)) in cmds.iter().enumerate() {
            assert_eq!(*cmd, Cmd::Cbor);
            assert_eq!(*data, payloads[i]);
        }
    }

    #[test]
    fn test_drop_handle_triggers_cancel_and_join() {
        let endpoint = FakeEndpoint::new();
        let handler = FakeHandler::new();

        let cancel = Arc::new(AtomicBool::new(false));
        let cancel_check = cancel.clone();

        {
            let _handle = spawn(
                endpoint,
                CtapHidHandler::new(handler),
                WorkerConfig {
                    poll_interval: Duration::from_millis(1),
                    cache_cleanup_interval: Duration::from_secs(3600),
                },
                cancel,
                Box::new(|| {}),
            );
            std::thread::sleep(Duration::from_millis(10));
        }

        assert!(cancel_check.load(Ordering::Relaxed));
    }

    #[test]
    fn test_write_error_isolation_during_drain() {
        let endpoint = FakeEndpoint::new();
        let handler = FakeHandler::new();

        handler.enqueue_response(vec![0x01]);

        let packet = make_cbor_packet(0xBBBBBBBB, &[0x42]);
        endpoint.push_packet(&packet);

        {
            let mut errors = endpoint.inner.write_errors.lock().unwrap();
            errors.push_back(WorkerError::Write("write failed".into()));
        }

        let cancel = Arc::new(AtomicBool::new(false));

        let handle = spawn(
            endpoint,
            CtapHidHandler::new(handler),
            WorkerConfig {
                poll_interval: Duration::from_millis(1),
                cache_cleanup_interval: Duration::from_secs(3600),
            },
            cancel,
            Box::new(|| {}),
        );

        let outcome = handle.join();
        match outcome {
            WorkerOutcome::Error(WorkerError::Write(msg)) => {
                assert!(msg.contains("write failed"));
            }
            _other => panic!("expected Error(Write), got other outcome"),
        }
    }

    #[test]
    fn test_hook_called_exactly_once_for_multi_packet_batch() {
        let endpoint = FakeEndpoint::new();
        let handler = FakeHandler::new();

        let large_response = vec![0xAA; 120];
        handler.enqueue_response(large_response);

        let packet = make_cbor_packet(0x12345678, &[0x01]);
        endpoint.push_packet(&packet);

        let hook_count = Arc::new(Mutex::new(0u32));
        let hook_count_clone = hook_count.clone();

        let cancel = Arc::new(AtomicBool::new(false));

        let handle = spawn_with_hooks(
            endpoint.clone(),
            CtapHidHandler::new(handler),
            WorkerConfig {
                poll_interval: Duration::from_millis(1),
                cache_cleanup_interval: Duration::from_secs(3600),
            },
            cancel,
            Box::new(|| {}),
            WorkerHooks {
                on_response_sent: Some(Box::new(move || {
                    *hook_count_clone.lock().unwrap() += 1;
                })),
            },
        );

        std::thread::sleep(Duration::from_millis(50));
        handle.cancel();
        let _ = handle.join();

        let outbound = endpoint.outbound_packets();
        assert!(
            outbound.len() > 1,
            "expected multi-packet response, got {} packets",
            outbound.len()
        );

        let count = *hook_count.lock().unwrap();
        assert_eq!(count, 1, "hook should be called exactly once");
    }

    #[test]
    fn test_hook_not_called_on_partial_write() {
        let endpoint = FakeEndpoint::new();
        let handler = FakeHandler::new();

        let large_response = vec![0xBB; 120];
        handler.enqueue_response(large_response);

        let packet = make_cbor_packet(0xAABBCCDD, &[0x02]);
        endpoint.push_packet(&packet);

        {
            let mut errors = endpoint.inner.write_errors.lock().unwrap();
            errors.push_back(WorkerError::Write("write failed mid-batch".into()));
        }

        let hook_count = Arc::new(Mutex::new(0u32));
        let hook_count_clone = hook_count.clone();

        let cancel = Arc::new(AtomicBool::new(false));

        let handle = spawn_with_hooks(
            endpoint,
            CtapHidHandler::new(handler),
            WorkerConfig {
                poll_interval: Duration::from_millis(1),
                cache_cleanup_interval: Duration::from_secs(3600),
            },
            cancel,
            Box::new(|| {}),
            WorkerHooks {
                on_response_sent: Some(Box::new(move || {
                    *hook_count_clone.lock().unwrap() += 1;
                })),
            },
        );

        let outcome = handle.join();
        assert!(matches!(outcome, WorkerOutcome::Error(_)));

        let count = *hook_count.lock().unwrap();
        assert_eq!(count, 0, "hook should not be called on partial write");
    }

    #[test]
    fn test_hook_called_on_handler_error_response() {
        let endpoint = FakeEndpoint::new();
        let handler = FakeHandler::new();

        handler.enqueue_response(vec![0x00]);

        let packet = make_cbor_packet(0x99999999, &[0x03]);
        endpoint.push_packet(&packet);

        let hook_count = Arc::new(Mutex::new(0u32));
        let hook_count_clone = hook_count.clone();

        let cancel = Arc::new(AtomicBool::new(false));

        let handle = spawn_with_hooks(
            endpoint.clone(),
            CtapHidHandler::new(handler),
            WorkerConfig {
                poll_interval: Duration::from_millis(1),
                cache_cleanup_interval: Duration::from_secs(3600),
            },
            cancel,
            Box::new(|| {}),
            WorkerHooks {
                on_response_sent: Some(Box::new(move || {
                    *hook_count_clone.lock().unwrap() += 1;
                })),
            },
        );

        std::thread::sleep(Duration::from_millis(50));
        handle.cancel();
        let _ = handle.join();

        let outbound = endpoint.outbound_packets();
        assert!(!outbound.is_empty(), "expected response packet");

        let count = *hook_count.lock().unwrap();
        assert_eq!(
            count, 1,
            "hook should be called after successful write of error response"
        );
    }

    #[test]
    fn test_drain_after_hook_callback() {
        let endpoint = FakeEndpoint::new();
        let handler = FakeHandler::new();

        handler.enqueue_response(vec![0x01]);
        handler.enqueue_response(vec![0x02]);

        let pkt1 = make_cbor_packet(0x11111111, &[0x10]);
        let pkt2 = make_cbor_packet(0x22222222, &[0x20]);
        endpoint.push_packet(&pkt1);
        endpoint.push_packet(&pkt2);

        let hook_count = Arc::new(Mutex::new(0u32));
        let hook_count_clone = hook_count.clone();

        let cancel = Arc::new(AtomicBool::new(false));

        let handle = spawn_with_hooks(
            endpoint,
            CtapHidHandler::new(handler),
            WorkerConfig {
                poll_interval: Duration::from_millis(1),
                cache_cleanup_interval: Duration::from_secs(3600),
            },
            cancel.clone(),
            Box::new(|| {}),
            WorkerHooks {
                on_response_sent: Some(Box::new(move || {
                    *hook_count_clone.lock().unwrap() += 1;
                })),
            },
        );

        std::thread::sleep(Duration::from_millis(50));
        handle.cancel();
        let outcome = handle.join();

        assert!(matches!(outcome, WorkerOutcome::Clean));

        let count = *hook_count.lock().unwrap();
        assert_eq!(count, 2, "hook should be called for each successful batch");
    }

    #[test]
    fn test_spawn_without_hooks_works() {
        let endpoint = FakeEndpoint::new();
        let handler = FakeHandler::new();

        handler.enqueue_response(vec![0x55]);

        let packet = make_cbor_packet(0xAAAAAAAA, &[0x04]);
        endpoint.push_packet(&packet);

        let cancel = Arc::new(AtomicBool::new(false));

        let handle = spawn(
            endpoint.clone(),
            CtapHidHandler::new(handler),
            WorkerConfig {
                poll_interval: Duration::from_millis(1),
                cache_cleanup_interval: Duration::from_secs(3600),
            },
            cancel,
            Box::new(|| {}),
        );

        std::thread::sleep(Duration::from_millis(50));
        handle.cancel();
        let outcome = handle.join();

        assert!(matches!(outcome, WorkerOutcome::Clean));

        let outbound = endpoint.outbound_packets();
        assert!(!outbound.is_empty(), "expected response packet");
    }
}
