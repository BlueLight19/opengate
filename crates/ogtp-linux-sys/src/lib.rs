//! Small, auditable Linux `sendmmsg` ownership boundary for OGTP.
//!
//! This crate contains the platform FFI that the main protocol crate forbids.
//! All descriptor, address, I/O-vector, and aligned ancillary storage is
//! allocated during [`LinuxSendBatch::new`]. [`LinuxSendBatch::send`] performs
//! no allocation, does not retain caller payloads, and returns only after the
//! kernel has synchronously copied every accepted UDP payload.

#![cfg(target_os = "linux")]
#![deny(unsafe_op_in_unsafe_fn)]

use core::mem::{align_of, size_of};
use core::ptr;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::os::fd::AsRawFd;

/// IP control-message family shared by one `sendmmsg` submission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IpVersion {
    V4,
    V6,
}

/// Ancillary settings shared by every datagram in one submission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SendControl {
    pub family: IpVersion,
    pub source: Option<IpAddr>,
    pub interface_index: Option<u32>,
    /// Low two ECN bits. `None` omits the per-datagram traffic-class message.
    pub ecn: Option<u8>,
    pub gso_segment_size: Option<u16>,
}

/// Synchronous kernel result for one fixed batch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SendBatchResult<const BATCH: usize> {
    sent: usize,
    lengths: [usize; BATCH],
}

impl<const BATCH: usize> SendBatchResult<BATCH> {
    /// Returns the accepted prefix length.
    #[must_use]
    pub const fn sent(&self) -> usize {
        self.sent
    }

    /// Returns accepted byte counts followed by zeroes for unsubmitted slots.
    #[must_use]
    pub const fn lengths(&self) -> &[usize; BATCH] {
        &self.lengths
    }
}

/// Startup-preallocated descriptors for one fixed-size `sendmmsg` batch.
pub struct LinuxSendBatch<const BATCH: usize> {
    batch_length: libc::c_uint,
    headers: Box<[libc::mmsghdr]>,
    addresses: Box<[libc::sockaddr_storage]>,
    io_vectors: Box<[libc::iovec]>,
    control_words: Box<[usize]>,
}

impl<const BATCH: usize> LinuxSendBatch<BATCH> {
    /// Allocates all syscall descriptors and maximum ancillary storage.
    ///
    /// # Errors
    ///
    /// Returns `InvalidInput` if `BATCH` cannot fit Linux's `vlen`, or
    /// `OutOfMemory` if one of the bounded startup allocations fails.
    pub fn new() -> io::Result<Self> {
        let batch_length = libc::c_uint::try_from(BATCH)
            .map_err(|_| invalid_input("sendmmsg batch exceeds c_uint::MAX"))?;
        let headers = boxed_zeroed_with(BATCH, zero_mmsghdr)?;
        let addresses = boxed_zeroed_with(BATCH, zero_sockaddr_storage)?;
        let io_vectors = boxed_zeroed_with(BATCH, zero_iovec)?;
        let control_bytes = maximum_control_bytes();
        let control_words =
            boxed_zeroed_with(control_bytes.div_ceil(size_of::<usize>()), || 0usize)?;
        debug_assert!(align_of::<usize>() >= align_of::<libc::cmsghdr>());
        Ok(Self {
            batch_length,
            headers,
            addresses,
            io_vectors,
            control_words,
        })
    }

    /// Submits exactly `BATCH` UDP payloads without allocating or retaining
    /// any caller-owned pointer after the system call.
    ///
    /// `MSG_DONTWAIT` is always used. Linux accepts a prefix and reports its
    /// exact length; the remaining suffix was not submitted.
    ///
    /// # Errors
    ///
    /// Returns `InvalidInput` before the syscall for inconsistent families,
    /// empty payloads, invalid ECN/GSO values, or an IPv4 interface index that
    /// cannot fit `in_pktinfo`. Otherwise returns the operating-system error.
    pub fn send(
        &mut self,
        socket: &UdpSocket,
        payloads: &[&[u8]; BATCH],
        destinations: &[SocketAddr; BATCH],
        control: SendControl,
    ) -> io::Result<SendBatchResult<BATCH>> {
        if BATCH == 0 {
            return Ok(SendBatchResult {
                sent: 0,
                lengths: [0; BATCH],
            });
        }
        validate_control(control)?;
        let control_length = self.encode_control(control)?;

        for position in 0..BATCH {
            if payloads[position].is_empty() {
                return Err(invalid_input("sendmmsg payload is empty"));
            }
            validate_destination(destinations[position], control.family)?;
            let address_length =
                write_socket_address(&mut self.addresses[position], destinations[position]);
            self.io_vectors[position] = libc::iovec {
                iov_base: payloads[position].as_ptr().cast_mut().cast(),
                iov_len: payloads[position].len(),
            };
            self.headers[position] = zero_mmsghdr();
            let header = &mut self.headers[position].msg_hdr;
            header.msg_name = ptr::from_mut(&mut self.addresses[position]).cast();
            header.msg_namelen = address_length;
            header.msg_iov = ptr::from_mut(&mut self.io_vectors[position]);
            header.msg_iovlen = 1;
            if control_length != 0 {
                header.msg_control = self.control_words.as_mut_ptr().cast();
                header.msg_controllen = control_length;
            }
        }

        // SAFETY: every header points into stable storage owned by `self` or
        // into a payload borrowed for this call. All lengths and families were
        // validated above. `sendmmsg` is synchronous and retains no pointer.
        let result = unsafe {
            libc::sendmmsg(
                socket.as_raw_fd(),
                self.headers.as_mut_ptr(),
                self.batch_length,
                libc::MSG_DONTWAIT,
            )
        };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        let sent = usize::try_from(result)
            .map_err(|_| io::Error::other("sendmmsg returned a negative result"))?;
        if sent > BATCH {
            return Err(io::Error::other("sendmmsg accepted beyond its batch"));
        }
        let lengths = core::array::from_fn(|position| {
            if position < sent {
                self.headers[position].msg_len as usize
            } else {
                0
            }
        });
        Ok(SendBatchResult { sent, lengths })
    }

    fn encode_control(&mut self, control: SendControl) -> io::Result<usize> {
        self.control_words.fill(0);
        let mut offset = 0;
        if control.source.is_some() || control.interface_index.is_some() {
            offset = match control.family {
                IpVersion::V4 => {
                    let source =
                        control
                            .source
                            .map_or(Ipv4Addr::UNSPECIFIED, |address| match address {
                                IpAddr::V4(address) => address,
                                IpAddr::V6(_) => Ipv4Addr::UNSPECIFIED,
                            });
                    let interface = control.interface_index.unwrap_or(0);
                    let interface = libc::c_int::try_from(interface)
                        .map_err(|_| invalid_input("IPv4 interface index exceeds c_int"))?;
                    let packet_info = libc::in_pktinfo {
                        ipi_ifindex: interface,
                        ipi_spec_dst: libc::in_addr {
                            s_addr: u32::from_ne_bytes(source.octets()),
                        },
                        ipi_addr: libc::in_addr { s_addr: 0 },
                    };
                    self.push_control(offset, libc::IPPROTO_IP, libc::IP_PKTINFO, packet_info)?
                }
                IpVersion::V6 => {
                    let source =
                        control
                            .source
                            .map_or(Ipv6Addr::UNSPECIFIED, |address| match address {
                                IpAddr::V6(address) => address,
                                IpAddr::V4(_) => Ipv6Addr::UNSPECIFIED,
                            });
                    let packet_info = libc::in6_pktinfo {
                        ipi6_addr: libc::in6_addr {
                            s6_addr: source.octets(),
                        },
                        ipi6_ifindex: control.interface_index.unwrap_or(0),
                    };
                    self.push_control(offset, libc::IPPROTO_IPV6, libc::IPV6_PKTINFO, packet_info)?
                }
            };
        }
        if let Some(ecn) = control.ecn {
            offset = match control.family {
                IpVersion::V4 => self.push_control(offset, libc::IPPROTO_IP, libc::IP_TOS, ecn)?,
                IpVersion::V6 => self.push_control(
                    offset,
                    libc::IPPROTO_IPV6,
                    libc::IPV6_TCLASS,
                    libc::c_int::from(ecn),
                )?,
            };
        }
        if let Some(segment_size) = control.gso_segment_size {
            offset = self.push_control(offset, libc::SOL_UDP, libc::UDP_SEGMENT, segment_size)?;
        }
        Ok(offset)
    }

    fn push_control<T: Copy>(
        &mut self,
        offset: usize,
        level: libc::c_int,
        kind: libc::c_int,
        value: T,
    ) -> io::Result<usize> {
        let space = control_space::<T>();
        let next = offset
            .checked_add(space)
            .ok_or_else(|| invalid_input("ancillary length overflow"))?;
        if next > self.control_words.len() * size_of::<usize>() {
            return Err(invalid_input("ancillary storage exhausted"));
        }
        if !offset.is_multiple_of(align_of::<libc::cmsghdr>()) {
            return Err(invalid_input("ancillary storage lost cmsghdr alignment"));
        }
        let value_length = libc::c_uint::try_from(size_of::<T>())
            .map_err(|_| invalid_input("ancillary value exceeds c_uint::MAX"))?;
        // SAFETY: `control_words` is cmsghdr-aligned, `offset` is a sum of
        // CMSG_SPACE values, and the checked range fits the allocated buffer.
        unsafe {
            let header = self
                .control_words
                .as_mut_ptr()
                .add(offset / size_of::<usize>())
                .cast::<libc::cmsghdr>();
            ptr::write(
                header,
                libc::cmsghdr {
                    cmsg_len: libc::CMSG_LEN(value_length) as _,
                    cmsg_level: level,
                    cmsg_type: kind,
                },
            );
            ptr::write(libc::CMSG_DATA(header).cast::<T>(), value);
        }
        Ok(next)
    }
}

impl<const BATCH: usize> core::fmt::Debug for LinuxSendBatch<BATCH> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("LinuxSendBatch")
            .field("batch_size", &BATCH)
            .field(
                "control_capacity",
                &(self.control_words.len() * size_of::<usize>()),
            )
            .finish_non_exhaustive()
    }
}

fn validate_control(control: SendControl) -> io::Result<()> {
    if control.ecn.is_some_and(|ecn| ecn > 0b11) {
        return Err(invalid_input("ECN value exceeds two bits"));
    }
    if control.gso_segment_size == Some(0) {
        return Err(invalid_input("UDP GSO segment size is zero"));
    }
    if let Some(source) = control.source {
        match (control.family, source) {
            (IpVersion::V4, IpAddr::V4(_)) | (IpVersion::V6, IpAddr::V6(_)) => {}
            _ => return Err(invalid_input("source and control families differ")),
        }
    }
    Ok(())
}

fn validate_destination(destination: SocketAddr, family: IpVersion) -> io::Result<()> {
    match (family, destination) {
        (IpVersion::V4, SocketAddr::V4(_)) | (IpVersion::V6, SocketAddr::V6(_)) => Ok(()),
        _ => Err(invalid_input("destination and control families differ")),
    }
}

// Linux address-family constants and sockaddr structure sizes are defined to
// fit their corresponding kernel ABI fields.
#[allow(clippy::cast_possible_truncation)]
fn write_socket_address(
    storage: &mut libc::sockaddr_storage,
    address: SocketAddr,
) -> libc::socklen_t {
    *storage = zero_sockaddr_storage();
    match address {
        SocketAddr::V4(address) => {
            let encoded = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: address.port().to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(address.ip().octets()),
                },
                sin_zero: [0; 8],
            };
            // SAFETY: sockaddr_storage is large and aligned enough for
            // sockaddr_in; the active length returned below matches the write.
            unsafe {
                ptr::from_mut(storage)
                    .cast::<libc::sockaddr_in>()
                    .write(encoded);
            };
            size_of::<libc::sockaddr_in>() as libc::socklen_t
        }
        SocketAddr::V6(address) => {
            let encoded = libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as libc::sa_family_t,
                sin6_port: address.port().to_be(),
                sin6_flowinfo: address.flowinfo(),
                sin6_addr: libc::in6_addr {
                    s6_addr: address.ip().octets(),
                },
                sin6_scope_id: address.scope_id(),
            };
            // SAFETY: sockaddr_storage is large and aligned enough for
            // sockaddr_in6; the active length returned below matches the write.
            unsafe {
                ptr::from_mut(storage)
                    .cast::<libc::sockaddr_in6>()
                    .write(encoded);
            };
            size_of::<libc::sockaddr_in6>() as libc::socklen_t
        }
    }
}

fn maximum_control_bytes() -> usize {
    control_space::<libc::in6_pktinfo>() + control_space::<libc::c_int>() + control_space::<u16>()
}

fn control_space<T>() -> usize {
    // SAFETY: CMSG_SPACE only performs the platform alignment calculation.
    // Every call uses a fixed Linux ancillary structure much smaller than
    // `c_uint::MAX` on every supported ABI.
    #[allow(clippy::cast_possible_truncation)]
    unsafe {
        libc::CMSG_SPACE(size_of::<T>() as libc::c_uint) as usize
    }
}

fn boxed_zeroed_with<T, F>(length: usize, mut value: F) -> io::Result<Box<[T]>>
where
    F: FnMut() -> T,
{
    let mut values = Vec::new();
    values
        .try_reserve_exact(length)
        .map_err(|_| io::Error::from(io::ErrorKind::OutOfMemory))?;
    values.resize_with(length, &mut value);
    Ok(values.into_boxed_slice())
}

fn zero_mmsghdr() -> libc::mmsghdr {
    // SAFETY: an all-zero message header represents empty optional pointers
    // and lengths; every input field is initialized before the syscall.
    unsafe { core::mem::zeroed() }
}

fn zero_sockaddr_storage() -> libc::sockaddr_storage {
    // SAFETY: sockaddr_storage accepts an all-zero unspecified family value.
    unsafe { core::mem::zeroed() }
}

fn zero_iovec() -> libc::iovec {
    libc::iovec {
        iov_base: ptr::null_mut(),
        iov_len: 0,
    }
}

fn invalid_input(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn input_validation_rejects_cross_family_and_invalid_fields() {
        assert!(
            validate_control(SendControl {
                family: IpVersion::V4,
                source: Some(IpAddr::V6(Ipv6Addr::LOCALHOST)),
                interface_index: None,
                ecn: None,
                gso_segment_size: None,
            })
            .is_err()
        );
        assert!(
            validate_control(SendControl {
                family: IpVersion::V4,
                source: None,
                interface_index: None,
                ecn: Some(4),
                gso_segment_size: None,
            })
            .is_err()
        );
        assert!(
            validate_control(SendControl {
                family: IpVersion::V4,
                source: None,
                interface_index: None,
                ecn: None,
                gso_segment_size: Some(0),
            })
            .is_err()
        );
    }

    #[test]
    fn zero_batch_is_a_noop() {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("socket");
        let mut batch = LinuxSendBatch::<0>::new().expect("batch");
        let result = batch
            .send(
                &socket,
                &[],
                &[],
                SendControl {
                    family: IpVersion::V4,
                    source: None,
                    interface_index: None,
                    ecn: None,
                    gso_segment_size: None,
                },
            )
            .expect("send");
        assert_eq!(result.sent(), 0);
    }

    #[test]
    fn loopback_batch_reports_every_length() {
        let receiver = UdpSocket::bind("127.0.0.1:0").expect("receiver");
        let sender = UdpSocket::bind("127.0.0.1:0").expect("sender");
        let destination = receiver.local_addr().expect("destination");
        let mut batch = LinuxSendBatch::<2>::new().expect("batch");
        let result = batch
            .send(
                &sender,
                &[b"one", b"three"],
                &[destination, destination],
                SendControl {
                    family: IpVersion::V4,
                    source: None,
                    interface_index: None,
                    ecn: None,
                    gso_segment_size: None,
                },
            )
            .expect("send");
        assert_eq!(result.sent(), 2);
        assert_eq!(result.lengths(), &[3, 5]);
    }
}
