use crate::returncode::ReturnCode;

#[derive(Copy, Clone, Debug, PartialEq)]
/// An enum to keep track of the NFC field status
pub enum NfcType4FieldState {
    /// Initial value that indicates no NFCT field events.
    None,
    /// The NFCT FIELDLOST event has been set.
    On,
    /// The NFCT FIELDDETECTED event has been set.
    Off,
    /// Both NFCT field events have been set - ambiguous state.
    Unknown,
    /// We are in the middle of a type 4 "handshake"
    Type4HandshakeInProgress,
    /// Passthrough all frames to the application
    Passthrough(u8),
}

/// Controls an NFC type4 tag
/// Uses the `nfc` capsule for providing the underlying functionality
pub trait NfcType4Tag<'a> {
    /// Set the client instance that will handle callbacks
    fn set_client(&self, client: &'a dyn Type4Client<'a>);

    /// Pass the buffer to be transmitted and the amount of data and take
    /// ownership of it. Subscribe to the relevant interrupt and trigger
    /// the task for transmission.
    ///
    /// On success returns the length of data to be sent.
    /// On failure returns an error code and the buffer passed in.
    fn transmit_buffer(
        &self,
        tx_buffer: &'static mut [u8],
        tx_amount: usize,
    ) -> Result<usize, (ReturnCode, &'static mut [u8])>;

    /// Pass a buffer for receiving data and take ownership of it.
    ///
    /// On success returns nothing.
    /// On failure returns an error code and the buffer passed in.
    fn receive_buffer(
        &self,
        rx_buffer: &'static mut [u8],
    ) -> Result<(), (ReturnCode, &'static mut [u8])>;
}

/// Implement this trait and use `set_client()` in order to receive callbacks.
pub trait Type4Client<'a> {
    /// Called when a frame is received.
    /// This will return the buffer passed into `receive_buffer()`.
    /// If the buffer length is smaller then the data length the buffer will only contain part
    /// of the frame the `result` will contain an `ENOMEM` error. If the received frame contained
    /// errors the `result` will contain a `FAIL` error.
    fn frame_received(&'a self, buffer: &'static mut [u8], rx_len: usize, result: ReturnCode);

    /// Called when a frame has finished transmitting.
    /// This will return the buffer passed into `transmit_buffer()`.
    /// If not all of the data could be sent because of a timeout the `result` will contain
    /// a `FAIL` error.
    fn frame_transmitted(&'a self, buffer: &'static mut [u8], result: ReturnCode);
}
