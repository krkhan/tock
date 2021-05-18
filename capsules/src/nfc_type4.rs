use crate::nfc as base_nfc_capsule;
use core::cell::Cell;
use core::cmp;
use kernel::common::cells::{OptionalCell, TakeCell};
use kernel::common::dynamic_deferred_call::{
    DeferredCallHandle, DynamicDeferredCall, DynamicDeferredCallClient,
};
use kernel::debug;
use kernel::hil::{nfc, nfc_type4};
use kernel::{AppId, AppSlice, Callback, Driver, Grant, ReturnCode, Shared};

/// Syscall driver number.
use crate::driver;
pub const DRIVER_NUM: usize = driver::NUM::NFCType4 as usize;

#[derive(Default)]
pub struct App {
    tx_callback: Option<Callback>,
    tx_buffer: Option<AppSlice<Shared, u8>>,
    rx_callback: Option<Callback>,
    rx_buffer: Option<AppSlice<Shared, u8>>,
}

pub const MAX_LENGTH: usize = 256;

pub struct NfcType4Driver<'a> {
    base_nfc_driver: &'a base_nfc_capsule::NfcDriver<'a>,
    #[allow(dead_code)]
    driver: &'a dyn nfc_type4::NfcType4Tag<'a>,
    deferred_caller: &'static DynamicDeferredCall,
    deferred_call_handle: OptionalCell<DeferredCallHandle>,
    driver_tx_buffer: TakeCell<'static, [u8]>,
    driver_rx_buffer: TakeCell<'static, [u8]>,
    driver_tx_in_progress: OptionalCell<AppId>,
    driver_rx_in_progress: OptionalCell<AppId>,
    driver_block_number: Cell<bool>,
    application: Grant<App>,
    app_tx_in_progress: OptionalCell<AppId>,
    app_tx_chaining: Cell<bool>,
    app_rx_in_progress: OptionalCell<AppId>,
    driver_selected: Cell<bool>,
    tag_configured: Cell<bool>,
    current_field_state: Cell<nfc_type4::NfcType4FieldState>,
    appid: OptionalCell<AppId>,
}

fn copy_slice<T: Copy>(src: &[T], dest: &mut [T]) -> usize {
    let mut count: usize = 0;
    for (i, c) in src.as_ref().iter().enumerate() {
        dest[i] = *c;
        count += 1;
    }
    count
}

impl<'a> NfcType4Driver<'a> {
    pub fn new(
        base_nfc_driver: &'a base_nfc_capsule::NfcDriver<'a>,
        driver: &'a dyn nfc_type4::NfcType4Tag<'a>,
        deferred_caller: &'static DynamicDeferredCall,
        driver_tx_buffer: &'static mut [u8; MAX_LENGTH],
        driver_rx_buffer: &'static mut [u8; MAX_LENGTH],
        grant: Grant<App>,
    ) -> NfcType4Driver<'a> {
        NfcType4Driver {
            base_nfc_driver,
            driver,
            deferred_caller,
            deferred_call_handle: OptionalCell::empty(),
            driver_tx_buffer: TakeCell::new(driver_tx_buffer),
            driver_rx_buffer: TakeCell::new(driver_rx_buffer),
            driver_tx_in_progress: OptionalCell::empty(),
            driver_rx_in_progress: OptionalCell::empty(),
            driver_block_number: Cell::new(true),
            application: grant,
            app_tx_in_progress: OptionalCell::empty(),
            app_tx_chaining: Cell::new(false),
            app_rx_in_progress: OptionalCell::empty(),
            driver_selected: Cell::new(false),
            tag_configured: Cell::new(false),
            current_field_state: Cell::new(nfc_type4::NfcType4FieldState::None),
            appid: OptionalCell::empty(),
        }
    }

    pub fn initialize_callback_handle(&self, handle: DeferredCallHandle) {
        self.deferred_call_handle.replace(handle);
    }

    fn do_next_op(&self) {
        if self.driver_rx_in_progress.is_some()
            || self.driver_tx_in_progress.is_some()
            || self.app_tx_in_progress.is_some()
        {
            return;
        }
        self.receive_in_driver_buffer();
    }

    fn do_next_op_async(&self) {
        self.deferred_call_handle
            .map(|handle| self.deferred_caller.set(*handle));
    }

    fn generate_type4_reply(&self, request: &[u8], reply: &mut [u8]) -> usize {
        //
        //                                     Spec: ISO 14443-4
        //                   The code below caters exclusively to the following scenario
        //
        //                              [ OpenSK running on nrf52840dk ]
        //                                             ^
        //                                             |
        //                                             v
        //                    [ "FIDO/WebAuthn Example" app running on Pixel 4 XL ]
        //
        //                   The conversation looks like this (CRC bytes are omitted)
        //      Pixel 4 XL                                                                 OpenSK
        //         (PCD)                                                                   (PICC)
        //        Reader                                                                    Tag
        //        ------                                                                    ---
        //          |                                                                        |
        //          | RATS ----------------------------------------------------------------> |
        //          | [e0 80 31 73] -------------------------------------------------------> |
        //          |                                                                        |
        //          | <----------------------------------------------------------------- ATS |
        //          | <---------------------------------------------- [05 78 80 f1 00 a3 f0] |
        //          |                                                                        |
        //          | SELECT "U2F_V2" -----------------------------------------------------> |
        //          | [02 00 a4 04 00 08 a0 00 06 47 2f 00 01 00] -------------------------> |
        //          |                                                                        |
        //          | <--------------------------------------------------------- "U2F_V2" OK |
        //          | <---------------------------------------- [02 55 32 46 5f 56 32 90 00] |
        //          |                                                                        |
        //          | I-Block(1); Chaining(Off) -------------------------------------------> |
        //          | [03 00 (APDU ...) ] -------------------------------------------------> |
        //          |                                                                        |
        //          | R-Block(1); NACK ----------------------------------------------------> |
        //          | <------------------------------------------------------- S-Block (WTX) |
        //          | <------------------------------------------------------------- [f2 fb] |
        //          |                                                                        |
        //          | S-Block (WTX Response) ----------------------------------------------> |
        //          | [f2 3b] -------------------------------------------------------------> |
        //          |                                                                        |
        //          |                                 .                                      |
        //          |                                 .                                      |
        //          |                                 .                                      |
        //          |                                                                        |
        //          |                      (OpenSK prepares response)                        |
        //          | R-Block(1); NACK ----------------------------------------------------> |
        //          | <------------------------------------------------------- S-Block (WTX) |
        //          | S-Block (WTX Response) ----------------------------------------------> |
        //          |                                 .                                      |
        //          |                                 .                                      |
        //          |                                 .                                      |
        //          |                                                                        |
        //          | <------------------------------------------------------- S-Block (WTX) |
        //          | <------------------------------------------------------------- [f2 fb] |
        //          |                                                                        |
        //          | S-Block (WTX Response) ----------------------------------------------> |
        //          | [f2 3b] -------------------------------------------------------------> |
        //          |                                                                        |
        //          | <-------------------------------------------- I-Block(1); Chaining(On) |
        //          | <-------------------------------------------- [13 (Partial APDU) ... ] |
        //          |                                                                        |
        //          | R-Block(0); ACK -----------------------------------------------------> |
        //          | [a2] ----------------------------------------------------------------> |
        //          |                                                                        |
        //          | <-------------------------------------------- I-Block(0); Chaining(On) |
        //          | <-------------------------------------------- [12 (Partial APDU) ... ] |
        //          |                                                                        |
        //          | R-Block(1); ACK -----------------------------------------------------> |
        //          | [a3] ----------------------------------------------------------------> |
        //          |                                                                        |
        //          |                                 .                                      |
        //          |                                 .                                      |
        //          |                                 .                                      |
        //          |                                                                        |
        //          |          (Chaining repeats with alternating block numbers)             |
        //          | <-------------------------------------------- I-Block(1); Chaining(On) |
        //          | R-Block(0); ACK -----------------------------------------------------> |
        //          | <-------------------------------------------- I-Block(0); Chaining(On) |
        //          | R-Block(1); ACK -----------------------------------------------------> |
        //          |                                 .                                      |
        //          |                                 .                                      |
        //          |                                 .                                      |
        //          |                                                                        |
        //          | <------------------------------------------- I-Block(0); Chaining(Off) |
        //          | <-------------------------------------- [02 (Partial APDU) ... 90 00 ] |
        //          |                                                                        |
        //
        // Responsibilities of the driver:
        //
        // * Respond to RATS with ATS
        // * Respond to [SELECT "U2F_V2"] with ["U2F_V2" OK]
        // * Bubble received APDUs to the app (after *removing* prefix and checksum)
        // * Respond to any NACK from reader with a S(WTX) request
        // * Generate appropriate prefix based on current block number and whether chaining is on
        // * Append 90 00 to last block in a chain
        //
        // This allows the application to keep processing its response while at the driver level
        // type 4 capsule keeps the reader engaged (pun gleefully intended)
        //

        debug!("[NFC_T4DRIVER] TYPE 4 REQUEST: {:?}", request);

        if request.len() == 0 {
            debug!("[NFC_T4DRIVER] RECEIVED: Empty Frame");
            debug!("[NFC_T4DRIVER] REPLYING: Nothing");
            return 0;
        }

        match request[0] {
            0xb2 | 0xb3 /* NACK */ => {
                debug!("[NFC_T4DRIVER] RECEIVED: R-BLOCK: NACK");
                debug!("[NFC_T4DRIVER] REPLYING: S-BLOCK: WTX Request");
                self.current_field_state.set(nfc_type4::NfcType4FieldState::Type4HandshakeInProgress);
                copy_slice(&[0xf2, 0xfb][..], reply)
            },
            0xe0 /* RATS */=> {
                // CONVERSATION 1
                debug!("[NFC_T4DRIVER] RECEIVED: RATS");
                debug!("[NFC_T4DRIVER] REPLYING: ATS");
                self.current_field_state.set(nfc_type4::NfcType4FieldState::Type4HandshakeInProgress);
                copy_slice(&[0x05, 0x78, 0x80, 0xF1, 0x00][..], reply)
            }
            0xc2 /* DESELECT */ => {
                // Ignore the request
                debug!("[NFC_T4DRIVER] RECEIVED: DESELECT");
                debug!("[NFC_T4DRIVER] REPLYING: Nothing");
                0
            }
            0x02 | 0x03 /* APDU Prefix */ => if request.len() > 2 && request[2] == 0xa4 {
                // Vesion: "U2F_V2"
                debug!("[NFC_T4DRIVER] RECEIVED: I-BLOCK: (APDU) SELECT 'U2F_V2'");
                debug!("[NFC_T4DRIVER] REPLYING: I-BLOCK: (APDU) 'U2F_V2' OK");
                self.current_field_state.set(nfc_type4::NfcType4FieldState::Type4HandshakeInProgress);
                copy_slice(&[request[0],0x55, 0x32, 0x46, 0x5f, 0x56, 0x32, 0x90, 0x00,][..], reply)
            } else {
                debug!("[NFC_T4DRIVER] RECEIVED: I-BLOCK: (APDU) APPLICATION DATA");
                debug!("[NFC_T4DRIVER] REPLYING: S-BLOCK: WTX Request");
                self.current_field_state.set(nfc_type4::NfcType4FieldState::Passthrough);
                copy_slice(&[0xf2, 0xfb][..], reply)
            }
            0x26 | 0x52 | 0x50 /* REQA | WUPA | Halt */ => {
                debug!("[NFC_T4DRIVER] RECEIVED: REQA | WUPA | Halt");
                debug!("[NFC_T4DRIVER] REPLYING: Nothing");
                self.current_field_state.set(nfc_type4::NfcType4FieldState::Type4HandshakeInProgress);
                0
            },
            0xf2 /* SFRAME */ => {
                debug!("[NFC_T4DRIVER] RECEIVED: S-BLOCK: WTX Response");
                debug!("[NFC_T4DRIVER] REPLYING: Nothing");
                self.current_field_state.set(nfc_type4::NfcType4FieldState::Type4HandshakeInProgress);
                0
            },
            _ => {
                debug!("[NFC_T4DRIVER] RECEIVED: Unknown");
                debug!("[NFC_T4DRIVER] REPLYING: Nothing");
                self.current_field_state.set(nfc_type4::NfcType4FieldState::Passthrough);
                0
            },
        }
    }

    fn reset(&self) {
        self.driver_selected.set(false);
        self.current_field_state
            .set(nfc_type4::NfcType4FieldState::Off);
        self.tag_configured.set(false);
    }

    pub fn transmit_app_buffer(
        &self,
        app_id: AppId,
        app: &mut App,
        len: usize,
        chaining: bool,
    ) -> ReturnCode {
        if self.current_field_state.get() == nfc_type4::NfcType4FieldState::Off {
            return ReturnCode::ECANCEL;
        }
        // Driver not ready yet
        if !self.driver_selected.get() {
            return ReturnCode::EOFF;
        }
        if self.app_tx_in_progress.is_some() {
            return ReturnCode::EBUSY;
        }
        match app.tx_buffer.take() {
            Some(slice) => self.transmit_app_slice(app_id, app, slice, len, chaining),
            None => ReturnCode::EBUSY,
        }
    }

    pub fn transmit_app_slice(
        &self,
        app_id: AppId,
        app: &mut App,
        slice: AppSlice<Shared, u8>,
        len: usize,
        chaining: bool,
    ) -> ReturnCode {
        if self.app_tx_in_progress.is_none() {
            self.app_tx_in_progress.set(app_id);
            self.driver_tx_buffer
                .take()
                .map(|buffer| {
                    let mut len = len;
                    if self.driver_block_number.get() {
                        buffer[0] = if chaining { 0x13 } else { 0x03 };
                    } else {
                        buffer[0] = if chaining { 0x12 } else { 0x02 };
                    }
                    for (i, c) in slice.as_ref()[..len].iter().enumerate() {
                        buffer[i + 1] = *c;
                    }
                    len += 1;
                    if self.app_tx_chaining.get() && !chaining {
                        debug!("[NFC_T4DRIVER] Turning off chaining");
                        buffer[len] = 0x90;
                        buffer[len + 1] = 0x00;
                        len += 2;
                        self.driver_block_number.set(true);
                    } else {
                        self.driver_block_number
                            .set(!self.driver_block_number.get());
                    }
                    self.app_tx_chaining.set(chaining);
                    let result = self.base_nfc_driver.driver.transmit_buffer(buffer, len);
                    if result.is_err() {
                        let (err, buf) = result.unwrap_err();
                        self.driver_tx_buffer.replace(buf);
                        return err;
                    }
                    ReturnCode::SUCCESS
                })
                .unwrap()
        } else {
            app.tx_buffer = Some(slice);
            ReturnCode::EBUSY
        }
    }

    fn transmit_slice_using_driver_buffer(&'a self, slice: &[u8]) {
        if self.driver_tx_in_progress.is_some() || self.driver_tx_buffer.is_none() {
            return;
        }

        self.appid
            .take()
            .map(|appid| {
                self.driver_tx_buffer
                    .take()
                    .map(|tx_buffer| {
                        self.driver_tx_in_progress.set(appid);
                        self.transmit_slice_using_passed_buffer(tx_buffer, slice);
                    })
                    .unwrap();
                self.appid.set(appid);
            })
            .unwrap();
    }

    pub fn transmit_slice_using_passed_buffer(
        &self,
        buffer: &'static mut [u8],
        slice: &[u8],
    ) -> ReturnCode {
        for (i, c) in slice.as_ref().iter().enumerate() {
            buffer[i] = *c;
        }
        let result = self
            .base_nfc_driver
            .driver
            .transmit_buffer(buffer, slice.len());
        if result.is_err() {
            let (err, buf) = result.unwrap_err();
            self.driver_tx_buffer.replace(buf);
            return err;
        }
        ReturnCode::SUCCESS
    }

    pub fn receive_app_buffer(&self, app_id: AppId, app: &mut App, _len: usize) -> ReturnCode {
        if !self.tag_configured.get() {
            return ReturnCode::EOFF;
        }
        if self.current_field_state.get() != nfc_type4::NfcType4FieldState::On {
            return ReturnCode::ECANCEL;
        }
        // Driver not ready yet
        if !self.driver_selected.get() {
            return ReturnCode::EBUSY;
        }
        if self.driver_rx_in_progress.is_some() || self.app_rx_in_progress.is_some() {
            return ReturnCode::EBUSY;
        }
        if self.driver_tx_in_progress.is_some() {
            panic!("Trying to receive while transmit is in progress");
        }
        if app.rx_buffer.is_some() {
            self.driver_rx_buffer
                .take()
                .map(|buffer| {
                    self.app_rx_in_progress.set(app_id);
                    self.receive_in_passed_buffer(buffer)
                })
                .unwrap()
        } else {
            debug!(" >> FAIL: no application buffer supplied!");
            // Must supply buffer before performing receive operation
            ReturnCode::EINVAL
        }
    }

    fn receive_in_driver_buffer(&self) {
        if self.driver_rx_in_progress.is_some() || self.driver_rx_buffer.is_none() {
            return;
        }

        self.appid
            .take()
            .map(|appid| {
                self.driver_rx_buffer
                    .take()
                    .map(|rx_buffer| {
                        self.driver_rx_in_progress.set(appid);
                        self.receive_in_passed_buffer(rx_buffer);
                    })
                    .unwrap();
                self.appid.set(appid);
            })
            .unwrap();
    }

    pub fn receive_in_passed_buffer(&self, buffer: &'static mut [u8]) -> ReturnCode {
        let result = self.base_nfc_driver.driver.receive_buffer(buffer);
        if result.is_err() {
            let (err, buf) = result.unwrap_err();
            self.driver_rx_buffer.replace(buf);
            return err;
        }
        ReturnCode::SUCCESS
    }

    fn bubble_received_frame(&'a self, buffer: &[u8], rx_len: usize, result: ReturnCode) {
        match self.current_field_state.get() {
            nfc_type4::NfcType4FieldState::Passthrough => {
                self.app_rx_in_progress.take().map(|appid| {
                    let _ = self.application.enter(appid, |app, _| {
                        app.rx_buffer = app.rx_buffer.take().map(|mut rb| {
                            // Figure out length to copy.
                            let max_len = cmp::min(rx_len, rb.len());
                            // Copy over data to app buffer.
                            for idx in 0..max_len {
                                rb.as_mut()[idx] = buffer[idx];
                            }
                            app.rx_callback
                                .map(|mut cb| cb.schedule(result.into(), max_len, 0));
                            rb
                        });
                    });
                });
            }
            _ => {
                debug!("Passthrough mode not set, refusing to bubble the receive frame to the app");
            }
        }
    }

    fn bubble_transmitted_frame(&'a self, _buffer: &[u8], result: ReturnCode) {
        self.app_tx_in_progress.take().map(|appid| {
            let _ = self.application.enter(appid, |app, _| {
                app.tx_callback
                    .map(|mut cb| cb.schedule(result.into(), 0, 0));
            });
        });
    }

    fn frame_received(
        &'a self,
        buffer: &'static mut [u8],
        rx_len_total: usize,
        result: ReturnCode,
    ) {
        let mut apdu: [u8; MAX_LENGTH - 1] = [0; MAX_LENGTH - 1];
        let protocol_byte = buffer[0];
        let rx_len = cmp::min(rx_len_total, buffer.len());
        copy_slice(&buffer[1..rx_len], &mut apdu[..rx_len - 1]);

        let mut reply: [u8; MAX_LENGTH] = [0; MAX_LENGTH];
        let reply_len = self.generate_type4_reply(&buffer[..rx_len], &mut reply);

        self.driver_rx_buffer.replace(buffer);
        self.driver_rx_in_progress.clear();

        if protocol_byte == 0x03 {
            self.bubble_received_frame(&apdu[..rx_len - 1], rx_len - 1, result);
        }

        if rx_len > 0 {
            match protocol_byte {
                0x02 | 0x12 => {
                    self.driver_block_number.set(false);
                }
                0x03 | 0x13 => {
                    self.driver_block_number.set(true);
                }
                _ => {}
            }
        }

        if reply_len > 0 {
            self.transmit_slice_using_driver_buffer(&reply[..reply_len]);
        } else {
            self.do_next_op_async();
        }
    }

    fn frame_transmitted(&'a self, buffer: &'static mut [u8], result: ReturnCode) {
        let mut apdu: [u8; MAX_LENGTH] = [0; MAX_LENGTH];
        let tx_len = cmp::min(MAX_LENGTH, buffer.len());
        copy_slice(&buffer[..tx_len], &mut apdu[..tx_len]);

        self.driver_tx_buffer.replace(buffer);
        self.driver_tx_in_progress.clear();

        if self.app_tx_in_progress.is_some() {
            self.bubble_transmitted_frame(&apdu[..], result);
        }

        self.do_next_op_async();
    }

    fn field_lost(
        &'a self,
        rx_buffer: Option<&'static mut [u8]>,
        tx_buffer: Option<&'static mut [u8]>,
    ) {
        if rx_buffer.is_some() {
            self.driver_rx_buffer.replace(rx_buffer.unwrap());
        }
        if self.driver_rx_in_progress.is_some() {
            self.driver_rx_in_progress.clear();
        }
        if self.app_rx_in_progress.is_some() {
            self.app_rx_in_progress.take().map(|appid| {
                let _ = self.application.enter(appid, |app, _| {
                    app.rx_callback
                        .map(|mut cb| cb.schedule((ReturnCode::ECANCEL).into(), 0, 0));
                });
            });
        }

        if tx_buffer.is_some() {
            self.driver_tx_buffer.replace(tx_buffer.unwrap());
        }
        if self.driver_tx_in_progress.is_some() {
            self.driver_tx_in_progress.clear();
        }
        if self.app_tx_in_progress.is_some() {
            self.app_tx_in_progress.take().map(|appid| {
                let _ = self.application.enter(appid, |app, _| {
                    app.tx_callback
                        .map(|mut cb| cb.schedule((ReturnCode::ECANCEL).into(), 0, 0));
                });
            });
        }

        self.reset();
    }
}

impl<'a> DynamicDeferredCallClient for NfcType4Driver<'a> {
    fn call(&self, _handle: DeferredCallHandle) {
        self.do_next_op();
    }
}

impl<'a> nfc_type4::Type4Client<'a> for NfcType4Driver<'a> {
    fn frame_received(&self, _buffer: &'static mut [u8], _rx_len: usize, _result: ReturnCode) {
        debug!("Should not be called directly");
    }

    fn frame_transmitted(&self, _buffer: &'static mut [u8], _result: ReturnCode) {
        debug!("Should not be called directly");
    }
}

impl Driver for NfcType4Driver<'_> {
    /// Setup shared buffers.
    ///
    /// ### `allow_num`
    ///
    /// - `1`: Readable buffer for transmission buffer, if
    ///        provided buffer length is more than MAX_LENGTH then
    ///        return EINVAL
    /// - `2`: Writeable buffer for reception buffer, if
    ///        provided buffer length is not MAX_LENGTH then
    ///        return EINVAL
    fn allow(
        &self,
        appid: AppId,
        allow_num: usize,
        slice: Option<AppSlice<Shared, u8>>,
    ) -> ReturnCode {
        self.appid.set(appid);
        match allow_num {
            1 => self
                .application
                .enter(appid, |app, _| {
                    if let Some(buf) = &slice {
                        if buf.len() > MAX_LENGTH {
                            return ReturnCode::EINVAL;
                        }
                    }
                    app.tx_buffer = slice;
                    ReturnCode::SUCCESS
                })
                .unwrap_or_else(|err| err.into()),
            2 => self
                .application
                .enter(appid, |app, _| {
                    if let Some(buf) = &slice {
                        if buf.len() != MAX_LENGTH {
                            return ReturnCode::EINVAL;
                        }
                    }
                    app.rx_buffer = slice;
                    ReturnCode::SUCCESS
                })
                .unwrap_or_else(|err| err.into()),
            _ => ReturnCode::ENOSUPPORT,
        }
    }

    /// Setup callbacks.
    ///
    /// ### `subscribe_num`
    ///
    /// - `1`: Frame transmission completed callback
    /// - `2`: Frame reception completed callback
    fn subscribe(
        &self,
        subscribe_num: usize,
        callback: Option<Callback>,
        appid: AppId,
    ) -> ReturnCode {
        self.appid.set(appid);
        match subscribe_num {
            1 => self
                .application
                .enter(appid, |app, _| {
                    app.tx_callback = callback;
                    ReturnCode::SUCCESS
                })
                .unwrap_or_else(|err| err.into()),
            2 => self
                .application
                .enter(appid, |app, _| {
                    app.rx_callback = callback;
                    ReturnCode::SUCCESS
                })
                .unwrap_or_else(|err| err.into()),
            _ => ReturnCode::ENOSUPPORT,
        }
    }

    /// NFC control
    ///
    /// ### `command_num`
    ///
    /// - `0`: Driver check.
    /// - `1`: Transmits a buffer passed via `allow`, up to the length
    ///        passed in `arg1`.
    /// - `2`: Receives into a buffer passed via `allow`, up to the length
    ///        passed in `arg1`.
    /// - `3`: Controls tag emulation, enables it if the value in `arg1`
    ///        is positive, disables it in case of 0.
    /// - `4`: Configures the tag based on the value of `arg1`.
    fn command(&self, command_num: usize, arg1: usize, arg2: usize, appid: AppId) -> ReturnCode {
        self.appid.set(appid);
        match command_num {
            0 /* check if present */ => ReturnCode::SUCCESS,
            1 => {
                let len = arg1;
                let chaining = arg2 != 0;
                self.application.enter(appid, |app, _| {
                    self.transmit_app_buffer(appid, app, len, chaining)
                }).unwrap_or_else(|err| err.into())
            },
            2 => {
                let len = arg1;
                self.application.enter(appid, |app, _| {
                    self.receive_app_buffer(appid, app, len)
                }).unwrap_or_else(|err| err.into())
            },
            3 /* enable tag emulation */=> {
                self.application.enter(appid, |_, _| {
                    match arg1 as u8 {
                        0 /* false */ => self.base_nfc_driver.driver.deactivate(),
                        _ /* true */ => self.base_nfc_driver.driver.activate(),
                    }
                    ReturnCode::SUCCESS
                }).unwrap_or_else(|err| err.into())
            }
            4 /* tag type configuration */ => {
                self.application.enter(appid, |_, _| {
                    self.tag_configured.set(true);
                    let tag_type = arg1;
                    self.base_nfc_driver.driver.configure(tag_type as u8)
                }).unwrap_or_else(|err| err.into())
            }
            _ => ReturnCode::ENOSUPPORT,
        }
    }
}

impl<'a> nfc::Client<'a> for NfcType4Driver<'a> {
    fn tag_selected(&'a self) {
        self.driver_selected.set(true);
        // 0xfffff results in 1048575 / 13.56e6 = 77ms
        // The anti-collision is finished, we can now
        // set the frame delay to the maximum value
        self.base_nfc_driver.driver.set_framedelaymax(0xfffff);
    }

    fn tag_deactivated(&'a self) {
        self.reset();
    }

    fn field_detected(&'a self) {
        self.current_field_state
            .set(nfc_type4::NfcType4FieldState::On);
    }

    fn field_lost(
        &'a self,
        rx_buffer: Option<&'static mut [u8]>,
        tx_buffer: Option<&'static mut [u8]>,
    ) {
        self.field_lost(rx_buffer, tx_buffer)
    }

    fn frame_received(&'a self, buffer: &'static mut [u8], rx_len: usize, result: ReturnCode) {
        self.frame_received(buffer, rx_len, result)
    }

    fn frame_transmitted(&'a self, buffer: &'static mut [u8], result: ReturnCode) {
        self.frame_transmitted(buffer, result)
    }
}
