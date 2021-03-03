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

pub const MAX_LENGTH: usize = base_nfc_capsule::MAX_LENGTH;

#[allow(dead_code)]
pub struct NfcType4Driver<'a> {
    base_nfc_driver: &'a base_nfc_capsule::NfcDriver<'a>,
    driver: &'a dyn nfc_type4::NfcType4Tag<'a>,
    deferred_caller: &'static DynamicDeferredCall,
    deferred_call_handle: OptionalCell<DeferredCallHandle>,
    application: Grant<App>,
    app_tx_in_progress: OptionalCell<AppId>,
    tx_in_progress: OptionalCell<AppId>,
    tx_buffer: TakeCell<'static, [u8]>,
    app_tx_buffer: TakeCell<'static, [u8]>,
    rx_in_progress: OptionalCell<AppId>,
    app_rx_in_progress: OptionalCell<AppId>,
    rx_buffer: TakeCell<'static, [u8]>,
    app_rx_buffer: TakeCell<'static, [u8]>,
    driver_selected: Cell<bool>,
    tag_configured: Cell<bool>,
    current_field: Cell<nfc_type4::NfcType4FieldState>,
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
        tx_buffer: &'static mut [u8; MAX_LENGTH],
        app_tx_buffer: &'static mut [u8; MAX_LENGTH],
        rx_buffer: &'static mut [u8; MAX_LENGTH],
        app_rx_buffer: &'static mut [u8; MAX_LENGTH],
        grant: Grant<App>,
    ) -> NfcType4Driver<'a> {
        NfcType4Driver {
            base_nfc_driver,
            driver,
            deferred_caller,
            deferred_call_handle: OptionalCell::empty(),
            application: grant,
            app_tx_in_progress: OptionalCell::empty(),
            tx_in_progress: OptionalCell::empty(),
            tx_buffer: TakeCell::new(tx_buffer),
            app_tx_buffer: TakeCell::new(app_tx_buffer),
            rx_in_progress: OptionalCell::empty(),
            app_rx_in_progress: OptionalCell::empty(),
            rx_buffer: TakeCell::new(rx_buffer),
            app_rx_buffer: TakeCell::new(app_rx_buffer),
            driver_selected: Cell::new(false),
            tag_configured: Cell::new(false),
            current_field: Cell::new(nfc_type4::NfcType4FieldState::None),
            appid: OptionalCell::empty(),
        }
    }

    pub fn initialize_callback_handle(&self, handle: DeferredCallHandle) {
        self.deferred_call_handle.replace(handle);
    }

    fn do_next_op(&self) {
        debug!("::::> [C][N1] DEFERRED CALL INVOKED");
        if self.rx_in_progress.is_some() {
            debug!("::> [C][N2] RX ALREADY IN PROGRESS, NOT SCHEDULING NEXT OP");
            return;
        }
        if self.tx_in_progress.is_some() {
            debug!("::> [C][N3] TX ALREADY IN PROGRESS, NOT SCHEDULING NEXT OP");
            return;
        }
        if self.app_tx_in_progress.is_some() {
            debug!("::> [C][N4] APP TX ALREADY IN PROGRESS, NOT SCHEDULING NEXT OP");
            return;
        }
        debug!("::::> [C][N5] NOTHING IS IN PROGRESS, SCHEDULING SELF RECEIVE");
        self.receive_self_packet();
    }

    fn do_next_op_async(&self) {
        self.deferred_call_handle
            .map(|handle| self.deferred_caller.set(*handle));
    }

    fn generate_type4_reply(&self, request: &[u8], reply: &mut [u8]) -> usize {
        // CONVERSATION 1
        // READER -> TAG: RATS
        // TAG -> READER: ATS
        //
        // CONVERSATION 2
        // READER -> TAG: CAN YOU SELECT NFC TYPE 4
        // TAG -> READER: YES, WE CAN! 0x9000
        //
        // CONVERSATION 3
        // READER -> TAG: SELECT FILE CAPAGBILITY CONTAINER
        // TAG -> READER: OK FILE SELECTED
        //
        // CONVERSATION 4
        // READER -> TAG: READ FROM THE SELECTED FILE AT OFFSET 0
        // TAG -> READER: HERE ARE THE CONTENTS OF THE SELECTED FILE (CAPABILITY CONTAINER)
        //
        // CONVERSATION 5
        // READER -> TAG: SELECT FILE NDEF
        // TAG -> READER: OK FILE SELECTED (BUT REALLY NOT!)
        //
        // CONVERSATION 6.1
        // READER -> TAG: READ 2 BYTES FROM THE SELECTED FILE (NDEF) AT OFFSET 0 TO GET FILE SIZE
        // TAG -> READER: HERE ARE THE CONTENTS OF THE SELECTED FILE (NDEF)
        //
        // CONVERSATION 6.2
        // READER -> TAG: READ N BYTES FROM THE SELECTED FILE (NDEF) AT OFFSET 2
        // TAG -> READER: HERE ARE THE CONTENTS OF THE SELECTED FILE (NDEF)
        //
        // CONVERASTION 7
        // READER -> TAG: SELECT APPLET FIDO_2_0
        // TAG -> READER: OK I HAVE SELECTED FIDO_2_0
        //
        // OK, ONWARDS TO THE APPLICATION

        if request.len() == 0 {
            debug!("XX> [C] EMPTY FRAME");
            return 0;
        }

        if request.len() < 3 && (request[0] == 0x02 || request[0] == 0x03) {
            debug!("XX> [C] FRAME IS TOO SHORT, ASSUMING IT'S S-FRAME");
            return copy_slice(&[0xf2, 0xfb][..], reply);
        }

        if request[0] == 0xB3 {
            debug!("XX> [C] NEGATIVE ACK RECEIVED, TROUBLE AHEAD");
            return copy_slice(&[0xf2, 0xfb][..], reply);
        }

        if request[0] == 0xA2 || request[0] == 0xB2 || request[0] == 0xC2 || request[0] == 0xD2 {
            debug!("XX> [C] GOOD THINGS ARE HAPPENING, CONTINUING");
            return copy_slice(&[0xf2, 0xfb][..], reply);
        }

        match request[0] {
            0xe0 /* RATS */=> {
                // CONVERSATION 1
                debug!("XX> [C] RATS, CONVERSATION 1");
                self.current_field.set(nfc_type4::NfcType4FieldState::Type4HandshakeInProgress);
                copy_slice(&[0x05, 0x78, 0x80, 0xF1, 0x00][..], reply)
            }
            0xc2 /* DESELECT */ => {
                // Ignore the request
                debug!("XX> [C] DESELECT");
                // self.current_field.set(nfc_type4::NfcType4FieldState::Type4HandshakeInProgress);
                // copy_slice(&[0x6A, 0x81][..], reply)
                0
            }
            0x02 | 0x03 /* APDU Prefix */ => match request[2] {
                // If the received packet is applet selection command (FIDO 2)
                0xa4 /* SELECT */ => if request[3] == 0x04 && request[5] == 0x08 && request[6] == 0xa0 {
                    // CONVERSATION 7
                    // Vesion: "U2F_V2"
                    debug!("XX> [C] APDU -> SELECT, CONVERSATION 7");
                    self.current_field.set(nfc_type4::NfcType4FieldState::Type4HandshakeInProgress);
                    copy_slice(&[request[0],0x55, 0x32, 0x46, 0x5f, 0x56, 0x32, 0x90, 0x00,][..], reply)
                } else if (request[6] == 0xd2 && request[7] == 0x76) || (request[6] == 0xe1 && (request[7] == 0x03 || request[7] == 0x04)){
                    // CONVERSATION 2
                    debug!("XX> [C] APDU -> SELECT, CONVERSATION 2");
                    self.current_field.set(nfc_type4::NfcType4FieldState::Type4HandshakeInProgress);
                    copy_slice(&[request[0], 0x90, 0x00][..], reply)
                } else /* Unknown file */ {
                    debug!("XX> [C] APDU -> SELECT, UNKNOWN");
                    self.current_field.set(nfc_type4::NfcType4FieldState::Type4HandshakeInProgress);
                    copy_slice(&[request[0], 0x6a, 0x82][..], reply)
                }
                0xb0 /* READ */ =>  match request[5] {
                    0x02 => {
                        // CONVERSATION 6.1
                        debug!("XX> [C] APDU -> READ, CONVERSATION 6.1");
                        self.current_field.set(nfc_type4::NfcType4FieldState::Type4HandshakeInProgress);
                        copy_slice(&[request[0], 0x12, 0x90, 0x00,][..], reply)
                    }
                    0x12 => {
                        // CONVERSATION 6.2
                        debug!("XX> [C] APDU -> READ, CONVERSATION 6.2");
                        self.current_field.set(nfc_type4::NfcType4FieldState::Type4HandshakeInProgress);
                        copy_slice(&[request[0], 0xd1, 0x01, 0x0e, 0x55, 0x77, 0x77, 0x77, 0x2e, 0x6f, 0x70, 0x65,
                            0x6e, 0x73, 0x6b, 0x2e, 0x64, 0x65, 0x76, 0x90, 0x00,][..], reply)
                    }
                    0x0f => {
                        // CONVERSATION 4
                        debug!("XX> [C] APDU -> READ, CONVERSATION 4");
                        self.current_field.set(nfc_type4::NfcType4FieldState::Type4HandshakeInProgress);
                        copy_slice(&[request[0], 0x00, 0x0f, 0x20, 0x00, 0x7f, 0x00, 0x7f, 0x04, 0x06, 0xe1, 0x04,
                            0x00, 0x7f, 0x00, 0x00, 0x90, 0x00,][..], reply)
                    }
                    _ => {
                        // CONVERSATION 3 & 5
                        if request[1] == 0x00 && request[2] == 0x01 && request[3] == 0x00 {
                            debug!("XX> [C] APDU -> READ -> ELSE, SETTING PASSTHROUGH");
                            self.current_field.set(nfc_type4::NfcType4FieldState::Passthrough(request[0]));
                            0
                        } else {
                            debug!("XX> [C] APDU -> READ -> ELSE, CONVERSATION 3/5");
                            self.current_field.set(nfc_type4::NfcType4FieldState::Type4HandshakeInProgress);
                            copy_slice(&[request[0], 0x90, 0x00][..], reply)
                        }
                    }
                }
                _ => {
                    if request[1] == 0x00 && request[2] == 0x01 && request[3] == 0x00 {
                        debug!("XX> [C] APDU -> ELSE, SETTING PASSTHROUGH");
                        self.current_field.set(nfc_type4::NfcType4FieldState::Passthrough(request[0]));
                        copy_slice(&[0xf2, 0xfb][..], reply)
                    } else {
                        debug!("XX> [C] APDU -> ELSE, BOGUS ACKNOWLEDGE");
                        self.current_field.set(nfc_type4::NfcType4FieldState::Type4HandshakeInProgress);
                        copy_slice(&[request[0], 0x90, 0x00][..], reply)
                    }
                }
            }
            0x26 | 0x52 | 0x50 /* REQA | WUPA | Halt */ => {
                debug!("XX> [C] REQA | WUPA | Halt");
                self.current_field.set(nfc_type4::NfcType4FieldState::Type4HandshakeInProgress);
                0
            },
            0xf2 /*SFRAME*/ => {
                debug!("XX> [C] SFRAME");
                self.current_field.set(nfc_type4::NfcType4FieldState::Type4HandshakeInProgress);
                copy_slice(&[0xf2, 0xfb][..], reply)
            },
            _ => {
                debug!("XX> [C] ELSE, SETTING PASSTHROUGH");
                self.current_field.set(nfc_type4::NfcType4FieldState::Passthrough(request[0]));
                0
            },
        }
    }

    fn reset(&self) {
        self.driver_selected.set(false);
        self.current_field.set(nfc_type4::NfcType4FieldState::Off);
        self.tag_configured.set(false);
    }

    pub fn transmit_slice(&self, buffer: &'static mut [u8], slice: &[u8]) -> ReturnCode {
        debug!("----> [C] TRANSMITTING TYPE 4 RESPONSE: {:02X?}", &slice);
        for (i, c) in slice.as_ref().iter().enumerate() {
            buffer[i] = *c;
        }
        let result = self
            .base_nfc_driver
            .driver
            .transmit_buffer(buffer, slice.len());
        if result.is_err() {
            debug!("----> [C] ERROR TRANSMITTING TYPE 4 RESPONSE");
            let (err, buf) = result.unwrap_err();
            self.tx_buffer.replace(buf);
            return err;
        }
        debug!("----> [C] SUCCESSFULLY TRANSMITTED TYPE 4 RESPONSE");
        ReturnCode::SUCCESS
    }

    pub fn transmit_internal(
        &self,
        buffer: &'static mut [u8],
        slice: AppSlice<Shared, u8>,
        len: usize,
    ) -> ReturnCode {
        debug!("----> [C][TI1] TRANSMITTING {} BYTES FROM THE APP", len);
        for (i, c) in slice.as_ref().iter().enumerate() {
            buffer[i] = *c;
        }
        let result = self
            .base_nfc_driver
            .driver
            .transmit_buffer(buffer, slice.len());
        if result.is_err() {
            let (err, buf) = result.unwrap_err();
            self.tx_buffer.replace(buf);
            return err;
        }
        ReturnCode::SUCCESS
    }

    /// Internal helper function for setting up frame transmission
    pub fn transmit_new(&self, app_id: AppId, app: &mut App, len: usize) -> ReturnCode {
        if self.current_field.get() == nfc_type4::NfcType4FieldState::Off {
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
            Some(slice) => self.transmit(app_id, app, slice, len),
            None => ReturnCode::EBUSY,
        }
    }

    /// Internal helper function for data transmission
    pub fn transmit(
        &self,
        app_id: AppId,
        app: &mut App,
        slice: AppSlice<Shared, u8>,
        len: usize,
    ) -> ReturnCode {
        if self.app_tx_in_progress.is_none() {
            self.app_tx_in_progress.set(app_id);
            self.app_tx_buffer
                .take()
                .map(|buffer| self.transmit_internal(buffer, slice, len))
                .unwrap()
        } else {
            app.tx_buffer = Some(slice);
            ReturnCode::EBUSY
        }
    }

    pub fn receive_slice(&self, buffer: &'static mut [u8]) -> ReturnCode {
        debug!("====> [C] RECEIVING TYPE 4 RESPONSE");
        let result = self.base_nfc_driver.driver.receive_buffer(buffer);
        if result.is_err() {
            debug!("====> [C] ERROR RECEIVING TYPE 4 RESPONSE");
            let (err, buf) = result.unwrap_err();
            self.rx_buffer.replace(buf);
            return err;
        }
        debug!("====> [C] SUCCESSFULLY KICKED OFF TYPE 4 RECEIVE");
        ReturnCode::SUCCESS
    }

    pub fn receive_internal(&self, buffer: &'static mut [u8]) -> ReturnCode {
        let result = self.base_nfc_driver.driver.receive_buffer(buffer);
        if result.is_err() {
            let (err, buf) = result.unwrap_err();
            self.rx_buffer.replace(buf);
            return err;
        }
        ReturnCode::SUCCESS
    }

    /// Internal helper function for starting a receive operation
    pub fn receive_new(&self, app_id: AppId, app: &mut App, _len: usize) -> ReturnCode {
        if !self.tag_configured.get() {
            return ReturnCode::EOFF;
        }
        if self.current_field.get() != nfc_type4::NfcType4FieldState::On {
            return ReturnCode::ECANCEL;
        }
        // Driver not ready yet
        if !self.driver_selected.get() {
            return ReturnCode::EBUSY;
        }
        if self.rx_in_progress.is_some() || self.app_rx_in_progress.is_some() {
            return ReturnCode::EBUSY;
        }
        if self.tx_in_progress.is_some() {
            panic!("Trying to receive while transmit is in progress");
        }
        if app.rx_buffer.is_some() {
            self.app_rx_buffer
                .take()
                .map(|buffer| {
                    self.app_rx_in_progress.set(app_id);
                    self.receive_internal(buffer)
                })
                .unwrap()
        } else {
            debug!(" >> FAIL: no application buffer supplied!");
            // Must supply buffer before performing receive operation
            ReturnCode::EINVAL
        }
    }

    fn bubble_received_frame(&'a self, buffer: &[u8], rx_len: usize, result: ReturnCode) {
        match self.current_field.get() {
            nfc_type4::NfcType4FieldState::Passthrough(_) => {
                debug!("==> [C][RB1] TYPE 4 PASSTHROUGH MODE WAS SET, BUBBLING UP THE BUFFER JUST RECEIVED ({} bytes)", rx_len);

                self.app_rx_in_progress.take().map(|appid| {
                    let _ = self.application.enter(appid, |app, _| {
                        app.rx_buffer = app.rx_buffer.take().map(|mut rb| {
                            // Figure out length to copy.
                            let max_len = cmp::min(rx_len, rb.len());
                            // Copy over data to app buffer.
                            for idx in 0..max_len {
                                rb.as_mut()[idx] = buffer[idx];
                            }
                            debug!("==> [C][RB2] TYPE 4 BUFFER COPIED TO APP BUFFER, SCHEDULING CALLBACK ({} bytes)", rx_len);
                            app.rx_callback
                                .map(|mut cb| cb.schedule(result.into(), max_len, 0));
                            rb
                        });
                    });
                });
            }
            _ => {
                debug!("==> [C][RB3] TYPE 4 PASSTHROUGH MODE WAS NOT SET, LEAVING THE JUST RECEIVED BUFFER ALONE ({} bytes)", rx_len);
            }
        }
    }

    fn bubble_transmitted_frame(&'a self, _buffer: &[u8], result: ReturnCode) {
        debug!("--> [C][TB1] TYPE 4 BUBBLING UP TRANSMITTED FRAME");
        self.app_tx_in_progress.take().map(|appid| {
            let _ = self.application.enter(appid, |app, _| {
                app.tx_callback
                    .map(|mut cb| cb.schedule(result.into(), 0, 0));
            });
        });
    }

    fn transmit_self_packet(&'a self, slice: &[u8]) {
        if self.tx_in_progress.is_some() {
            debug!("--> [C][TH1] SELF TRANSMIT ALREADY IN PROGRESS, REFUSING TO TRANSMIT");
            return;
        }

        if self.tx_buffer.is_none() {
            debug!("--> [C][TH2] SELF TX BUFFER NOT AVAILAIBLE, REFUSING TO TRANSMIT");
            return;
        }

        self.appid
            .take()
            .map(|appid| {
                self.tx_buffer
                    .take()
                    .map(|tx_buffer| {
                        debug!("--> [C][TH3] TRANSMITTING TYPE 4 SLICE");
                        self.tx_in_progress.set(appid);
                        self.transmit_slice(tx_buffer, slice);
                    })
                    .unwrap();
                self.appid.set(appid);
            })
            .unwrap();
    }

    fn receive_self_packet(&self) {
        if self.rx_in_progress.is_some() {
            debug!("==> [C][RH1] SELF RECEIVE ALREADY IN PROGRESS, REFUSING TO RECEIVE AGAIN");
            return;
        }

        if self.rx_buffer.is_none() {
            debug!("==> [C][RH2] SELF RX BUFFER NOT AVAILAIBLE, REFUSING TO RECEIVE");
            return;
        }

        self.appid
            .take()
            .map(|appid| {
                self.rx_buffer
                    .take()
                    .map(|rx_buffer| {
                        debug!("==> [C][RH3] RECEIVING TYPE 4 SLICE");
                        self.rx_in_progress.set(appid);
                        self.receive_slice(rx_buffer);
                    })
                    .unwrap();
                self.appid.set(appid);
            })
            .unwrap();
    }

    fn frame_received_helper(
        &'a self,
        buffer: &'static mut [u8],
        rx_len_total: usize,
        result: ReturnCode,
    ) {
        let mut bufcopy: [u8; base_nfc_capsule::MAX_LENGTH] = [0; base_nfc_capsule::MAX_LENGTH];
        let rx_len = cmp::min(rx_len_total, buffer.len());
        copy_slice(&buffer[..rx_len], &mut bufcopy[..rx_len]);

        debug!(
            "==> [C][R1] TYPE 4 FRAME RECEIVED: {:02X?}",
            &buffer[..rx_len]
        );

        if self.rx_buffer.is_none() {
            debug!("==> [C][R2] SELF RX_BUFFER IS EMPTY, REPLACING");
            self.rx_buffer.replace(buffer);
        } else {
            debug!("==> [C][R3] APP RX_BUFFER IS EMPTY, REPLACING");
            self.app_rx_buffer.replace(buffer);
        }

        debug!("==> [C][R4] CLEARING SELF RX_IN_PROGRESS");
        self.rx_in_progress.clear();

        let mut reply: [u8; MAX_LENGTH] = [0; MAX_LENGTH];
        let reply_len = self.generate_type4_reply(&bufcopy[..rx_len], &mut reply);

        if bufcopy[0] == 0x03 {
            for i in 0..rx_len - 1 {
                bufcopy[i] = bufcopy[i + 1];
            }
            self.bubble_received_frame(&bufcopy[..], rx_len, result);
        }

        if reply_len > 0 {
            debug!(
                "==> [C][R5] TRANSMITTING TYPE 4 REPLY: {:02X?}",
                &reply[..reply_len]
            );
            self.transmit_self_packet(&reply[..reply_len]);
        } else {
            debug!("==> [C][R6] SCHEDULING NEXT OP ASYNCLY");
            self.do_next_op_async();
        }
    }

    fn frame_transmitted_helper(&'a self, buffer: &'static mut [u8], result: ReturnCode) {
        let mut bufcopy: [u8; base_nfc_capsule::MAX_LENGTH] = [0; base_nfc_capsule::MAX_LENGTH];
        let tx_len = cmp::min(base_nfc_capsule::MAX_LENGTH, buffer.len());
        copy_slice(&buffer[..tx_len], &mut bufcopy[..tx_len]);

        if buffer[0] != 0xf2 {
            debug!(
                "--> [C][T1] TYPE 4 REPLY TRANSMITTED ({} bytes): {:02X?} ...",
                tx_len,
                &buffer[..8]
            );
        }

        if self.app_tx_buffer.is_none() {
            debug!("--> [C][T2] APP TX_BUFFER IS EMPTY, REPLACING");
            self.app_tx_buffer.replace(buffer);
        } else {
            debug!("--> [C][T3] SELF TX_BUFFER IS EMPTY, REPLACING");
            self.tx_buffer.replace(buffer);
        }

        debug!("--> [C][T4] CLEARING SELF TX_IN_PROGRESS");
        self.tx_in_progress.clear();

        if bufcopy[0] == 0x03 || bufcopy[0] == 0x13 || bufcopy[0] == 0x02 || bufcopy[0] == 0x12 {
            self.bubble_transmitted_frame(&bufcopy[..], result);
        }

        debug!("--> [C][T5] SCHEDULING NEXT OP ASYNCLY");
        self.do_next_op_async();
    }

    fn field_lost_helper(
        &'a self,
        rx_buffer: Option<&'static mut [u8]>,
        tx_buffer: Option<&'static mut [u8]>,
    ) {
        debug!(
            "..> [C][L1] RX [ARG][SELF|PROGRESS] [APP|APP_PROGRESS]: [{}] [{}|{}] [{}|{}]",
            rx_buffer.is_some(),
            self.rx_buffer.is_some(),
            self.rx_in_progress.is_some(),
            self.app_rx_buffer.is_some(),
            self.app_rx_in_progress.is_some()
        );
        debug!(
            "..> [C][L2] TX [ARG][SELF|PROGRESS] [APP|APP_PROGRESS]: [{}] [{}|{}] [{}|{}]",
            tx_buffer.is_some(),
            self.tx_buffer.is_some(),
            self.tx_in_progress.is_some(),
            self.app_tx_buffer.is_some(),
            self.app_tx_in_progress.is_some()
        );

        if rx_buffer.is_none() && self.rx_buffer.is_none() {
            debug!("..> [C][L3] NO RX BUFFER RECEIVED IN ARG AND SELF RX BUFFER IS EMPTY");
        }
        if tx_buffer.is_none() && self.tx_buffer.is_none() {
            debug!("..> [C][L4] NO TX BUFFER RECEIVED IN ARG AND SELF TX BUFFER IS EMPTY");
        }

        if rx_buffer.is_some() {
            if self.rx_buffer.is_none() {
                self.rx_buffer.replace(rx_buffer.unwrap());
            } else {
                self.app_rx_buffer.replace(rx_buffer.unwrap());
            }
        }
        if self.rx_in_progress.is_some() {
            self.rx_in_progress.clear();
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
            if self.tx_buffer.is_none() {
                self.tx_buffer.replace(tx_buffer.unwrap());
            } else {
                self.app_tx_buffer.replace(tx_buffer.unwrap());
            }
        }
        if self.tx_in_progress.is_some() {
            self.tx_in_progress.clear();
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
        debug!("::::> [C][X] TYPE 4 CLIENT INVOKED, FRAME RECEIVED, WHAT THE FUCK IS HAPPENING?");
    }

    fn frame_transmitted(&self, _buffer: &'static mut [u8], _result: ReturnCode) {
        debug!(
            "::::> [C][X] TYPE 4 CLIENT INVOKED, FRAME TRANSMITTED, WHAT THE FUCK IS HAPPENING?"
        );
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
    fn command(&self, command_num: usize, arg1: usize, _: usize, appid: AppId) -> ReturnCode {
        self.appid.set(appid);
        match command_num {
            0 /* check if present */ => ReturnCode::SUCCESS,
            1 => {
                let len = arg1;
                self.application.enter(appid, |app, _| {
                    self.transmit_new(appid, app, len)
                }).unwrap_or_else(|err| err.into())
            },
            2 => {
                let len = arg1;
                self.application.enter(appid, |app, _| {
                    self.receive_new(appid, app, len)
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
        self.current_field.set(nfc_type4::NfcType4FieldState::On);
    }

    fn field_lost(
        &'a self,
        rx_buffer: Option<&'static mut [u8]>,
        tx_buffer: Option<&'static mut [u8]>,
    ) {
        self.field_lost_helper(rx_buffer, tx_buffer)
    }

    fn frame_received(&'a self, buffer: &'static mut [u8], rx_len: usize, result: ReturnCode) {
        self.frame_received_helper(buffer, rx_len, result)
    }

    fn frame_transmitted(&'a self, buffer: &'static mut [u8], result: ReturnCode) {
        self.frame_transmitted_helper(buffer, result)
    }
}
