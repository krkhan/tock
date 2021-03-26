//! Near Field Communication Tag (NFCT)
//!
//! Author
//! -------------------
//!
//! * Jean-Michel Picod <jmichel@google.com>
//! * Mirna Al-Shetairy <mshetairy@google.com>

use crate::nfct::NFCT;
use core::cell::Cell;
use kernel::common::cells::OptionalCell;
use kernel::hil::{nfc, nfc_type4};
use kernel::ReturnCode;

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum NfcType4State {
    Initialized,
}

pub static mut NFCT_TYPE4: NfcType4Tag = NfcType4Tag::new();

#[allow(dead_code)]
pub struct NfcType4Tag<'a> {
    client: OptionalCell<&'a dyn nfc_type4::Type4Client<'a>>,
    // To keep additional code-related states
    state: Cell<NfcType4State>,
}

impl<'a> NfcType4Tag<'a> {
    pub const fn new() -> Self {
        Self {
            client: OptionalCell::empty(),
            state: Cell::new(NfcType4State::Initialized),
        }
    }
}

impl<'a> nfc_type4::NfcType4Tag<'a> for NfcType4Tag<'a> {
    fn set_client(&self, client: &'a dyn nfc_type4::Type4Client<'a>) {
        self.client.set(client);
    }

    #[allow(dead_code, unused_variables)]
    fn transmit_buffer(
        &self,
        buf: &'static mut [u8],
        amount: usize,
    ) -> Result<usize, (ReturnCode, &'static mut [u8])> {
        unsafe {
            (&NFCT as &dyn nfc::NfcTag).transmit_buffer(buf, amount)
        }
    }

    #[allow(dead_code, unused_variables)]
    fn receive_buffer(
        &self,
        buf: &'static mut [u8],
    ) -> Result<(), (ReturnCode, &'static mut [u8])> {
        unsafe {
            (&NFCT as &dyn nfc::NfcTag).receive_buffer(buf)
        }
    }
}
