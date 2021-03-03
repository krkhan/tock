//! Component for NFC Tag.
//!
//! Usage
//! -----
//! ```rust
//! let nfct_type4 = components::nfct_type4::NfcType4Component::new(board_kernel, &nrf52840::nfct::NFCT).finalize(());
//! ```

use capsules::{nfc, nfc_type4};
use kernel::capabilities;
use kernel::common::dynamic_deferred_call::DynamicDeferredCall;
use kernel::component::Component;
use kernel::create_capability;
use kernel::hil::nfc_type4::NfcType4Tag;
use kernel::static_init;

#[allow(dead_code)]
pub struct NfcType4Component {
    board_kernel: &'static kernel::Kernel,
    base_driver: &'static nfc::NfcDriver<'static>,
    nfct_type4: &'static dyn NfcType4Tag<'static>,
    deferred_caller: &'static DynamicDeferredCall,
}

impl NfcType4Component {
    pub fn new(
        board_kernel: &'static kernel::Kernel,
        base_driver: &'static nfc::NfcDriver<'static>,
        nfct_type4: &'static dyn NfcType4Tag<'static>,
        deferred_caller: &'static DynamicDeferredCall,
    ) -> NfcType4Component {
        NfcType4Component {
            board_kernel,
            base_driver,
            nfct_type4,
            deferred_caller,
        }
    }
}

impl Component for NfcType4Component {
    type StaticInput = ();
    type Output = &'static nfc_type4::NfcType4Driver<'static>;

    unsafe fn finalize(self, _static_buffer: Self::StaticInput) -> Self::Output {
        let grant_cap = create_capability!(capabilities::MemoryAllocationCapability);

        let tx_buffer = static_init!([u8; nfc_type4::MAX_LENGTH], [0u8; nfc_type4::MAX_LENGTH]);
        let app_tx_buffer = static_init!([u8; nfc_type4::MAX_LENGTH], [0u8; nfc_type4::MAX_LENGTH]);
        let rx_buffer = static_init!([u8; nfc_type4::MAX_LENGTH], [0u8; nfc_type4::MAX_LENGTH]);
        let app_rx_buffer = static_init!([u8; nfc_type4::MAX_LENGTH], [0u8; nfc_type4::MAX_LENGTH]);

        let nfct_type4 = static_init!(
            // Supply to the capsule: the driver and a grant
            nfc_type4::NfcType4Driver<'static>,
            nfc_type4::NfcType4Driver::new(
                self.base_driver,
                self.nfct_type4,
                self.deferred_caller,
                tx_buffer,
                app_tx_buffer,
                rx_buffer,
                app_rx_buffer,
                self.board_kernel.create_grant(&grant_cap)
            )
        );
        nfct_type4.initialize_callback_handle(
            self.deferred_caller
                .register(nfct_type4)
                .expect("no deferred call slot available for uart mux"),
        );
        self.base_driver.driver.set_client(nfct_type4);
        self.nfct_type4.set_client(nfct_type4);
        nfct_type4
    }
}
