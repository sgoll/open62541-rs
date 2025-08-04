use std::ptr::NonNull;

use open62541_sys::UA_DataTypeArray;

/// Wrapper for [`UA_DataTypeArray`] from [`open62541_sys`].
#[derive(Debug)]
pub struct DataTypeArray(NonNull<UA_DataTypeArray>);

impl DataTypeArray {
    /// Creates wrapper by taking ownership of value.
    ///
    /// # Safety
    ///
    /// Ownership of the value passes to `Self`. This must only be used for values that are not
    /// contained within other values that may be dropped.
    #[must_use]
    pub(crate) const unsafe fn from_raw(src: *mut UA_DataTypeArray) -> Self {
        Self(NonNull::new(src).unwrap())
    }

    /// Gives up ownership and returns value.
    ///
    /// The returned value must be re-wrapped with [`from_raw()`] or cleared manually to free
    /// internal allocations and not leak memory.
    #[must_use]
    pub(crate) fn into_raw(self) -> *mut UA_DataTypeArray {
        self.0.as_ptr()
    }
}

impl Drop for DataTypeArray {
    fn drop(&mut self) {
        // FIXME: Implement cleanup with `UA_cleanupDataTypeWithCustom()`.
    }
}
