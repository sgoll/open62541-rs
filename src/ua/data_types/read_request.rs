use crate::ua;

crate::data_type!(ReadRequest, UA_ReadRequest, UA_TYPES_READREQUEST);

impl ReadRequest {
    #[must_use]
    pub fn with_nodes_to_read(mut self, nodes_to_read: &[ua::ReadValueId]) -> Self {
        let array = ua::Array::from_slice(nodes_to_read);

        // Make sure to clean up any previous value in target.
        let _unused = ua::Array::<ua::ReadValueId>::from_raw_parts(
            self.0.nodesToRead,
            self.0.nodesToReadSize,
        );

        // Transfer ownership from `array` into `self`.
        let (size, ptr) = array.into_raw_parts();
        self.0.nodesToReadSize = size;
        self.0.nodesToRead = ptr;

        self
    }
}
