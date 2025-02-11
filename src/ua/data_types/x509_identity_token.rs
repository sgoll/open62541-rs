use crate::{ua, Certificate, DataType as _};

crate::data_type!(X509IdentityToken);

impl X509IdentityToken {
    /// Sets policy ID.
    pub fn with_policy_id(mut self, policy_id: ua::String) -> Self {
        policy_id.move_into_raw(&mut self.0.policyId);
        self
    }

    /// Sets certificate data ([DER] format).
    ///
    /// [DER]: https://en.wikipedia.org/wiki/X.690#DER_encoding
    #[must_use]
    pub fn with_certificate_data(mut self, certificate_data: ua::ByteString) -> Self {
        certificate_data.move_into_raw(&mut self.0.certificateData);
        self
    }

    /// Sets certificate data.
    ///
    /// This handles certificates in both [DER] and [PEM] format.
    ///
    /// [DER]: https://en.wikipedia.org/wiki/X.690#DER_encoding
    /// [PEM]: https://en.wikipedia.org/wiki/Privacy-Enhanced_Mail
    #[cfg(feature = "x509")]
    #[must_use]
    pub fn with_certificate(self, certificate: Certificate) -> crate::Result<Self> {
        let certificate_data = certificate
            .into_x509()
            .map_err(|_| crate::Error::internal("unable to parse PEM certificate"))?
            .encode_der()
            .map_err(|_| crate::Error::internal("unable to encode DER certificate"))?;
        Ok(self.with_certificate_data(ua::ByteString::new(&certificate_data)))
    }
}
