use std::{ffi::c_void, ptr, sync::Arc};

use open62541_sys::{
    UA_ServerConfig, UA_Server_runUntilInterrupt, __UA_Server_addNode, __UA_Server_write,
};

use crate::{ua, DataType, Error, ObjectNode, Result, VariableNode};

/// Builder for [`Server`].
///
/// Use this to specify additional options when building an OPC UA server.
///
/// # Examples
///
/// ```no_run
/// use open62541::ServerBuilder;
/// use std::time::Duration;
///
/// # #[tokio::main]
/// # async fn main() -> anyhow::Result<()> {
/// #
/// let server = ServerBuilder::default()
///     .server_urls(&["opc.tcp://localhost:4840"])
///     .build();
/// #
/// # Ok(())
/// # }
/// ```
#[derive(Default)]
#[allow(clippy::module_name_repetitions)]
pub struct ServerBuilder(ua::ServerConfig);

impl ServerBuilder {
    /// Sets server port.
    ///
    /// This is a shortcut for setting the corresponding server URL `opc.tcp://:<port>` and thus may
    /// overwrite any previously set server URLs from [`server_urls()`](Self::server_urls).
    #[must_use]
    pub fn port(self, port: u16) -> Self {
        self.server_urls(&[&format!("opc.tcp://:{port}")])
    }

    /// Sets server URLs.
    ///
    /// # Panics
    ///
    /// The strings must not contain any NUL bytes.
    #[must_use]
    pub fn server_urls(mut self, server_urls: &[&str]) -> Self {
        let config = self.config_mut();
        let server_urls = server_urls
            .iter()
            .map(|server_url| ua::String::new(server_url).unwrap());
        ua::Array::from_iter(server_urls)
            .move_into_raw(&mut config.serverUrlsSize, &mut config.serverUrls);
        self
    }

    /// Builds OPC UA server.
    #[must_use]
    pub fn build(self) -> (Server, ServerRunner) {
        let server = Arc::new(ua::Server::new_with_config(self.0));

        let runner = ServerRunner(Arc::clone(&server));
        let server = Server(server);
        (server, runner)
    }

    /// Access server configuration.
    fn config_mut(&mut self) -> &mut UA_ServerConfig {
        // SAFETY: Ownership is not given away.
        unsafe { self.0.as_mut() }
    }
}

/// OPC UA server.
///
/// This represents an OPC UA server. Nodes can be added through the several methods below.
///
/// Note: The server must be started with [`ServerRunner::run()`] before it can accept connections
/// from clients.
#[derive(Clone)]
pub struct Server(Arc<ua::Server>);

impl Server {
    /// Creates default server.
    ///
    /// If you need more control over the initialization, use [`ServerBuilder`] instead, and turn it
    /// into [`Server`](crate::Server) by calling [`build()`](ServerBuilder::build).
    ///
    /// # Errors
    ///
    /// See [`ServerBuilder::build()`].
    ///
    /// # Panics
    ///
    /// See [`ServerBuilder::build()`].
    #[must_use]
    pub fn new() -> (Self, ServerRunner) {
        ServerBuilder::default().build()
    }

    /// Adds object node to address space.
    ///
    /// # Errors
    ///
    /// This fails when the node cannot be added.
    pub fn add_object_node(&self, node: ObjectNode) -> Result<()> {
        let status_code = ua::StatusCode::new(unsafe {
            __UA_Server_addNode(
                // SAFETY: Cast to `mut` pointer, function is marked `UA_THREADSAFE`.
                self.0.as_ptr().cast_mut(),
                // Passing ownership is trivial with primitive value (`u32`).
                ua::NodeClass::OBJECT.into_raw(),
                node.requested_new_node_id.as_ptr(),
                node.parent_node_id.as_ptr(),
                node.reference_type_id.as_ptr(),
                // TODO: Verify that `__UA_Server_addNode()` takes ownership.
                node.browse_name.into_raw(),
                node.type_definition.as_ptr(),
                node.attributes.as_node_attributes().as_ptr(),
                ua::ObjectAttributes::data_type(),
                ptr::null_mut(),
                ptr::null_mut(),
            )
        });
        Error::verify_good(&status_code)
    }

    /// Adds variable node to address space.
    ///
    /// # Errors
    ///
    /// This fails when the node cannot be added.
    pub fn add_variable_node(&self, node: VariableNode) -> Result<()> {
        let status_code = ua::StatusCode::new(unsafe {
            __UA_Server_addNode(
                // SAFETY: Cast to `mut` pointer, function is marked `UA_THREADSAFE`.
                self.0.as_ptr().cast_mut(),
                // Passing ownership is trivial with primitive value (`u32`).
                ua::NodeClass::VARIABLE.into_raw(),
                node.requested_new_node_id.as_ptr(),
                node.parent_node_id.as_ptr(),
                node.reference_type_id.as_ptr(),
                // TODO: Verify that `__UA_Server_addNode()` takes ownership.
                node.browse_name.into_raw(),
                node.type_definition.as_ptr(),
                node.attributes.as_node_attributes().as_ptr(),
                ua::VariableAttributes::data_type(),
                ptr::null_mut(),
                ptr::null_mut(),
            )
        });
        Error::verify_good(&status_code)
    }

    /// Writes value to variable node.
    ///
    /// # Errors
    ///
    /// This fails when the variable node cannot be written.
    pub fn write_variable(&self, node_id: &ua::NodeId, value: &ua::Variant) -> Result<()> {
        let status_code = ua::StatusCode::new(unsafe {
            __UA_Server_write(
                // SAFETY: Cast to `mut` pointer, function is marked `UA_THREADSAFE`.
                self.0.as_ptr().cast_mut(),
                node_id.as_ptr(),
                // Passing ownership is trivial with primitive value (`u32`).
                ua::AttributeId::VALUE.into_raw(),
                ua::Variant::data_type(),
                value.as_ptr().cast::<c_void>(),
            )
        });
        Error::verify_good(&status_code)
    }

    /// Writes string value to variable node.
    ///
    /// This is a shortcut and roughly equivalent to the following:
    ///
    /// ```
    /// # use open62541::{ua, DataType as _, Server};
    /// #
    /// # fn write_string(
    /// #     server: &mut Server,
    /// #     node_id: &ua::NodeId,
    /// #     value: &str,
    /// # ) -> anyhow::Result<()> {
    /// let value = ua::String::new(value)?;
    /// let value = ua::Variant::init().with_scalar(&value);
    /// server.write_variable(node_id, &value)?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// This fails when the variable node cannot be written.
    pub fn write_variable_string(&self, node_id: &ua::NodeId, value: &str) -> Result<()> {
        let ua_variant = ua::Variant::scalar(ua::String::new(value)?);
        self.write_variable(node_id, &ua_variant)
    }
}

#[allow(clippy::module_name_repetitions)]
pub struct ServerRunner(Arc<ua::Server>);

impl ServerRunner {
    /// Runs the server until interrupted.
    ///
    /// The server is shut down cleanly upon receiving the `SIGINT` signal at which point the method
    /// returns.
    ///
    /// # Errors
    ///
    /// This fails when the server cannot be started.
    pub fn run(self) -> Result<()> {
        let status_code = ua::StatusCode::new(unsafe {
            UA_Server_runUntilInterrupt(
                // SAFETY: Cast to `mut` pointer. Function is not marked `UA_THREADSAFE` but we make
                // sure that it can only be invoked a single time (ownership of `ServerRunner`). The
                // examples in `open62541` demonstrate that running the server in its own thread and
                // interacting with it as we do through `Server` is okay.
                self.0.as_ptr().cast_mut(),
            )
        });
        Error::verify_good(&status_code)
    }
}
