// Path and filename constants
pub const EIF_FILE_NAME: &str = "application.eif";
pub const MANIFEST_FILE_NAME: &str = "enclaver.yaml";

pub const ENCLAVE_CONFIG_DIR: &str = "/etc/enclaver";
pub const ENCLAVE_ODYN_PATH: &str = "/sbin/odyn";

pub const RELEASE_BUNDLE_DIR: &str = "/enclave";

// Port Constants

// start "internal" ports above the 16-bit boundary (reserved for proxying TCP)
pub const STATUS_PORT: u32 = 17000;
pub const APP_LOG_PORT: u32 = 17001;
pub const HTTP_EGRESS_VSOCK_PORT: u32 = 17002;
pub const CLOCK_SYNC_PORT: u32 = 17003;

// Default TCP Port that the egress proxy listens on inside the enclave, if not
// specified in the manifest.
pub const HTTP_EGRESS_PROXY_PORT: u16 = 10000;

// The hostname to refer to the host side from inside the enclave.
pub const OUTSIDE_HOST: &str = "host";
