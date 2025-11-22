//! Security hardening configuration

use super::defaults;
use super::state::Resolved;

use libc::{MCL_CURRENT, MCL_FUTURE, PR_SET_DUMPABLE, mlockall, prctl};
use log::debug;
use nix::sys::resource::{Resource, setrlimit};

crate::define_config! {
    /// Security hardening configuration
    SecurityConfig / SecurityConfigArgs => group = "security", prefix = "", env_prefix = "SECURITY" {
        (use_mlock, "USE_MLOCK", "use-mlock": bool = defaults::SECURITY_USE_MLOCK
            => "Use mlock to prevent credentials from being swapped to disk (requires CAP_IPC_LOCK)"
        ),

        (disable_core_dumps, "DISABLE_CORE_DUMPS", "disable-core-dumps": bool = defaults::SECURITY_DISABLE_CORE_DUMPS
            => "Disable core dumps to prevent credential leakage"
        ),

        (constant_signature_counter, "CONSTANT_SIGNATURE_COUNTER", "constant-signature-counter": bool = defaults::SECURITY_CONSTANT_SIGNATURE_COUNTER
            => "Enable constant signature counter to help RPs detect cloned authenticators"
        ),

        (user_verification_registration, "USER_VERIFICATION_REGISTRATION", "user-verification-registration": bool = defaults::SECURITY_USER_VERIFICATION_REGISTRATION
            => "Show user verification notification during registration"
        ),

        (user_verification_authentication, "USER_VERIFICATION_AUTHENTICATION", "user-verification-authentication": bool = defaults::SECURITY_USER_VERIFICATION_AUTHENTICATION
            => "Show user verification notification during authentication"
        ),
    }
}

impl SecurityConfig<Resolved> {
    /// Apply all enabled security hardening measures
    pub fn apply_hardening(&self) -> Result<(), Box<dyn std::error::Error>> {
        if self.disable_core_dumps {
            self.disable_core_dumps_impl()?;
        }
        if self.use_mlock {
            self.lock_all_memory()?;
        }
        Ok(())
    }

    /// Disable core dumps to prevent credential leakage
    fn disable_core_dumps_impl(&self) -> Result<(), Box<dyn std::error::Error>> {
        debug!("Disabling core dumps to prevent credential leakage");
        setrlimit(Resource::RLIMIT_CORE, 0, 0)?;
        let r = unsafe { prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) };
        if r != 0 {
            log::warn!("prctl(PR_SET_DUMPABLE) failed: {}", r);
        }
        Ok(())
    }

    /// Lock all current and future memory mappings to prevent swapping
    fn lock_all_memory(&self) -> Result<(), Box<dyn std::error::Error>> {
        debug!("Locking all memory to prevent swapping");
        let r = unsafe { mlockall(MCL_CURRENT | MCL_FUTURE) };
        if r != 0 {
            return Err(format!(
                "mlockall failed (errno {}). Consider increasing RLIMIT_MEMLOCK.\n\
                 Hint: grant CAP_IPC_LOCK to the binary with: 'sudo setcap cap_ipc_lock=+ep $(which passless)'",
                std::io::Error::last_os_error()
            )
            .into());
        }
        Ok(())
    }
}
