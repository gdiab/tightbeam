//! Native helpers for the gateway (stage 1 of the device-lifecycle follow-on):
//!
//! - `argon2id/2`: the S0.3 verifier, Argon2id with m = 64 MiB, t = 3, p = 1 and a
//!   32-byte output, on a dirty CPU scheduler. The CLI ceremonies use the same crate
//!   and parameters, so a verifier written by either side matches the other.
//! - `base_lock/1`: the S1.2 base-directory lock, an exclusive non-blocking `flock`
//!   on `<base_dir>/gateway.lock`, held for as long as the returned resource lives.

use std::fs::{File, OpenOptions};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::AsRawFd;

use argon2::{Algorithm, Argon2, Params, Version};
use rustler::{Binary, Env, NewBinary, ResourceArc};

pub const M_COST_KIB: u32 = 64 * 1024;
pub const T_COST: u32 = 3;
pub const P_COST: u32 = 1;
pub const OUTPUT_LEN: usize = 32;

mod atoms {
    rustler::atoms! {
        ok,
        error,
        held,
        bad_salt,
        kdf_failed,
    }
}

#[rustler::nif(schedule = "DirtyCpu")]
fn argon2id<'a>(env: Env<'a>, secret: Binary, salt: Binary) -> Result<Binary<'a>, rustler::Error> {
    if salt.len() != 16 {
        return Err(rustler::Error::RaiseTerm(Box::new(atoms::bad_salt())));
    }
    let params = Params::new(M_COST_KIB, T_COST, P_COST, Some(OUTPUT_LEN))
        .map_err(|_| rustler::Error::RaiseTerm(Box::new(atoms::kdf_failed())))?;
    let kdf = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; OUTPUT_LEN];
    kdf.hash_password_into(secret.as_slice(), salt.as_slice(), &mut out)
        .map_err(|_| rustler::Error::RaiseTerm(Box::new(atoms::kdf_failed())))?;
    let mut binary = NewBinary::new(env, OUTPUT_LEN);
    binary.as_mut_slice().copy_from_slice(&out);
    Ok(binary.into())
}

pub struct BaseLock {
    _file: File,
}

#[rustler::resource_impl]
impl rustler::Resource for BaseLock {}

#[rustler::nif(schedule = "DirtyIo")]
fn base_lock(path: String) -> Result<ResourceArc<BaseLock>, rustler::Error> {
    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .mode(0o600)
        .open(&path)
        .map_err(|e| rustler::Error::RaiseTerm(Box::new(format!("open:{}", e))))?;
    // An exclusive advisory lock, never waiting: the gateway refuses to start while
    // the recovery ceremony or a root-admin command holds it, and they refuse while
    // the gateway holds it.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(rustler::Error::RaiseTerm(Box::new(atoms::held())));
    }
    Ok(ResourceArc::new(BaseLock { _file: file }))
}

rustler::init!("Elixir.Tightbeam.Native");
