//! The exported object, and the free functions that make one.

use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use beacon_client::Client;

use crate::error::ClientException;
use crate::ledger::LedgerEntryView;
use crate::views::{MemberRowView, ProfileView, SeedsView, ServerDeviceRowView};

/// A client, and the ledger entries making it produced.
///
/// The two arrive together and there is no call that yields one without the
/// other. Founding a family is a membership event, and the ledger rule has no
/// exemptions — an app can still fail to persist the entries, but not without
/// visibly dropping them on the floor.
#[derive(uniffi::Record)]
pub struct Enrolled {
    /// The enrolled device.
    pub client: Arc<BeaconClient>,
    /// Entries to append to the activity log, stamped with the app's clock.
    pub ledger: Vec<LedgerEntryView>,
}

/// One Family Beacon device.
///
/// **Every method here blocks and none may be called from the main thread.**
/// The core is driven from WorkManager and BGTask; it owns no thread, no clock
/// and no scheduler, which is why `now` is a parameter wherever it matters.
///
/// After any call that changed state, write [`BeaconClient::snapshot`] to
/// encrypted storage. Slice 0 has no such call — enrollment is the only mutation
/// and it happens once — but the habit is the contract from slice 1 on.
#[derive(uniffi::Object)]
pub struct BeaconClient {
    /// The mutex is not defensive: UniFFI objects are shared and must be `Sync`,
    /// and the methods that mutate arrive in slice 1. Putting it in now means
    /// those land without changing the type the app already holds.
    inner: Mutex<Client>,
}

impl BeaconClient {
    fn new(client: Client) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(client),
        })
    }

    /// Borrow the composed client.
    ///
    /// Poisoning is treated as fatal rather than recovered from: a panic inside
    /// the core left some state machine half-applied, and continuing would mean
    /// guessing which. The app's crash handler is the honest place for that.
    fn locked(&self) -> std::sync::MutexGuard<'_, Client> {
        self.inner.lock().unwrap_or_else(|poisoned| {
            panic!("the core panicked in an earlier call: {poisoned}");
        })
    }
}

#[uniffi::export]
impl BeaconClient {
    /// Everything to persist, as one opaque blob.
    ///
    /// **Write it encrypted at rest** — an `EncryptedFile` or a keystore-wrapped
    /// key over app-private storage, and never a cache directory. Not
    /// belt-and-braces: the outbox seals at drain rather than at enqueue, so this
    /// contains message bodies in the clear, which for Family Beacon means
    /// positions.
    ///
    /// The two seeds are *not* in here. They belong in the keystore.
    pub fn snapshot(&self) -> Result<Vec<u8>, ClientException> {
        Ok(self.locked().snapshot()?)
    }

    /// This device's id — the principal every grant, channel and ledger entry
    /// names.
    pub fn device_id(&self) -> String {
        self.locked().device_id().to_owned()
    }

    /// The Sund account the invitation belonged to.
    ///
    /// An operational identifier, and never an answer to "who is in the family":
    /// Sund's account membership is not the authority on that.
    pub fn account_id(&self) -> String {
        self.locked().account_id().to_owned()
    }

    /// The server this device is paired with, in its canonical form.
    ///
    /// Show it where the user can compare it: the trust mode is part of the
    /// server's identity, and switching modes re-pairs every device.
    pub fn server_address(&self) -> String {
        self.locked().server_address().to_string()
    }

    /// This device's own row.
    pub fn self_description(&self) -> MemberRowView {
        self.locked().self_description().into()
    }

    /// The family, per the roster.
    ///
    /// Local and offline — a signed vouch is why each device is in this list, and
    /// no server was asked. This is the list a "family" screen renders.
    pub fn roster(&self) -> Vec<MemberRowView> {
        self.locked().roster().into_iter().map(Into::into).collect()
    }

    /// What Sund lists for this account, for reconciliation.
    ///
    /// **A separate call from [`BeaconClient::roster`], and it must stay
    /// separate in the UI too.** The two answer different questions, and a screen
    /// that merged them would hide the injected-device signal: a row here with
    /// `vouched == false` is a device the server carries that nobody in the
    /// family vouched for.
    ///
    /// # Errors
    ///
    /// Any [`ClientException`]. If it is
    /// [`ClientException::ServerIdentity`], render it as an identity failure —
    /// never as "no connection".
    pub fn server_devices(&self) -> Result<Vec<ServerDeviceRowView>, ClientException> {
        Ok(self
            .locked()
            .server_devices()?
            .into_iter()
            .map(Into::into)
            .collect())
    }
}

/// Draw two fresh Ed25519 seeds from the platform RNG.
///
/// Call once, at first run, and write both into the platform keystore before
/// enrolling. See [`SeedsView`].
///
/// # Errors
///
/// [`ClientException::Rng`] if the platform has no secure random source, which
/// is fatal: there is nothing weaker to fall back to.
#[uniffi::export]
pub fn generate_seeds() -> Result<SeedsView, ClientException> {
    Ok(beacon_client::Seeds::generate()?.into())
}

/// Enroll against a Sund server and found a family.
///
/// `address` is a `sund://host:port#fingerprint` or `sund+webpki://host[:port]`
/// string, and `invitation` is the one-time token from the server. `now` is the
/// app's clock: the core has none.
///
/// The founding device self-vouches, so the roster exists from the first run and
/// a family screen renders from real state rather than a placeholder.
///
/// # Errors
///
/// [`ClientException::Unauthorized`] if the invitation was spent, expired or
/// revoked; [`ClientException::Address`] if the address is not a Sund address;
/// [`ClientException::ServerIdentity`] if the server could not be verified —
/// which must never be shown as a connectivity failure.
#[uniffi::export]
pub fn enroll(
    address: &str,
    invitation: &str,
    profile: ProfileView,
    seeds: SeedsView,
    now: SystemTime,
) -> Result<Enrolled, ClientException> {
    let applied = Client::enroll(
        address,
        invitation,
        &profile.into(),
        &seeds.to_seeds()?,
        now,
    )?;
    Ok(Enrolled {
        client: BeaconClient::new(applied.outcome),
        ledger: applied.ledger.into_iter().map(Into::into).collect(),
    })
}

/// Reopen a device from the blob the app persisted.
///
/// Makes no request, so it works in a doze window with no network — which
/// matters, because the activity log is exactly what a family wants to read when
/// nothing else is working.
///
/// The server address comes out of the blob rather than from the caller: it is
/// part of the server's stored identity, and a client that accepted it afresh on
/// every open could be walked from pinned to WebPKI without anyone re-pairing.
///
/// Takes the blob **by value** rather than by reference. `&[u8]` binds to a
/// direct `java.nio.ByteBuffer`, which would leave the app converting in one
/// direction and not the other — [`BeaconClient::snapshot`] hands back a
/// `ByteArray`, and what comes out of storage should go straight back in. The
/// cost is one copy of a few kilobytes.
///
/// # Errors
///
/// [`ClientException::State`] for a blob this build does not speak or one that
/// does not parse, and [`ClientException::Session`] if the blob belongs to
/// another device or the seeds do not match it.
#[uniffi::export]
pub fn open(state: Vec<u8>, seeds: SeedsView) -> Result<Arc<BeaconClient>, ClientException> {
    Ok(BeaconClient::new(Client::open(&state, &seeds.to_seeds()?)?))
}
