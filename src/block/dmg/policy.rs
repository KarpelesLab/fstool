//! What a rewrite may drop: explicit choices for parts of a UDIF image
//! that cannot survive being rewritten.

use super::container::UdifInfo;
use crate::Result;

/// What to do when the source of a rewrite carries an embedded code
/// signature (`codesign` on a `.dmg`).
///
/// A signature covers the image's exact bytes, so *any* rewrite — a
/// conversion, a resize, segmenting, editing resources — invalidates it.
/// Keeping the signature bytes would only make the output look signed.
/// fstool therefore never copies them: the choice is to refuse or to
/// produce an unsigned image. **Re-signing is out of scope** — fstool
/// holds no signing identities; sign the result with `codesign` (and
/// notarize it) yourself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum SignaturePolicy {
    /// Refuse to rewrite a signed image ([`crate::Error::InvalidArgument`]).
    #[default]
    Reject,
    /// Produce an unsigned output: the signature is dropped.
    Remove,
}

/// What to do when the source records a legacy binary resource fork in
/// its trailer (`rsrc_fork_offset` / `_length`; see
/// [`UdifInfo::legacy_resource_fork`]). fstool's writers have nowhere to
/// put one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum LegacyForkPolicy {
    /// Refuse to rewrite the image.
    #[default]
    Reject,
    /// Rewrite without it. (Read it first with
    /// [`super::read_legacy_resource_fork`] to keep a copy.)
    Discard,
}

/// The data-loss choices of a UDIF rewrite. The default refuses both.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub struct UdifRewritePolicy {
    /// An embedded code signature.
    pub signature: SignaturePolicy,
    /// A legacy binary resource fork.
    pub legacy_resource_fork: LegacyForkPolicy,
}

impl UdifRewritePolicy {
    /// Allow dropping a code signature (and nothing else).
    pub fn remove_signature() -> Self {
        Self {
            signature: SignaturePolicy::Remove,
            ..Self::default()
        }
    }

    /// Check `info` against the policy before `what` rewrites it.
    pub(crate) fn check(&self, info: &UdifInfo, what: &str) -> Result<()> {
        if let Some(sig) = info.code_signature()
            && self.signature == SignaturePolicy::Reject
        {
            return Err(crate::Error::InvalidArgument(format!(
                "dmg: the image is code-signed ({} signature bytes at offset {}); {what} would \
                 invalidate the signature. Choose SignaturePolicy::Remove (CLI: \
                 --remove-signature) to write an unsigned image, then re-sign it with codesign",
                sig.length, sig.offset
            )));
        }
        if let Some((off, len)) = info.legacy_resource_fork()
            && self.legacy_resource_fork == LegacyForkPolicy::Reject
        {
            return Err(crate::Error::InvalidArgument(format!(
                "dmg: the image carries a legacy binary resource fork ({len} bytes at offset \
                 {off}) that {what} cannot keep. Choose LegacyForkPolicy::Discard (CLI: \
                 --discard-legacy-resource-fork) to drop it"
            )));
        }
        Ok(())
    }
}
