//! JVM class-FQN → SDK identity classification.
//!
//! "Which JVM class prefix maps to which SDK" is DEX-format domain
//! knowledge — class FQNs are DEX-encoded identifiers, and the
//! encyclopedia of known-SDK prefixes belongs in the bundle crate
//! that parses them. The cross-layer [`SdkId`] enum stays in
//! [`droidsaw_common`] (it's a Finding-payload type consumed by the
//! cross-layer suppression pipeline); the
//! **table** of class-prefix → SdkId moves here.
//!
//! Mirrors the "common hosts algorithms, bundles host instructions"
//! "common hosts algorithms, bundles host instructions" rule.
//!
//! **Scope**: pure pattern-match. No regex compilation, no I/O.

use droidsaw_common::provenance::SdkId;

/// Classify a fully-qualified JVM class name (FQN) into an [`SdkId`].
///
/// Returns the **most specific** match — order matters in the table
/// below so `com.amazon.identity.*` beats a hypothetical broader
/// `com.amazon.*`. Returns `None` if the FQN doesn't match any known
/// SDK prefix.
///
/// # Examples
///
/// ```
/// use droidsaw_dex::sdk_inventory::classify_fqn;
/// use droidsaw_common::provenance::SdkId;
///
/// assert_eq!(
///     classify_fqn("org.bouncycastle.crypto.engines.AESEngine"),
///     Some(SdkId::BouncyCastle),
/// );
/// assert_eq!(
///     classify_fqn("software.amazon.awssdk.regions.Region"),
///     Some(SdkId::AwsSdkJava),
/// );
/// assert_eq!(
///     classify_fqn("com.amazon.identity.auth.device.token.OAuthTokenManager"),
///     Some(SdkId::AmazonIdentitySdk),
/// );
/// assert_eq!(classify_fqn("com.example.MyClass"), None);
/// ```
#[must_use]
pub fn classify_fqn(fqn: &str) -> Option<SdkId> {
    // Order matters: longer / more-specific prefixes first so
    // `com.amazon.identity.*` beats a hypothetical `com.amazon.*`.
    if fqn.starts_with("org.bouncycastle.") {
        return Some(SdkId::BouncyCastle);
    }
    if fqn.starts_with("software.amazon.awssdk.") || fqn.starts_with("com.amazonaws.") {
        return Some(SdkId::AwsSdkJava);
    }
    if fqn.starts_with("aws_sdk_") {
        return Some(SdkId::AwsSdkRust);
    }
    if fqn.starts_with("com.nimbusds.jose.") || fqn.starts_with("com.nimbusds.jwt.") {
        return Some(SdkId::JoseLibrary);
    }
    if fqn.starts_with("com.stripe.android.")
        || fqn.starts_with("com.stripe.stripeterminal.")
    {
        return Some(SdkId::StripeSdk);
    }
    if fqn.starts_with("com.google.firebase.crashlytics.") {
        return Some(SdkId::Crashlytics);
    }
    if fqn.starts_with("com.appsflyer.") {
        return Some(SdkId::AppsFlyer);
    }
    if fqn.starts_with("com.fingerprintjs.android.fpjs_pro.") {
        return Some(SdkId::FingerprintJsPro);
    }
    if fqn.starts_with("com.shapesecurity.")
        || fqn.starts_with("com.f5.apiguard3.")
        || fqn.starts_with("com.f5.ApiGuard3.")
    {
        return Some(SdkId::F5ApiGuard3);
    }
    if fqn.starts_with("com.microblink.") {
        return Some(SdkId::Microblink);
    }
    if fqn.starts_with("com.amazon.identity.") {
        return Some(SdkId::AmazonIdentitySdk);
    }
    if fqn == "io.netty.handler.ssl.util.SelfSignedCertificate"
        || fqn.starts_with("io.netty.handler.ssl.util.SelfSignedCertificate$")
    {
        return Some(SdkId::NettySelfSigned);
    }
    if fqn.starts_with("com.geocomply.") {
        return Some(SdkId::GeoComply);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bouncycastle_root_class() {
        assert_eq!(
            classify_fqn("org.bouncycastle.crypto.engines.AESEngine"),
            Some(SdkId::BouncyCastle),
        );
    }

    #[test]
    fn bouncycastle_pqc_subpackage() {
        assert_eq!(
            classify_fqn("org.bouncycastle.pqc.crypto.picnic.PicnicTest"),
            Some(SdkId::BouncyCastle),
        );
    }

    #[test]
    fn aws_sdk_java_v2_prefix() {
        assert_eq!(
            classify_fqn("software.amazon.awssdk.regions.Region"),
            Some(SdkId::AwsSdkJava),
        );
    }

    #[test]
    fn aws_sdk_java_legacy_prefix() {
        assert_eq!(
            classify_fqn("com.amazonaws.auth.AWSCredentials"),
            Some(SdkId::AwsSdkJava),
        );
    }

    #[test]
    fn aws_sdk_rust_prefix() {
        assert_eq!(
            classify_fqn("aws_sdk_s3::Client"),
            Some(SdkId::AwsSdkRust),
        );
    }

    #[test]
    fn amazon_identity_beats_hypothetical_amazon_wildcard() {
        // Critical ordering test: `com.amazon.identity.*` MUST match
        // before any hypothetical `com.amazon.*` rule would. Both this
        // and the AwsSdkJava test above guard the longer-prefix-first
        // ordering invariant.
        assert_eq!(
            classify_fqn("com.amazon.identity.auth.device.token.OAuthTokenManager"),
            Some(SdkId::AmazonIdentitySdk),
        );
    }

    #[test]
    fn jose_library_jose_subpackage() {
        assert_eq!(
            classify_fqn("com.nimbusds.jose.JWSObject"),
            Some(SdkId::JoseLibrary),
        );
    }

    #[test]
    fn jose_library_jwt_subpackage() {
        assert_eq!(
            classify_fqn("com.nimbusds.jwt.JWTClaimsSet"),
            Some(SdkId::JoseLibrary),
        );
    }

    #[test]
    fn stripe_android_sdk() {
        assert_eq!(
            classify_fqn("com.stripe.android.PaymentSession"),
            Some(SdkId::StripeSdk),
        );
    }

    #[test]
    fn stripe_terminal() {
        assert_eq!(
            classify_fqn("com.stripe.stripeterminal.external.models.Reader"),
            Some(SdkId::StripeSdk),
        );
    }

    #[test]
    fn crashlytics() {
        assert_eq!(
            classify_fqn("com.google.firebase.crashlytics.FirebaseCrashlytics"),
            Some(SdkId::Crashlytics),
        );
    }

    #[test]
    fn appsflyer() {
        assert_eq!(
            classify_fqn("com.appsflyer.AppsFlyerLib"),
            Some(SdkId::AppsFlyer),
        );
    }

    #[test]
    fn fingerprintjs_pro() {
        assert_eq!(
            classify_fqn("com.fingerprintjs.android.fpjs_pro.FingerprintJSProAgent"),
            Some(SdkId::FingerprintJsPro),
        );
    }

    #[test]
    fn f5_apiguard3_shapesecurity() {
        assert_eq!(
            classify_fqn("com.shapesecurity.foo.Bar"),
            Some(SdkId::F5ApiGuard3),
        );
    }

    #[test]
    fn f5_apiguard3_lowercase() {
        assert_eq!(
            classify_fqn("com.f5.apiguard3.Module"),
            Some(SdkId::F5ApiGuard3),
        );
    }

    #[test]
    fn f5_apiguard3_camelcase() {
        assert_eq!(
            classify_fqn("com.f5.ApiGuard3.Module"),
            Some(SdkId::F5ApiGuard3),
        );
    }

    #[test]
    fn microblink() {
        assert_eq!(
            classify_fqn("com.microblink.entities.Recognizer"),
            Some(SdkId::Microblink),
        );
    }

    #[test]
    fn netty_self_signed_exact_match() {
        assert_eq!(
            classify_fqn("io.netty.handler.ssl.util.SelfSignedCertificate"),
            Some(SdkId::NettySelfSigned),
        );
    }

    #[test]
    fn netty_self_signed_inner_class() {
        assert_eq!(
            classify_fqn("io.netty.handler.ssl.util.SelfSignedCertificate$Inner"),
            Some(SdkId::NettySelfSigned),
        );
    }

    #[test]
    fn netty_other_util_does_not_match() {
        // Guards against an over-eager prefix like
        // `io.netty.handler.ssl.util.*` — only `SelfSignedCertificate`
        // (exact or inner-class) is recognized.
        assert_eq!(
            classify_fqn("io.netty.handler.ssl.util.OtherUtil"),
            None,
        );
    }

    #[test]
    fn geocomply() {
        assert_eq!(
            classify_fqn("com.geocomply.client.GeoComplyClient"),
            Some(SdkId::GeoComply),
        );
    }

    #[test]
    fn unknown_class() {
        assert_eq!(classify_fqn("com.example.MyClass"), None);
    }

    #[test]
    fn empty_fqn() {
        assert_eq!(classify_fqn(""), None);
    }

    #[test]
    fn jvm_stdlib_unmatched() {
        assert_eq!(classify_fqn("java.lang.String"), None);
        assert_eq!(classify_fqn("kotlin.collections.ArrayList"), None);
    }
}
