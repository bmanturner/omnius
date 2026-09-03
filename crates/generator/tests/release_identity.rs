//! Release-identity validation contracts.

use omnius_generator::{
    CANONICAL_REPOSITORY, GENERATOR_VERSION, KIT_VERSION, ReleaseIdentity, ReleaseIdentityError,
};

const REVISION: &str = "0123456789abcdef0123456789abcdef01234567";

#[test]
fn catalog_kit_version_should_equal_the_generator_package_version() {
    assert_eq!(KIT_VERSION, GENERATOR_VERSION);
}

#[test]
fn explicit_identity_should_preserve_validated_release_metadata() -> Result<(), ReleaseIdentityError>
{
    let identity = ReleaseIdentity::new(GENERATOR_VERSION, CANONICAL_REPOSITORY, REVISION)?;

    assert_eq!(
        (
            identity.version(),
            identity.repository(),
            identity.revision()
        ),
        (GENERATOR_VERSION, CANONICAL_REPOSITORY, REVISION)
    );
    Ok(())
}

#[test]
fn explicit_identity_should_reject_a_noncanonical_repository() {
    let Err(error) = ReleaseIdentity::new(
        GENERATOR_VERSION,
        "git@github.com:bmanturner/omnius.git",
        REVISION,
    ) else {
        panic!("SSH repository spelling must not identify a release");
    };

    assert_eq!(
        error,
        ReleaseIdentityError::InvalidRepository {
            expected: CANONICAL_REPOSITORY,
            actual: "git@github.com:bmanturner/omnius.git".to_owned(),
        }
    );
}

#[test]
fn explicit_identity_should_reject_an_uppercase_revision() {
    let revision = REVISION.to_ascii_uppercase();
    let Err(error) = ReleaseIdentity::new(GENERATOR_VERSION, CANONICAL_REPOSITORY, &revision)
    else {
        panic!("uppercase hexadecimal must not identify a release");
    };

    assert_eq!(error, ReleaseIdentityError::InvalidRevision(revision));
}

#[test]
fn explicit_identity_should_reject_a_short_revision() {
    let revision = "0123456789abcdef";
    let Err(error) = ReleaseIdentity::new(GENERATOR_VERSION, CANONICAL_REPOSITORY, revision) else {
        panic!("short Git revisions must not identify a release");
    };

    assert_eq!(
        error,
        ReleaseIdentityError::InvalidRevision(revision.to_owned())
    );
}

#[test]
fn explicit_identity_should_accept_an_older_release_version() -> Result<(), ReleaseIdentityError> {
    let identity = ReleaseIdentity::new("0.2.0", CANONICAL_REPOSITORY, REVISION)?;

    assert_eq!(identity.version(), "0.2.0");
    Ok(())
}

#[test]
fn explicit_identity_should_reject_an_invalid_release_version() {
    let Err(error) = ReleaseIdentity::new("not-semver", CANONICAL_REPOSITORY, REVISION) else {
        panic!("release identity versions must be semantic");
    };

    assert_eq!(
        error,
        ReleaseIdentityError::InvalidVersion("not-semver".to_owned())
    );
}
