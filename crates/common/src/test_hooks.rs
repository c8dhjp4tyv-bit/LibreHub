//! Test-only switches. They are honoured only in debug builds: a release build ignores every
//! `LIBREHUB_TEST_*` and `*_FOR_TESTS` variable, so no deployment can enable a fixture source
//! or DNS answer, a mocked vulnerability database, a fault barrier, or an insecure identity
//! or webhook path by setting an environment variable. Read every such flag through here.
pub fn test_env(name: &str) -> Result<String, std::env::VarError> {
    if cfg!(debug_assertions) {
        std::env::var(name)
    } else {
        Err(std::env::VarError::NotPresent)
    }
}
