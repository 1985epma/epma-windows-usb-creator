//! Port of the engine-side parts of tests/test_hardening_engine_seed.py (section 2, "Contract bits: modes, needs_admin,
//! dependencies"): the seed drive is not an image type, needs the same rights as Windows mode, and needs only the
//! partitioning tools. (The seed engine itself - labels, files, staging, build_seed_usb - is A4's; needs_admin for
//! the seed is also checked in test_refactor_helpers_a2.rs.)

mod common_a2;

use common_a2::*;
use epma_usb_creator::constants::LINUX_REQUIRED_TOOLS;
use epma_usb_creator::engine::{get_missing_dependencies_on, validate_image_for_mode_on, Os};
use epma_usb_creator::types::{Error, Mode};
use std::path::Path;

fn ops(os: Os, which: impl Fn(&str) -> bool + Send + Sync + 'static) -> FakeOps {
    let mut ops = FakeOps::new(os);
    ops.missing = None;
    ops.which_fn = Some(Box::new(which));
    ops
}

#[test]
fn seed_is_not_an_image_mode() {
    // `--mode` and validate_image_for_mode() are about images; a seed drive has none.
    assert!(!Mode::Seed.is_image_mode());
    assert!(!Mode::ALL.contains(&Mode::Seed));
    assert!(!Mode::Seed.is_raw());
    let err = validate_image_for_mode_on(&FakeOps::new(Os::Mac), Path::new("/nonexistent.iso"), Mode::Seed, None)
        .unwrap_err();
    assert!(matches!(err, Error::Value(_)));
}

#[test]
fn dependencies_are_only_the_partitioning_tools() {
    // macOS: diskutil is part of the system
    assert_eq!(get_missing_dependencies_on(&ops(Os::Mac, |_| false), Mode::Seed), Vec::<String>::new());
    let mut missing = get_missing_dependencies_on(&ops(Os::Linux, |_| false), Mode::Seed);
    missing.sort();
    let mut expected: Vec<String> =
        ["parted", "mkfs.vfat", "wipefs", "partprobe"].iter().map(|s| s.to_string()).collect();
    expected.sort();
    assert_eq!(missing, expected);
    assert!(!missing.contains(&"rsync".to_string()));
    assert!(!missing.contains(&"wimlib-imagex".to_string()));
    let only_parted = ops(Os::Linux, |t| t != "parted");
    assert_eq!(get_missing_dependencies_on(&only_parted, Mode::Seed), ["parted"]);
}

#[test]
fn windows_mode_dependencies_are_unchanged() {
    let none = ops(Os::Linux, |_| false);
    let want: Vec<String> = LINUX_REQUIRED_TOOLS.iter().map(|s| s.to_string()).collect();
    assert_eq!(get_missing_dependencies_on(&none, Mode::Windows), want);
}

#[test]
fn seed_tools_are_installable_by_the_allow_list() {
    let mut seed = get_missing_dependencies_on(&ops(Os::Linux, |_| false), Mode::Seed);
    seed.sort();
    for tool in seed {
        assert!(LINUX_REQUIRED_TOOLS.contains(&tool.as_str()), "{tool}");
    }
}
