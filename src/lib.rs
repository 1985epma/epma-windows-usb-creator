//! EPMA USB CREATOR: creates verified bootable USB drives from Windows 11, Linux and other ISOs, and Google's
//! ChromeOS Flex, on Windows 11, macOS and Linux (window and command line).
//!
//! This crate is a Rust port of `win11_usb_creator.py` (kept in the repository as the reference while the port is
//! verified). Read `docs/RUST_PORT.md` for the conventions. Module map (Python line ranges in each module's header):
//!
//! * foundations: `constants`, `types`, `i18n`, `util`, `audit`, `validate`, `isoinfo`, `hash`, `proc`
//! * engine: `copyverify`, `privilege`, `diskrisk`, `engine`
//! * backends: `macos`, `linux`, `windows`, `seed`
//! * generated content: `harden_linux`, `harden_windows`, `seed_files`, `help`
//! * front ends: `download`, `cli`, `gui` (the egui window itself is behind feature `gui`; the window's logic is not)

#![allow(clippy::too_many_arguments)]

pub mod constants;
pub mod types;

pub mod audit;
pub mod hash;
pub mod i18n;
mod i18n_table;
pub mod isoinfo;
pub mod proc;
pub mod util;
pub mod validate;

pub mod copyverify;
pub mod diskrisk;
pub mod engine;
pub mod privilege;

pub mod linux;
pub mod macos;
pub mod seed;
pub mod windows;

pub mod harden_linux;
pub mod harden_macos;
pub mod harden_windows;
pub mod help;
pub mod seed_files;

pub mod cli;
pub mod download;
pub mod gui;
