//! Telegram MCP server: a Model Context Protocol server exposing a Telegram
//! user (or bot) account through typed tools, built on grammers (MTProto)
//! and rmcp (MCP).

pub mod accounts;
pub mod aliases;
pub mod config;
pub mod contact_sheet;
pub mod entity;
pub mod errors;
pub mod events;
pub mod format;
pub mod paths;
pub mod photo_source;
pub mod registry;
pub mod sanitize;
pub mod server;
pub mod session;
pub mod singleton;
pub mod tools;
pub mod transcription;

pub use grammers_client as tg;
pub use grammers_tl_types as tl;
