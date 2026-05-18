// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 notme contributors
// Origin: lifted from cloister (AGPL-3.0) by sole author, contributed to notme under Apache-2.0 on 2026-05-18; see NOTICE.

// Public library surface for schema-bridge.
//
// The binary at src/main.rs is a thin shim over this library. Tests
// drive the library directly with hand-built inputs so that golden +
// fail-case coverage doesn't depend on having the `capnp` CLI
// installed.

pub mod error;
pub mod ir;
pub mod inputs;
pub mod outputs;

pub use error::SchemaBridgeError;
pub use ir::{Enum, FieldType, ScalarType, Schema, Struct, StructField, Union, UnionVariant};
