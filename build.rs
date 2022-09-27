// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Generates the Rust D-Bus bindings for tlsdate.

use std::path::Path;

use chromeos_dbus_bindings::{self, generate_module, BindingsType};

const SOURCE_DIR: &str = ".";

// (<module name>, <relative path to source xml>)
const BINDINGS_TO_GENERATE: &[(&str, &str, BindingsType)] = &[(
    "org_torproject_tlsdate",
    "dbus/org.torproject.tlsdate.xml",
    BindingsType::Client(None),
)];

fn main() {
    generate_module(Path::new(SOURCE_DIR), BINDINGS_TO_GENERATE).unwrap();
}
