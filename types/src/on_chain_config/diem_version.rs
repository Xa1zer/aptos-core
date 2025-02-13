// Copyright (c) Aptos
// SPDX-License-Identifier: Apache-2.0

use crate::on_chain_config::OnChainConfig;
use serde::{Deserialize, Serialize};

/// Defines the version of Diem Validator software.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Version {
    pub major: u64,
}

impl OnChainConfig for Version {
    const IDENTIFIER: &'static str = "Version";
}

// NOTE: version number for release 1.2 Diem
// Items gated by this version number include:
//  - the ScriptFunction payload type
pub const DIEM_VERSION_2: Version = Version { major: 2 };

// NOTE: version number for release 1.3 of Diem
// Items gated by this version number include:
//  - Multi-agent transactions
pub const DIEM_VERSION_3: Version = Version { major: 3 };

// NOTE: version number for release 1.4 of Diem
// Items gated by this version number include:
//  - Conflict-Resistant Sequence Numbers
pub const DIEM_VERSION_4: Version = Version { major: 4 };

// Maximum current known version
pub const DIEM_MAX_KNOWN_VERSION: Version = DIEM_VERSION_4;
