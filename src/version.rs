use serde::{Deserialize, Serialize};

use crate::uma;

const MAJOR_VERSION: i32 = 1;
const MINOR_VERSION: i32 = 0;

static BACKWARD_COMPATIBLE_VERSION: [&str; 1] = ["0.3"];

pub fn uma_protocol_version() -> String {
    format!("{}.{}", MAJOR_VERSION, MINOR_VERSION)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnsupportedVersionError {
    pub unsupported_version: String,
    pub supported_major_versions: Vec<i32>,
}

pub fn get_supported_major_versions_from_error_response_body(
    error_response_body: &[u8],
) -> Result<Vec<i32>, uma::Error> {
    let error_response: UnsupportedVersionError =
        serde_json::from_slice(error_response_body).map_err(|_| uma::Error::InvalidResponse)?;
    Ok(error_response.supported_major_versions)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedVersion {
    pub major: i32,
    pub minor: i32,
}

impl ParsedVersion {
    pub fn new(version: &str) -> Result<Self, uma::Error> {
        let parts: Vec<&str> = version.split('.').collect();
        if parts.len() != 2 {
            Err(uma::Error::InvalidVersion)
        } else {
            let major = parts[0]
                .parse::<i32>()
                .map_err(|_| uma::Error::InvalidVersion)?;
            let minor = parts[1]
                .parse::<i32>()
                .map_err(|_| uma::Error::InvalidVersion)?;
            Ok(Self { major, minor })
        }
    }

    pub fn string_value(&self) -> String {
        format!("{}.{}", self.major, self.minor)
    }
}

pub fn get_supported_major_version() -> Vec<i32> {
    // NOTE: In the future, we may want to support multiple major versions in the same SDK, but for
    // now, this keeps things simple.
    let mut result = vec![MAJOR_VERSION];
    for version in BACKWARD_COMPATIBLE_VERSION.iter() {
        if let Ok(parsed_version) = ParsedVersion::new(version) {
            result.push(parsed_version.major);
        }
    }
    result
}

pub fn get_highest_supported_version_for_major_version(
    major_version: &i32,
) -> Option<ParsedVersion> {
    if *major_version != MAJOR_VERSION {
        for version in BACKWARD_COMPATIBLE_VERSION.iter() {
            if let Ok(parsed_version) = ParsedVersion::new(version) {
                if parsed_version.major == *major_version {
                    return Some(parsed_version);
                }
            }
        }
        None
    } else {
        ParsedVersion::new(&uma_protocol_version()).ok()
    }
}

pub fn select_highest_supported_version(
    other_vasp_supported_major_versions: &[i32],
) -> Option<String> {
    let supported_version = get_supported_major_version();
    let mut highest_version: Option<ParsedVersion> = None;
    for other_vasp_major_version in other_vasp_supported_major_versions {
        if !supported_version.contains(other_vasp_major_version) {
            continue;
        }

        match highest_version {
            Some(ref v) => {
                if *other_vasp_major_version > v.major {
                    highest_version = Some(
                        get_highest_supported_version_for_major_version(other_vasp_major_version)
                            .unwrap(),
                    );
                }
            }
            None => {
                highest_version = Some(
                    get_highest_supported_version_for_major_version(other_vasp_major_version)
                        .unwrap(),
                );
            }
        }
    }

    highest_version.map(|v| v.string_value())
}

pub fn select_lower_version(version1: &str, version2: &str) -> Result<String, uma::Error> {
    let v1 = ParsedVersion::new(version1)?;
    let v2 = ParsedVersion::new(version2)?;

    if v1.major > v2.major || (v1.major == v2.major && v1.minor > v2.minor) {
        Ok(version2.to_string())
    } else {
        Ok(version1.to_string())
    }
}

pub fn is_version_supported(version: &str) -> bool {
    let parsed_version = match ParsedVersion::new(version) {
        Ok(parsed_version) => parsed_version,
        Err(_) => return false,
    };
    get_supported_major_version().contains(&parsed_version.major)
}
