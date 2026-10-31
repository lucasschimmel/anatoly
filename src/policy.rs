use serde::Serialize;

pub const POLICY_DATE: &str = "2026-10-30";
pub const ADVISORIES: [&str; 2] = [
    "https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w",
    "https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp",
];
pub const CVES: [&str; 2] = ["CVE-2026-109618", "CVE-2026-109619"];

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PhpVersion {
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
    pub prerelease: bool,
}

impl std::fmt::Display for PhpVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}.{}.{}{}",
            self.major,
            self.minor,
            self.patch,
            if self.prerelease { " (prerelease)" } else { "" }
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VersionStatus {
    AffectedRange,
    FixFloorMet,
    UnsupportedBranch,
    UnreviewedBranch,
    Prerelease,
    Unknown,
    Conflicting,
}

#[derive(Debug, Serialize)]
pub struct Build {
    pub branch: &'static str,
    pub last_affected: &'static str,
    pub fix_floor: &'static str,
}

pub const BUILDS: [Build; 4] = [
    Build {
        branch: "8.2",
        last_affected: "8.2.34",
        fix_floor: "8.2.35",
    },
    Build {
        branch: "8.3",
        last_affected: "8.3.35",
        fix_floor: "8.3.36",
    },
    Build {
        branch: "8.4",
        last_affected: "8.4.26",
        fix_floor: "8.4.27",
    },
    Build {
        branch: "8.5",
        last_affected: "8.5.11",
        fix_floor: "8.5.12",
    },
];

/// Compare an advertised release with upstream floors; this never verifies a package patch.
pub fn classify(v: &PhpVersion) -> VersionStatus {
    if v.prerelease {
        return VersionStatus::Prerelease;
    }
    let floor = match (v.major, v.minor) {
        (8, 2) => 35,
        (8, 3) => 36,
        (8, 4) => 27,
        (8, 5) => 12,
        (5..=7, _) | (8, 0..=1) => return VersionStatus::UnsupportedBranch,
        _ => return VersionStatus::UnreviewedBranch,
    };
    if v.patch < floor {
        VersionStatus::AffectedRange
    } else {
        VersionStatus::FixFloorMet
    }
}
