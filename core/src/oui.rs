//! MAC prefix → manufacturer, from the IEEE MA-L registry (`scripts/generate-oui.mjs`).

use std::sync::OnceLock;

use crate::packet::MacAddr;

static DATA: &str = include_str!("../data/oui.tsv");
static TABLE: OnceLock<Vec<(u32, &'static str)>> = OnceLock::new();

/// Label for addresses with the locally-administered bit: phones and laptops randomise their MAC
/// per network, so there is no manufacturer to look up.
pub const PRIVATE_ADDRESS: &str = "Private (randomised) address";

fn table() -> &'static [(u32, &'static str)] {
    TABLE.get_or_init(|| {
        DATA.lines()
            .filter_map(|line| {
                let (prefix, name) = line.split_once('\t')?;
                Some((u32::from_str_radix(prefix, 16).ok()?, name))
            })
            .collect()
    })
}

pub fn vendor(mac: &MacAddr) -> Option<&'static str> {
    if mac.is_multicast() || mac.is_broadcast() {
        return None;
    }
    if mac.0[0] & 0x02 != 0 {
        return Some(PRIVATE_ADDRESS);
    }
    let key = u32::from_be_bytes([0, mac.0[0], mac.0[1], mac.0[2]]);
    let t = table();
    t.binary_search_by_key(&key, |&(k, _)| k).ok().map(|i| t[i].1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_prefixes_and_private_addresses() {
        assert_eq!(vendor(&MacAddr([0x00, 0x0c, 0x29, 1, 2, 3])), Some("VMware"));
        assert_eq!(vendor(&MacAddr([0x3c, 0x22, 0xfb, 1, 2, 3])), Some("Apple"));
        assert_eq!(vendor(&MacAddr([0x7a, 0x11, 0x22, 1, 2, 3])), Some(PRIVATE_ADDRESS));
        assert_eq!(vendor(&MacAddr::BROADCAST), None);
        assert!(table().windows(2).all(|w| w[0].0 < w[1].0), "table must stay sorted for binary search");
    }
}
