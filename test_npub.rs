use nostr::prelude::*;
use std::str::FromStr;

fn npub_to_hex(npub: &str) -> Option<String> {
    if npub.starts_with("npub") {
        // Use nostr crate's PublicKey to decode npub
        match PublicKey::parse(npub) {
            Ok(pubkey) => Some(pubkey.to_string()),
            Err(_) => None,
        }
    } else {
        // Already in hex format
        Some(npub.to_string())
    }
}

fn main() {
    let test_npub = "npub1xpuz4qerklyck9evtg40wgrthq5rce2mumwuuygnxcg6q02lz9ms275ams";
    let expected_hex = "30782a8323b7c98b172c5a2af7206bb8283c655be6ddce11133611a03d5f1177";

    match npub_to_hex(test_npub) {
        Some(hex) => {
            println!("Input npub: {}", test_npub);
            println!("Converted hex: {}", hex);
            println!("Expected hex: {}", expected_hex);
            println!("Match: {}", hex == expected_hex);
        }
        None => {
            println!("Failed to convert npub to hex");
        }
    }
}
