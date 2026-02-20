use helios::ethereum::config::networks::Network;
use std::str::FromStr;

fn main() {
    let n = Network::from_str("mainnet");
    println!("{:?}", n.is_ok());
}
