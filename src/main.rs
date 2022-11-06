use rcon_rs::rcon_query;

fn main() {
    println!("Running");
    let addr = "192.168.1.116:27020";

    rcon_query(addr, "raaage").expect("could not query rcon");
}
