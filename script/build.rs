use sp1_helper::build_program;

fn main() {
    println!("BEGIN BUILD");
    let a = build_program("../program");
    println!("END BUILD");
    a
}
