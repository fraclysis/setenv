use std::fmt::Write;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let file: String = std::fs::read_to_string("lib/setenv_remote_thread_opcodes.txt")?;

    let mut f = String::new();

    write!(&mut f, "unsigned char seProcessInjectionThread_opcodes[] = {{")?;

    for opc in file.split_whitespace() {
        let op = u8::from_str_radix(opc, 16).unwrap();
        write!(&mut f, "0x{op:X}, ")?;
    }

    write!(&mut f, "}};\n")?;

    std::fs::write("lib/setenv_remote_thread_opcodes.c", f)?;

    Ok(())
}
