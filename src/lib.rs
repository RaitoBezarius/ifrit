pub mod writer;

#[cfg(test)]
mod tests {
    use crate::writer::PEWriter;
    use goblin::pe::PE;
    use stderrlog;

    #[test]
    fn identity_write() {
        stderrlog::new().verbosity(4).init().unwrap();

        let bytes = std::fs::read("src/tests/fixtures/nixos-lanzaboote-pki.efi")
            .expect("Failed to read the fixture");

        let pe = PE::parse(&bytes).expect("Failed to parse the fixture as a PE");

        let mut writer = PEWriter::new(pe).expect("Failed to instantiate the writer");
        let _ = writer
            .write_into()
            .expect("Failed to rewrite the PE without any modification");
    }
}
