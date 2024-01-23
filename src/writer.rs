use core::mem::size_of;

use goblin::pe::certificate_table::AttributeCertificate;
use goblin::pe::certificate_table::ATTRIBUTE_CERTIFICATE_HEADER_SIZEOF;
use goblin::pe::relocation;
/// Meta writer structures for PE
/// PE is a complicated format that requires meta knowledge about all its fields
/// and reorganization at write time as we cannot predict all fields based on local information.
/// This file contains global structure which possess the global information to make up
/// for the complexity of PE.
/// Heavily inspired of how LLVM objcopy works for COFF.
use log::debug;
use log::trace;
use scroll::Pread;
use scroll::Pwrite;

use goblin::error;
use goblin::pe::data_directories::SIZEOF_DATA_DIRECTORY;
use goblin::pe::header::SIZEOF_COFF_HEADER;
use goblin::pe::optional_header::StandardFields32;
use goblin::pe::optional_header::StandardFields64;
use goblin::pe::optional_header::WindowsFields32;
use goblin::pe::optional_header::WindowsFields64;

use goblin::pe::utils::align_to;

use goblin::pe::data_directories::DataDirectory;
use goblin::pe::data_directories::DataDirectoryType;
use goblin::pe::debug::ImageDebugDirectory;
use goblin::pe::header::DosHeader;
use goblin::pe::header::DosStub;
use goblin::pe::optional_header::OptionalHeader;
use goblin::pe::section_table::SectionTable;
use goblin::pe::section_table::IMAGE_SCN_CNT_INITIALIZED_DATA;
use goblin::pe::section_table::IMAGE_SCN_MEM_EXECUTE;
use goblin::pe::section_table::IMAGE_SCN_MEM_READ;
use goblin::pe::section_table::IMAGE_SCN_MEM_WRITE;
use goblin::pe::utils::{is_in_range, rva2offset};
use goblin::pe::PE;

#[derive(Debug, PartialEq, Clone)]
pub struct Section {
    pub(crate) table: SectionTable,
    pub(crate) contents: Option<Vec<u8>>,
    pub(crate) relocations: Vec<relocation::Relocation>,
}

pub fn from_section_table<'a>(
    mut table: SectionTable,
    pe_bytes: &'a [u8],
) -> error::Result<Section> {
    let contents = table.data(pe_bytes)?.map(|c| c.into_owned());
    let relocations = table.relocations(pe_bytes)?.collect::<Vec<_>>();
    let table = core::mem::take(&mut table);

    Ok(Section {
        table,
        contents,
        relocations,
    })
}

impl Section {
    pub fn new(
        name: &[u8; 8],
        contents: Option<Vec<u8>>,
        characteristics: u32,
    ) -> error::Result<Self> {
        let mut table = SectionTable::default();

        table.name = *name;
        table.characteristics = characteristics;

        // Filling this data requires a complete overview
        // of the final PE which may involve rewriting
        // the complete PE.
        table.size_of_raw_data = 0;
        table.pointer_to_raw_data = 0;
        table.pointer_to_relocations = 0;

        table.pointer_to_linenumbers = 0;
        table.number_of_linenumbers = 0;
        table.pointer_to_relocations = 0;

        table.virtual_size = 0;
        table.virtual_address = 0;

        Ok(Self {
            table,
            contents,
            relocations: Vec::new(),
        })
    }
}

// The maximum number of sections that a COFF object can have (inclusive)
// which is a strict limit for PE, taken from LLVM.
const MAX_NUMBER_OF_SECTIONS_PE: usize = 65279;

fn certificate_contents_length<'a, 'cert: 'a, I>(certificates: I) -> u32
where
    I: Iterator<Item = &'a AttributeCertificate<'cert>>,
{
    certificates.map(|cert| align_to(cert.length, 8)).sum()
}

pub struct PEWriter<'a> {
    pe: PE<'a>,
    file_size: u32,
    file_alignment: u32,
    section_alignment: u32,
    size_of_initialized_data: u64,
    pending_sections: Vec<Section>,
    ready_sections: Vec<Section>,
    prefinalized: bool,
}

impl<'a> PEWriter<'a> {
    /// Consume the PE and store on-the-side information to rewrite
    /// this PE with new information, e.g. new sections.
    /// Some data can be manipulated beforehand and will be correctly rewritten
    /// but this is very driven by implementation details.
    /// It is guaranteed to work for new sections and removed sections, not for much more.
    pub fn new(pe: PE<'a>) -> error::Result<Self> {
        let header = pe.header.optional_header.ok_or(error::Error::Malformed(
            "Missing optional header, write is not supported in this usecase".into(),
        ))?;
        Ok(Self {
            pe,
            file_size: 0,
            file_alignment: header.windows_fields.file_alignment,
            section_alignment: header.windows_fields.section_alignment,
            size_of_initialized_data: 0,
            pending_sections: Vec::new(),
            ready_sections: Vec::new(),
            prefinalized: false,
        })
    }

    /// Enqueue a pending section to be laid out at write time.
    /// Fields that are impossible to predict can be left out
    /// and will be filled automatically.
    pub fn insert_section(&mut self, mut section: Section) -> error::Result<()> {
        // VA is needed only if characteristics is
        // execute | read | write.
        let need_virtual_address = (section.table.characteristics
            & (IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE))
            != 0;

        if let Some(contents) = &section.contents {
            debug_assert!(need_virtual_address, "contents present without any need for a virtual address; missing flag on characteristics?");
            section.table.virtual_size = contents.len().try_into()?;
            let mut sections = self.pe.sections.clone();
            sections.sort_by_key(|sect| sect.virtual_address);
            let last_section_offset = sections
                .iter()
                .chain(self.pending_sections.iter().map(|sect| &sect.table))
                .last()
                .map(|last_section| last_section.virtual_address + last_section.virtual_size)
                .ok_or(0u32)
                .unwrap();

            section.table.virtual_address = align_to(last_section_offset, self.section_alignment);
            debug!(
                "[section {:?}] virtual address assigned: {}",
                section.table.name, section.table.virtual_address
            );
        }

        self.pending_sections.push(section);
        Ok(())
    }

    /// This will compute all the missing fields for a pending section
    /// and put it inside the "ready" sections array for the writer
    /// It relies on the global internal `self.file_size` and
    /// `self.size_of_initialized_data` state to adjust the "on-disk" pointers.
    fn layout_sections(&mut self) -> error::Result<()> {
        fn layout_section(
            file_size: &mut u32,
            size_of_initialized_data: &mut u64,
            header: &mut SectionTable,
            data_length: usize,
            n_relocations: usize,
            file_alignment: u32,
        ) -> error::Result<()> {
            header.size_of_raw_data = align_to(data_length as u32, file_alignment);
            if header.size_of_raw_data > 0 {
                header.pointer_to_raw_data = *file_size;
            }

            if n_relocations > 0 {
                return Err(error::Error::Malformed(
                    "COFF are unsupported; PE should not have relocations!".into(),
                ));
            }

            *file_size += header.size_of_raw_data;
            *file_size = align_to(*file_size, file_alignment);

            if header.characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA
                == IMAGE_SCN_CNT_INITIALIZED_DATA
            {
                *size_of_initialized_data += header.size_of_raw_data as u64;
            }

            Ok(())
        }
        for section in &mut self.pe.sections {
            layout_section(
                &mut self.file_size,
                &mut self.size_of_initialized_data,
                section,
                section.size_of_raw_data as usize,
                section.number_of_relocations.into(),
                self.file_alignment,
            )?;
        }
        while !self.pending_sections.is_empty() {
            let mut section = self.pending_sections.pop().unwrap();

            layout_section(
                &mut self.file_size,
                &mut self.size_of_initialized_data,
                &mut section.table,
                section.contents.as_ref().map(|c| c.len()).unwrap_or(0),
                section.relocations.len(),
                self.file_alignment,
            )?;

            self.ready_sections.push(section);
        }

        // Sections were added in LIFO style.
        // This means that the last element here is the first pending section.
        // i.e. section with the lowest virtual address.
        // To maintain the sorting invariant, we just need to reverse the list.
        self.ready_sections.reverse();

        Ok(())
    }

    /// Clear the current set of certificates attached to the PE binary.
    pub fn clear_certificates(&mut self) {
        if let Some(opt_header) = self.pe.header.optional_header.as_mut() {
            opt_header.data_directories.data_directories[4] = None;
        }
        self.pe.certificates.clear();
        debug!("cleared the certificate table");
    }

    /// Rewrite the data directory for the certificate table
    /// to point to an acceptable position for the start of certificates
    /// and reserve enough space for the whole area.
    /// It will also mutate `self.file_size` to expand the PE for receiving the
    /// contents of the certificates themselves.
    fn layout_certificate_table(&mut self, certificate_area_length: u32) -> error::Result<()> {
        let opt_header = self
            .pe
            .header
            .optional_header
            .as_mut()
            .ok_or(error::Error::Malformed(
                "Missing optional header for a PE".into(),
            ))?;
        // 4 := certificate data directory
        // it is special because it virtual size does not reflect the full size
        // of attribute certificates available.
        // virtual size is only the size of a single bundle of certificate.
        let mut cert_table =
            // Offset is not required for certificate table.
            opt_header.data_directories.data_directories[4].unwrap_or_else(|| (0, DataDirectory {
                virtual_address: self.file_size,
                size: 0,
            }));
        // We need to expand the area.
        debug!(
            "required length for new certificates: {}, existing length: {}, current file size: {}",
            certificate_area_length, cert_table.1.size, self.file_size
        );

        // let debug_table = self.clear_debug_table()?;
        // Either, we are big enough already,
        // or we need to grow to the alignment of our current size + delta size.
        cert_table.1.virtual_address = self.file_size;
        self.file_size += certificate_area_length;
        cert_table.1.size = certificate_area_length;
        // ensure self.file_size is big enough?
        // add_debug_table(debug_table);

        opt_header.data_directories.data_directories[4] = Some(cert_table);

        assert!(
            self.file_size >= cert_table.1.virtual_address + cert_table.1.size,
            "File size is less than the offset of the last certificate in the binary"
        );

        Ok(())
    }

    /// Attach new certificates to this PE.
    /// If you want to clear the old ones, manually call clear.
    /// PE is usually [ header ... | sections ... | certificates ... | debug table ].
    /// This operation will expand the certificates area and push the debug table.
    /// It will also update the PE's header to inform about the new size.
    ///
    /// This operation should have no effect on the Authenticode hash
    /// as per the specification.
    pub fn attach_certificates<'cert: 'a>(
        &mut self,
        certificates: Vec<AttributeCertificate<'cert>>,
    ) -> error::Result<()> {
        // TODO: We need to recopy the debug table *after* this certificate table.
        // Currently, debug table is overwritten / ignored.

        if certificates.is_empty() {
            return Ok(());
        }

        for cert in &certificates {
            if align_to(cert.certificate.len(), 8usize) + ATTRIBUTE_CERTIFICATE_HEADER_SIZEOF
                != cert.length as usize
            {
                return Err(error::Error::Malformed(
                    "Attribute certificate is misaligned!".to_string(),
                ));
            }
        }

        self.finalize()?;
        self.layout_certificate_table(certificate_contents_length(
            self.pe.certificates.iter().chain(certificates.iter()),
        ))?;

        self.pe.certificates.reserve_exact(certificates.len());
        for cert in certificates {
            self.pe.certificates.push(cert);
        }

        Ok(())
    }

    fn layout_data_directories_contents(
        &mut self,
        opt_header: &mut OptionalHeader,
    ) -> error::Result<()> {
        for (index, dir) in opt_header
            .data_directories
            .data_directories
            .iter_mut()
            .enumerate()
        {
            trace!("{}: {:?}", index, dir);
            let dd_type: DataDirectoryType = index.try_into()?;
            // skip certificate table, we don't use size here.
            // skip the debug table, it must be ordered *after* the certificate table
            // as per:
            // > Another exception is that attribute certificate and debug information must be placed
            // > at the very end of an image file, with the attribute certificate table immediately
            // > preceding the debug section, because the loader does not map these into memory. The
            // > rule about attribute certificate and debug information does not apply to object
            // > files, however.
            // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#other-contents-of-the-file
            if dd_type == DataDirectoryType::CertificateTable
                || dd_type == DataDirectoryType::DebugTable
            {
                continue;
            }

            if let Some((offset, dd)) = dir {
                *offset = self.file_size as usize;
                self.file_size += dd.size;
            }
        }
        // 6 := debug table
        // it is special because if it exist, it must be *after* the certificate table.
        // this is incorrect, the data directory offset must point at some section offset.
        opt_header.data_directories.data_directories[6] = None;
        Ok(())
    }

    fn finalize(&mut self) -> error::Result<()> {
        // XXX(RaitoBezarius): some steps of finalization are "commented out"
        // They would be necessary if you are planning to support those codepaths for COFF Object
        // File write support, I do not want to support them, I will stop at supporting *PE
        // executables*.
        // 1. finalize symbol table
        // FIXME: COFF are unsupported ; self.finalize_symbol_table()?;
        // 2. finalize relocation targets
        // FIXME: COFF are unsupported ; self.finalize_relocation_targets()?;
        // 3. finalize symbol contents
        // FIXME: COFF are unsupported ; self.finalize_symbol_contents()?;
        // 4. compute the address of the new exe header
        let mut size_of_headers: u32 = 0;
        let pe_header_size: u32 = {
            if self.pe.is_64 {
                size_of::<StandardFields64>() as u32 + size_of::<WindowsFields64>() as u32
            } else {
                size_of::<StandardFields32>() as u32 + size_of::<WindowsFields32>() as u32
            }
        };
        self.pe.header.dos_header.pe_pointer =
            (size_of::<DosHeader>() + size_of::<DosStub>()) as u32;
        debug_assert!(
            self.pe.header.dos_header.pe_pointer >= 0x40,
            "PE pointer < 0x40, this is not expected."
        );
        // 5. compute the initial pe header size
        let mut opt_header = self
            .pe
            .header
            .optional_header
            .ok_or(error::Error::Malformed(
                "Missing optional header for a PE".into(),
            ))?;
        // Count data directories in the PE.
        opt_header.windows_fields.number_of_rva_and_sizes = 16; // TODO(raito): opt_header.data_directories.dirs().count() as u32; is better but requires the write operation for DD to skip none dds.
        size_of_headers += pe_header_size
            + (SIZEOF_DATA_DIRECTORY as u32) * opt_header.windows_fields.number_of_rva_and_sizes;
        // 6. compute the number of sections
        self.pe.header.coff_header.number_of_sections =
            (self.pe.sections.len() + self.pending_sections.len()) as u16;
        size_of_headers += SIZEOF_COFF_HEADER as u32;
        size_of_headers += (size_of::<SectionTable>() as u32)
            * (self.pe.header.coff_header.number_of_sections as u32);
        size_of_headers = align_to(size_of_headers, self.file_alignment);
        // 7. compute the optional header size
        self.pe.header.coff_header.size_of_optional_header = u16::try_from(pe_header_size)?
            + (SIZEOF_DATA_DIRECTORY as u16)
                * u16::try_from(opt_header.windows_fields.number_of_rva_and_sizes)?;
        // 8. set file size
        self.file_size = size_of_headers;
        self.size_of_initialized_data = 0;
        // 9. layout all sections and data directories contents
        self.layout_sections()?;
        self.layout_data_directories_contents(&mut opt_header)?;
        // 10. adjust PE specific headers w.r.t to sizes
        opt_header.windows_fields.size_of_headers = size_of_headers;
        opt_header.standard_fields.size_of_initialized_data = self.size_of_initialized_data;

        if let Some(last_section) = self
            .pe
            .sections
            .iter()
            .chain(self.ready_sections.iter().map(|s| &s.table))
            .last()
        {
            opt_header.windows_fields.size_of_image = align_to(
                last_section.virtual_address + last_section.virtual_size,
                self.section_alignment,
            );
        }

        // Clear the checksum and do not compute it.
        opt_header.windows_fields.check_sum = 0;

        // 11. FIXME: COFF are unsupported ; finalize string tables

        self.pe.header.optional_header = Some(opt_header);
        self.file_size = align_to(self.file_size, self.file_alignment);

        // We need to relocate once we know the true `file_size`.
        self.layout_certificate_table(certificate_contents_length(self.pe.certificates.iter()))?;

        self.prefinalized = true;
        Ok(())
    }

    fn write_headers(&mut self, buf: &mut Vec<u8>) -> error::Result<usize> {
        let offset = &mut 0;
        // 1. write the header
        debug!("writing this header: {:#?}", self.pe.header);
        buf.gwrite(self.pe.header, offset)?;
        // 2. write the section tables
        for section in self
            .pe
            .sections
            .iter()
            .chain(self.ready_sections.iter().map(|s| &s.table))
        {
            debug!(
                "writing section table {} at {}",
                section.name().unwrap_or("unknown name"),
                offset
            );
            buf.gwrite(section, offset)?;
        }

        Ok(*offset)
    }

    fn write_sections(&mut self, buf: &mut Vec<u8>) -> error::Result<usize> {
        // For each section, seek at the pointer to raw data, write the contents.
        // For executable sections, pad the remainder of the raw data size
        // with 0xCC, because it's useful on x86 (debugger breakpoint).
        let mut written = 0;
        let ready_sections = core::mem::take(&mut self.ready_sections);
        for section in self
            .pe
            .sections
            .iter()
            .cloned()
            .map(|s| from_section_table(s, self.pe.bytes()).unwrap())
            .chain(ready_sections.into_iter())
        {
            let offset = section.table.pointer_to_raw_data as usize;
            if let Some(contents) = &section.contents {
                written += buf.pwrite(contents.as_slice(), offset)?;
                debug!(
                    "wrote {} (true size: {}) contents at {}",
                    contents.len(),
                    section.table.size_of_raw_data,
                    offset
                );
                if section.table.size_of_raw_data as usize > contents.len() {
                    written += buf.pwrite(
                        &vec![0xCC; (section.table.size_of_raw_data as usize) - contents.len()][..],
                        offset + contents.len(),
                    )?;
                }
            }
        }
        // FIXME: COFF are unsupported but you would need to write the relocations here and
        // distinguish based on the size of the COFF object.
        Ok(written)
    }

    fn patch_debug_directory(
        &mut self,
        debug_directory: &DataDirectory,
        w: &mut Vec<u8>,
    ) -> error::Result<usize> {
        if debug_directory.size == 0 {
            return Ok(0);
        }

        for section in &self.pe.sections {
            let section_end = section.virtual_address + section.virtual_size;

            if is_in_range(
                debug_directory.virtual_address as usize,
                section.virtual_address as usize,
                section_end as usize,
            ) {
                if debug_directory.virtual_address + debug_directory.size > section_end {
                    return Err(error::Error::Malformed(
                        "debug directory extends past end of section".into(),
                    ));
                }

                // We compute the relative difference inside the section
                let offset = debug_directory.virtual_address - section.virtual_address;
                // We compute the pointer to raw data for the debug dir
                // based on the on-disk offset section + relative diff
                // as mapping is linear.
                let mut target_offset = (section.pointer_to_raw_data + offset) as usize;
                let end = target_offset + debug_directory.size as usize;
                // Read until target_offset + debug_directory.size
                while target_offset < end {
                    let mut debug_data: ImageDebugDirectory =
                        w.gread::<ImageDebugDirectory>(&mut target_offset)?;
                    if debug_data.pointer_to_raw_data != 0 {
                        debug_data.pointer_to_raw_data =
                            rva2offset(debug_data.address_of_raw_data as usize, section)
                                .try_into()?;
                        // We rewrite the previous pointer inside the memory buffer
                        // Right now, we are sitting potentially onto the next ImageDebugDirectory
                        // or the end.
                        // It is therefore enough to start from target_offset, go back to previous
                        // element and go to the relevant field immediately.

                        w.pwrite(
                            debug_data.pointer_to_raw_data,
                            target_offset + 0x18 - size_of::<ImageDebugDirectory>(),
                        )?;
                    }
                }
            }
        }

        Ok(0)
    }

    pub fn write_into(&mut self) -> error::Result<Vec<u8>> {
        let total_sections = self.pending_sections.len() + self.pe.sections.len();
        let is_too_large = total_sections >= MAX_NUMBER_OF_SECTIONS_PE;

        if is_too_large {
            return Err(error::Error::Malformed(
                format!("Trying to write {total_sections} sections, the limit is {MAX_NUMBER_OF_SECTIONS_PE} for a PE binary")
            ));
        }

        let mut written = 0;

        if !self.prefinalized {
            self.finalize()?;
            debug!("finalized the new PE binary at {} bytes", self.file_size);
        } else {
            debug!(
                "pre-finalized the new PE binary at {} bytes",
                self.file_size
            );
        }
        let mut buffer = vec![0; self.file_size as usize];

        let header_length = self.write_headers(&mut buffer)?;
        debug!("wrote {header_length} bytes of headers");
        written += header_length;
        let section_length = self.write_sections(&mut buffer)?;
        debug!("wrote {section_length} bytes of sections");
        written += section_length;
        // FIXME: COFF are unsupported ; written += self.write_symbol_string_tables(&mut buffer)?;
        if let Some((_, debug_dir)) = &self
            .pe
            .header
            .optional_header
            .and_then(|opt_header| opt_header.data_directories.data_directories[6])
        {
            self.patch_debug_directory(debug_dir, &mut buffer)?;
            debug!("patched debug directory");
        }
        // Technically, `write_certificates` return the maximum offset encountered… is it really
        // the written number of bytes?
        let cert_length = certificate_contents_length(self.pe.certificates.iter()) as usize;
        debug!("writing {cert_length} bytes of certificates");
        self.pe.write_certificates(&mut buffer, scroll::LE)?;
        debug!("wrote {cert_length} bytes of certificates");
        written += cert_length;

        // Specification says that:
        // if cert table and debug table exist, they must be at the very end in this order
        // if cert table exist, it should be the last element
        // if debug table exist, it should be the last element
        // This is important because they are not mapped in memory.
        // TODO: reintroduce it.

        // We cannot guarantee that written == self.file_size
        // as PE cannot be perfectly efficient vs. how we do write them.
        // For example, if you have 1 data directory and it is the last one,
        // you will have to say that you have all data directories and will only write one data
        // directory header, but your file size will reflect the potential size of all data
        // directories contents.
        // Of course, it is possible to improve many moving parts and make it quite efficient.
        // PRs are welcome as correctness is already a good enough goal with PEs.
        debug_assert!(
            written <= self.file_size as usize,
            "incorrect amount of bytes written, expected at most: {}, wrote: {}",
            self.file_size,
            written
        );
        Ok(buffer)
    }
}
