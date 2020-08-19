use std::{
    mem::{size_of, size_of_val},
    path::Path,
};

use anyhow::{anyhow, bail, Result};

use async_fs::File;
use futures_lite::io::{AsyncReadExt, AsyncSeekExt, SeekFrom};

macro_rules! read_from_file {
    ($f:expr, $t:ty) => {{
        let mut buffer = [0u8; size_of::<$t>()];
        $f.read_exact(&mut buffer).await?;
        <$t>::from_le_bytes(buffer)
    }};
}

pub async fn pdb_path(file: impl AsRef<Path>) -> Result<String> {
    const IMAGE_FILE_HEADER_SIZE: usize = 0x14;
    const IMAGE_DATA_DIRECTORY_OFFSET32: usize = 0x60;
    const IMAGE_DATA_DIRECTORY_OFFSET64: usize = 0x70;
    const IMAGE_DATA_DIRECTORY_SIZE: usize = 0x8;
    const IMAGE_DIRECTORY_ENTRY_DEBUG: usize = 06;
    const IMAGE_NUMBEROF_DIRECTORY_ENTRIES: usize = 0x10;

    let mut file = File::open(file).await?;

    // check MZ header
    let mz = read_from_file!(file, u16);
    if mz != 0x4d5a {
        bail!("bad MZ header");
    }

    // read e_lfanew
    file.seek(SeekFrom::Current(0x3a)).await?;
    let e_lfanew = read_from_file!(file, u32);

    // seek to the image NT header
    file.seek(SeekFrom::Start(e_lfanew as _)).await?;
    let pe_signature = read_from_file!(file, u32);
    if pe_signature != 0x5045  {
        bail!("bad image file header");
    }

    // now at the image file header
    let image_file_machine = read_from_file!(file, u16);
    if image_file_machine != 0x014c && image_file_machine != 0x8664 {
        bail!("bad image file machine");
    }

    // use it later
    let number_of_sections = read_from_file!(file, u16);

    // seek to the image optional header (since it comes immediately after the image file header)
    file.seek(SeekFrom::Current(
        (IMAGE_FILE_HEADER_SIZE - size_of_val(&pe_signature)) as i64,
    ))
    .await?;
    let optional_header_magic = read_from_file!(file, u16);
    if optional_header_magic != 0x010b && optional_header_magic != 0x020b {
        bail!("bad image optional header magic");
    }

    let is_pe64 = if image_file_machine == 0x014c && optional_header_magic == 0x010b {
        false
    } else if image_file_machine == 0x8664 && optional_header_magic == 0x020b {
        true
    } else {
        bail!("confict between file machine and optional header magic");
    };

    // seek to the image data directory.. then seek to the debug entry
    file.seek(SeekFrom::Current(
        (if is_pe64 {
            IMAGE_DATA_DIRECTORY_OFFSET64
        } else {
            IMAGE_DATA_DIRECTORY_OFFSET32
        } - size_of_val(&optional_header_magic)
            + IMAGE_DIRECTORY_ENTRY_DEBUG * IMAGE_DATA_DIRECTORY_SIZE) as _,
    ))
    .await?;
    let debug_directory_rva = read_from_file!(file, u32);

    // seek to the image section hearder
    file.seek(SeekFrom::Current(
        ((IMAGE_NUMBEROF_DIRECTORY_ENTRIES - IMAGE_DIRECTORY_ENTRY_DEBUG)
            * IMAGE_DATA_DIRECTORY_SIZE
            - size_of_val(&debug_directory_rva)) as i64,
    ))
    .await?;
    // try to map sections, virtually
    for _ in 0..number_of_sections {
        file.seek(SeekFrom::Current(
            (size_of::<u8>() + size_of::<u32>()) as i64,
        ))
        .await?;
        let rva = read_from_file!(file, u32);
        let size_of_raw_data = read_from_file!(file, u32);

        if rva <= debug_directory_rva && debug_directory_rva < rva + size_of_raw_data {
            let pointer_to_raw_data = read_from_file!(file, u32);

            // seek to the image debug directory
            file.seek(SeekFrom::Start(pointer_to_raw_data as _)).await?;
        }
    }

    todo!()
}
