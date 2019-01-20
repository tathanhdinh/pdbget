use std::{
    env, fs,
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
};

use {
    byteorder::{LittleEndian, ReadBytesExt},
    if_chain::*,
    rayon::prelude::*,
    reqwest::Url,
    structopt::StructOpt,
    walkdir::WalkDir,
};

use crate::error::{OtherErrors, Result};

fn try_parse_url(url: &str) -> Result<Url> {
    Url::parse(url).map_err(From::from)
    // .map_err(Error::UrlParsing)
}

#[derive(StructOpt)]
#[structopt(name = "pdbget")]
struct PdbgetArg {
    #[structopt(
        name = "input",
        parse(from_os_str),
        help = "PE file or folder (recursively traversed)"
    )]
    input_path: PathBuf,

    #[structopt(
        name = "output",
        short = "o",
        long = "out",
        help = "Directory to save downloaded pdbs (default: current)"
    )]
    output_path: Option<String>,

    #[structopt(
        name = "url",
        short = "s",
        long = "server",
        parse(try_from_str = "try_parse_url"),
        help = "Symbol server url (e.g. https://msdl.microsoft.com/download/symbols/)"
    )]
    symbol_server_url: Url,
}

pub(super) struct Config {
    input_path: PathBuf,
    pub(crate) pdb_dir: PathBuf,
    pub(crate) symbol_server: Url,
}

impl Config {
    pub fn new() -> Result<Config> {
        let args = PdbgetArg::from_args();

        let pdb_dir = {
            if let Some(ref output_path) = args.output_path {
                let path = PathBuf::from(output_path);
                fs::create_dir_all(&path)?;
                path
            } else {
                env::current_dir()?
            }
        };

        Ok(Config {
            pdb_dir,
            input_path: args.input_path,
            symbol_server: args.symbol_server_url,
        })
    }

    pub fn scan_pe_files(&self) -> Result<Vec<PathBuf>> {
        let is_pe = |file_path: &Path| {
            let mut buffer = [0u8; 64];
            if_chain! {
                if let Ok(mut file) = fs::File::open(file_path);
                if let Ok(len) = file.read(&mut buffer);
                if len == buffer.len();
                if let Ok(mz) = (&buffer[..]).read_u16::<LittleEndian>();
                if mz == 0x5a4d;
                if let Ok(pe_header_offset) = (&buffer[60..=63]).read_u32::<LittleEndian>();
                if let Ok(_) = file.seek(SeekFrom::Start(pe_header_offset.into()));
                if let Ok(len) = file.read(&mut buffer);
                if len == buffer.len();
                if let Ok(pe_sig) = (&buffer[..]).read_u32::<LittleEndian>();
                then {
                    pe_sig == 0x4550
                } else {
                    false
                }
            }
        };

        let pe_files = {
            let ref input_path = self.input_path;

            let input_mtd = fs::metadata(input_path)?;

            if input_mtd.is_file() {
                if is_pe(input_path) {
                    vec![input_path.clone()]
                } else {
                    vec![]
                }
            } else if input_mtd.is_dir() {
                let file_paths: Vec<PathBuf> = WalkDir::new(input_path)
                    .into_iter()
                    .filter_map(|e| e.ok())
                    .filter_map(|e| {
                        if e.file_type().is_file() {
                            Some(e)
                        } else {
                            None
                        }
                    })
                    .map(|e| e.path().to_owned())
                    .collect();

                // concurrency: assume that is_pe is costly
                file_paths
                    .into_par_iter()
                    .filter(|p| is_pe(p.as_path()))
                    .collect()
            } else {
                // fail_with_application_error!("input path is neither file nor directory")
                return Err(OtherErrors::InputNotFound(format!("{:?}", input_path)).into());
            }
        };

        Ok(pe_files)
    }
}
