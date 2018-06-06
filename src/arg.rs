use std::{path, fs, env, io::{Read, Seek, SeekFrom}};

use structopt::StructOpt;
use walkdir::WalkDir;
use reqwest::{Url};
use byteorder::{LittleEndian, ReadBytesExt};
use rayon::prelude::*;

use error::{Error, Result};

fn try_parse_url(url: &str) -> Result<Url> {
    Url::parse(url).map_err(Error::UrlParsing)
}

#[derive(StructOpt, Debug)]
#[structopt(name = "pdbget")]
struct PdbgetArg {
    #[structopt(parse(from_os_str), 
                help = "PE file or folder to get pdbs")]
    input_path: path::PathBuf,

    #[structopt(short = "o", 
                long = "out", 
                help = "output directory (default: current)")]
    output_path: Option<String>,
    
    #[structopt(short = "u", 
                long = "url", 
                parse(try_from_str = "try_parse_url"), help = "symbol server url (e.g. https://msdl.microsoft.com/download/symbols/)")]
    symbol_server_url: Url,
}

pub(super) struct Config {
    pub(crate) pe_files: Vec<path::PathBuf>,
    pub(crate) pdb_dir: path::PathBuf,
    pub(crate) symbol_server: Url,
}

impl Config {
    pub fn new() -> Result<Config> {
        let args = PdbgetArg::from_args();

        let is_pe = |file_path: &path::Path| {
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
                if pe_sig == 0x4550;
                then {
                    true
                } else {
                    false
                }
            }
        };

        let pe_files = {
            let input_mtd = fs::metadata(&args.input_path).map_err(Error::Io)?;

            if input_mtd.is_file() {
                if is_pe(&args.input_path) {
                    vec![args.input_path]
                } else {
                    vec![]
                }
            } else if input_mtd.is_dir() {
                let file_paths: Vec<path::PathBuf> = WalkDir::new(args.input_path)
                    .into_iter()
                    .filter_map(|e| e.ok())
                    .filter_map(|e| if e.file_type().is_file() { Some(e) } else { None} )
                    .map(|e| e.path().to_owned()).collect();

                // concurrency: assume that is_pe is costly
                file_paths.into_par_iter().filter(|p| is_pe(p.as_path())).collect()
            } else {
                fail_with_application_error!("input path is neither file nor directory")
            }
        };

        if pe_files.is_empty() {
            fail_with_application_error!("cannot detect any PE from input")
        }

        let pdb_dir = {
            if let Some(ref output_path) = args.output_path {
                let path = path::PathBuf::from(output_path);
                fs::create_dir_all(&path).map_err(Error::Io)?;
                path

            } else {
                env::current_dir().map_err(Error::Io)?
            }
        };

        Ok(Config { pe_files, pdb_dir, symbol_server: args.symbol_server_url })
    }
}