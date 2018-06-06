#![feature(generators, generator_trait)]

use std::{path, fs, io::{Read, Write}, ops::{Generator, GeneratorState}};

use uuid::Uuid;
use goblin::pe;
use hex::encode_upper;
use reqwest::{Url, Client, header::{UserAgent, ContentLength}};

use error::{Error, Result};

thread_local! {
    static PDBGET_USER_AGENT: UserAgent = UserAgent::new("Microsoft-Symbol-Server/10.0.0.0");
}

pub struct Pdb {
    name: String,
    guid: Uuid,
    age: u32,
}

impl Pdb {
    pub fn from(file: &path::PathBuf) -> Result<Self> {
        let mut buffer = vec![];
        let pe_obj = {
            let mut fd = fs::File::open(file).map_err(Error::Io)?;
            fd.read_to_end(&mut buffer).map_err(Error::Io)?;
            pe::PE::parse(&buffer).map_err(Error::PeParsing)?
        };

        let debug_data = pe_obj.debug_data.ok_or(application_error!("Debug data not found in PE file"))?;
        let codeview_pdb70 = debug_data.codeview_pdb70_debug_info.ok_or(application_error!("CodeView PDB 7.0 information not found"))?;
        
        let name = {
            let base_name = codeview_pdb70.filename.split(|&c| c == '\\' as u8)
                                                   .last()
                                                   .unwrap_or(codeview_pdb70.filename);
            let name = String::from_utf8(base_name.to_vec()).map_err(|_| application_error!("bad PDB file name"))?;
            let name = name.trim_matches(char::from(0));
            name.to_owned()
        };

        let guid = Uuid::from_bytes(&codeview_pdb70.signature).map_err(|_| application_error!("CodeView PDB 7.0 bad signature"))?;
        
        Ok(Self { name, guid, age: codeview_pdb70.age })
    }

    const DOWNLOAD_BUFFER_SIZE: usize = 1024;

    pub fn download(&self, symbol_server_url: &Url, dir: &path::Path) -> Result<path::PathBuf> {
        // Microsoft GUID encoding
        let pdb_guid_age = {
            let (b0, b1, b2, b3) = self.guid.as_fields();
            format!("{:08X}{:04X}{:04X}{}{:X}", b0.swap_bytes(), b1.swap_bytes(), b2.swap_bytes(), encode_upper(b3), 
                                                self.age)
        };

        let mut response = {
            let url = {
              let new_url_path = format!("{}/{}/{}/{}", symbol_server_url.as_str(), &self.name, &pdb_guid_age, &self.name);
                Url::parse(&new_url_path).map_err(Error::UrlParsing)?
            };

            let client = Client::new();
            PDBGET_USER_AGENT.with(|agent| { client.get(url.clone()).header(agent.clone()).send() }).map_err(Error::Connection)?
        };

        let file_length = {
            if let Some(ct_length) = response.headers().get::<ContentLength>() {
                Some(ct_length.0 as usize)
            } else {
                None
            }
        };

        let file_path = {
            let mut file_path = path::PathBuf::from(dir);
            file_path.push(&self.name);
            file_path.push(pdb_guid_age);
            file_path.push(&self.name);
            file_path
        };

        let mut file = {
            let file_dir = file_path.parent().unwrap();
            fs::create_dir_all(file_dir).map_err(Error::Io)?;
            fs::File::create(&file_path).map_err(Error::Io)?
        };

        let mut buffer = vec![0u8; Self::DOWNLOAD_BUFFER_SIZE];

        let mut downloaded_bytes_count = 0usize;

        // download
        loop {
            if let Ok(read_bytes_count) = response.read(&mut buffer[..]) {
                buffer.truncate(read_bytes_count);
                file.write_all(&buffer).map_err(Error::Io)?;
                downloaded_bytes_count += read_bytes_count;

                if_chain! {
                    if let Some(file_length) = file_length;
                    if downloaded_bytes_count > file_length;
                    then {
                        fail_with_application_error!(format!("stop downloading since received bytes number exceed the file length ({} > {})", downloaded_bytes_count, file_length))
                    }
                }
                
                buffer.resize(Self::DOWNLOAD_BUFFER_SIZE, 0u8);
            } else {
                if_chain! {
                    if let Some(file_length) = file_length;
                    if file_length != downloaded_bytes_count;
                    then {
                        fail_with_application_error!(format!("file length mismatch ({} != {})", downloaded_bytes_count, file_length))
                    } else {
                        break
                    }
                }
            }
        }

        Ok(file_path)
    }
}

#[allow(dead_code)] 
type YT = Pdb;
type RT = Result<()>;

fn pdb_generator(pe_files: Vec<path::PathBuf>) -> impl Generator<Yield = YT, Return = RT> {
    move || {
        for pe in pe_files {
            if let Ok(pdb) = Pdb::from(&pe) {
                yield pdb
            } else {
                warn!("not a PE: {:#?}", &pe);
            }
        }

        Err(Error::StopGeneration)
    }
}

fn to_iter<G>(g: G) -> impl Iterator<Item = G::Yield>
    where G: Generator<Return = RT> {
    struct It<G>(G);

    impl<G: Generator<Return = Result<()>>> Iterator for It<G> {
        type Item = G::Yield;

        fn next(&mut self) -> Option<Self::Item> {
            match unsafe { self.0.resume() } {
                GeneratorState::Yielded(y) => Some(y),
                GeneratorState::Complete(_) => None,
            }
        }
    }

    It(g)
}

pub(super) struct PdbGenerator {
    pe_files: Vec<path::PathBuf>,
}

impl PdbGenerator {
    pub fn new(pe_files: Vec<path::PathBuf>) -> Self {
        PdbGenerator { pe_files }
    }

    pub fn to_iter(self) -> impl Iterator<Item = YT> {
        to_iter(pdb_generator(self.pe_files))
    }
}