use std::{
    convert, fmt, fs,
    io::{BufWriter, Read, Write},
    ops::{Generator, GeneratorState},
    path::{Path, PathBuf},
};

use {
    bytes::BytesMut,
    goblin::pe,
    hex::encode_upper,
    reqwest::{header::USER_AGENT, Client, Url},
    uuid::Uuid,
};

use crate::error::{Error, Result};

// thread_local! {
//     static PDBGET_USER_AGENT: UserAgent = UserAgent::new("Microsoft-Symbol-Server/10.0.0.0");
// }
static PDBGET_USER_AGENT: &str = "Microsoft-Symbol-Server/10.0.0.0";
const DOWNLOAD_DATA_BUFFER_SIZE: usize = 4 * 1024;

pub(super) struct Pdb {
    name: String,
    guid: Uuid,
    age: u32,
}

impl Pdb {
    pub fn from<P: AsRef<Path> + fmt::Debug>(file: P) -> Result<Self> {
        let mut buffer = vec![];
        let pe_obj = {
            let mut fd = fs::File::open(&file)?;
            fd.read_to_end(&mut buffer)?;
            pe::PE::parse(&buffer)?
        };

        let debug_data = pe_obj.debug_data.ok_or_else(|| {
            application_error!(format!("PE debug data not found, file: {:?}", file))
        })?;
        let codeview_pdb70 = debug_data.codeview_pdb70_debug_info.ok_or_else(|| {
            application_error!(format!(
                "CodeView PDB 7.0 information not found, file: {:?}",
                file
            ))
        })?;

        let name = {
            let base_name = codeview_pdb70
                .filename
                .split(|&c| c == b'\\')
                .last()
                .unwrap_or(codeview_pdb70.filename);

            let name = String::from_utf8(base_name.to_vec())
                .map_err(|_| application_error!(format!("bad PDB name, file: {:?}", file)))?;

            let name = name.trim_matches(char::from(0));
            name.to_owned()
        };

        let guid = Uuid::from_bytes(codeview_pdb70.signature);
        // .map_err(|_| application_error!("CodeView PDB 7.0 bad signature"))?;

        Ok(Self {
            name,
            guid,
            age: codeview_pdb70.age,
        })
    }

    // pub fn download<P: AsRef<Path>, U: AsRef<Url>>(&self, symbol_server_url: &Url, dir: P) -> Result<PathBuf> {
    pub fn download<P: AsRef<Path>, U: AsRef<str>>(
        &self,
        symbol_server_url: U,
        dir: P,
    ) -> Result<PathBuf>
    where
        PathBuf: convert::From<P>,
    {
        // Microsoft GUID encoding
        let pdb_guid_age = {
            let (b0, b1, b2, b3) = self.guid.as_fields();
            format!(
                "{:08X}{:04X}{:04X}{}{:X}",
                b0.swap_bytes(),
                b1.swap_bytes(),
                b2.swap_bytes(),
                encode_upper(b3),
                self.age
            )
        };

        // send GET request and get response
        let mut response = {
            let url = {
                let new_url_path = format!(
                    "{}/{}/{}/{}",
                    symbol_server_url.as_ref(),
                    &self.name,
                    &pdb_guid_age,
                    &self.name
                );
                Url::parse(&new_url_path).map_err(Error::UrlParsing)?
            };

            let client = Client::new();
            client
                .get(url)
                .header(USER_AGENT, PDBGET_USER_AGENT)
                .send()?
            // .map_err(Error::NetworkConnection)?

            // PDBGET_USER_AGENT
            //     .with(|agent| {
            //         let client = Client::new();
            //         client.get(url.clone()).header(agent.clone()).send()
            //     })
            //     .map_err(Error::Connection)?
        };

        // check response
        let status = response.status();
        if !status.is_success() {
            fail_with_application_error!(format!(
                "bad response, url: {}, code: {}",
                response.url(),
                status
            ));
        }

        // prepare file for data
        let file_path = {
            let mut file_path = PathBuf::from(dir);
            file_path.push(&self.name);
            file_path.push(&pdb_guid_age);
            file_path.push(&self.name);
            file_path
        };

        let mut file = {
            let file_dir = file_path.parent().unwrap();
            fs::create_dir_all(file_dir)?;
            let file = fs::File::create(&file_path)?;
            BufWriter::new(file)
        };

        // download data and save
        let mut data_buffer = BytesMut::with_capacity(DOWNLOAD_DATA_BUFFER_SIZE);
        unsafe { data_buffer.set_len(data_buffer.capacity()) };
        loop {
            let count = response.read(&mut data_buffer)?;
            if count == 0 {
                break;
            }
            file.write_all(&data_buffer[0..count])?;
        }
        // for byte in response.bytes() {
        //     // let byte = byte?;
        //     let count = file.write(&[byte?])?;
        //     if count == 0 {
        //         fail_with_application_error!(format!("cannot write data, file: {:?}", file_path));
        //     }
        // }

        Ok(file_path)
    }
}

#[allow(dead_code)]
type YT = Pdb;
type RT = Result<()>;

pub(super) struct PdbGenerator {
    pe_files: Vec<PathBuf>,
}

impl PdbGenerator {
    pub(super) fn new(pe_files: Vec<PathBuf>) -> Self {
        PdbGenerator { pe_files }
    }

    pub(super) fn into_iter(self) -> impl Iterator<Item = YT> {
        fn pdb_generator(pe_files: Vec<PathBuf>) -> impl Generator<Yield = YT, Return = RT> {
            move || {
                for pe in pe_files {
                    if let Ok(pdb) = Pdb::from(&pe) {
                        yield pdb
                    } else {
                        log::warn!("not a PE: {:#?}", &pe);
                    }
                }

                Err(Error::StopGeneration)
            }
        }

        fn gen_to_iter<G>(g: G) -> impl Iterator<Item = G::Yield>
        where
            G: Generator<Return = RT>,
        {
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

        gen_to_iter(pdb_generator(self.pe_files))
    }
}
