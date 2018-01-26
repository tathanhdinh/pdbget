#![recursion_limit="256"]

// use goblin::*;
extern crate goblin;
extern crate clap;
extern crate glob;
// extern crate term;
extern crate uuid;
extern crate reqwest;
// extern crate url;
extern crate indicatif;
extern crate hex;

#[macro_use]
extern crate if_chain;

// #[macro_use]
// extern crate lazy_static;

// use std::fs::File;
// use std::path::Path;
use std::io::Read;
use std::io::Write;

// use uuid::Uuid;
// use term::Terminal;

// fn run() -> goblin::error::Result<()> {
//     let path = Path::new("C:\\Windows\\System32\\ntoskrnl.exe");
//     let mut fd = File::open(path)?;
//     let mut buffer = Vec::new();
//     fd.read_to_end(&mut buffer)?;
//     match goblin::Object::parse(&buffer)? {
//         goblin::Object::PE(pe) => {
//             // println!("pe: {:?}", &pe);
//             if pe.is_64 {
//                 println!("PE32+");
//             }
//             else {
//                 println!("PE32");
//             }
//         },
//         _ => {
//             println!("not a pe");
//         }
//     }
//     Ok(())
// }

// fn is_pe(file_path: &std::path::Path) -> Result<bool, std::io::Error> {
//     let mut fd = std::fs::File::open(file_path)?;
//     let mut buffer = Vec::new();
//     fd.read_to_end(&mut buffer)?;
//     match goblin::Object::parse(&buffer) {
//         Ok(obj) => {
//             match obj {
//                 goblin::Object::PE(_) => Ok(true),
//                 _ => Ok(false)
//             }
//         }
//         Err(_) => Ok(false)
//     }
// }
static RAW_USER_AGENT: &'static str = "Microsoft-Symbol-Server/10.0.0.0";
static ARG_NAME_INPUT_PE: &'static str = "PE files";
static ARG_NAME_SYMBOL_SERVER: &'static str = "Symbol server";
static ARG_NAME_OUTPUT_FOLDER: &'static str = "Output folder";
static DOWNLOAD_BUFFER_SIZE: usize = 1024;

// lazy_static! {
//     static ref USER_AGENT: reqwest::header::UserAgent = reqwest::header::UserAgent::new(RAW_USER_AGENT);
// }

fn response_length(resp: &reqwest::Response) -> Option<u64> {
    let ct_len = resp.headers().get::<reqwest::header::ContentLength>();
    ct_len.map(|ct_len| **ct_len)
}

fn response_location(resp: &reqwest::Response) -> Option<&str> {
    let loc = resp.headers().get::<reqwest::header::Location>();
    loc.map(|loc| &**loc)

    // let t = loc.map(|loc| *loc);
    // match t {
    //     Some(ref a) => Some(a.as_str()),
    // }
    // t.map(|ta| ta.as_str())
    // Some("wcsdfs")
}

fn remote_file_length<'t>(url: &reqwest::Url) -> Result<u64, &'t str> {
    let client = reqwest::Client::new();
    
    if let Ok(response) = client.head(url.clone())
    .header(reqwest::header::UserAgent::new(RAW_USER_AGENT))
    .send() {
        let handle_file_size = |resp: &reqwest::Response| {
            response_length(resp).ok_or("cannot get file length").and_then(|s| {
                if s > 0 {
                    if s < std::usize::MAX as u64 {
                        Ok(s)
                    }
                    else {
                        Err("file too large")
                    }
                }
                else {
                    Err("empty file")
                }
            })
        };

        match response.status() {
            reqwest::StatusCode::Ok => {
                handle_file_size(&response)
            },

            reqwest::StatusCode::MovedPermanently | reqwest::StatusCode::Found |
            reqwest::StatusCode::SeeOther | reqwest::StatusCode::TemporaryRedirect |
            reqwest::StatusCode::PermanentRedirect => {
                response_location(&response).ok_or("redirected url not found").and_then(|location| {
                    reqwest::Url::parse(location)
                    .or(Err("malformed redirected url"))
                    .and_then(|redirected_url| {
                        client.head(redirected_url)
                        .header(reqwest::header::UserAgent::new(RAW_USER_AGENT))
                        .send()
                        .or(Err("no HEAD response"))
                        .and_then(|response| {
                            match response.status() {
                                reqwest::StatusCode::Ok => {
                                    handle_file_size(&response)
                                },

                                _ => {
                                    Err("file not found")
                                }
                            }
                        })
                    })
                })
            }

            _ => {
                Err("file not found")
            }
        }
    }
    else {
        Err("no HEAD response")
    }
}

fn make_pdb_file_url<'t>(compressed: bool, 
                         symbol_server_url: &str, 
                         pdb_name: &str, 
                         pdb_guid: &uuid::Uuid, 
                         pdb_age: u32) -> Result<reqwest::Url, &'t str>
{
    // download url = server_url + "/" + pdb_name + "/" + pdb_guid + pdb_age + "/" + pdb_name
    symbol_server_url.chars().last().ok_or("empty symbol server url").and_then(|last_char| {
        let symbol_server_url = 
            if last_char == '/' {
                let len = symbol_server_url.len();
                &symbol_server_url[..len - 1]
            }
            else {
                symbol_server_url
            };

        pdb_name.chars().last().ok_or("empty file name").and_then(|last_char| {
            let pdb_name = 
                if last_char == '\0' {
                    let len = pdb_name.len();
                    &pdb_name[..len - 1]
                }
                else {
                    pdb_name
                };
            
            // display GUID under Microsoft encoding
            let (first, second, third, last) = pdb_guid.as_fields();

            // let mut file_url = format!("{}/{}/{}{:x}/{}", 
            //                            symbol_server_url, 
            //                            &pdb_name, 
            //                            &pdb_guid.simple().to_string(), 
            //                         //    first, second, third, hex::encode(last),
            //                            pdb_age,
            //                            &pdb_name);

            let mut file_url = format!("{}/{}/{:08x}{:04x}{:04x}{}{:x}/{}", 
                                       symbol_server_url, 
                                       &pdb_name, 
                                       first.swap_bytes(), 
                                       second.swap_bytes(), 
                                       third.swap_bytes(), 
                                       hex::encode(last),
                                       pdb_age,
                                       &pdb_name);
            if compressed {
                let len = file_url.len();
                // file_url.trim_right_matches("pdb");
                file_url = String::from(&file_url[..len - 3]);
                file_url += "pd_";
            }

            reqwest::Url::parse(&file_url).or_else(|_| Err("malformed file url"))
        })
    })
}

fn build_pdb_file_path<'t>(file_url: &reqwest::Url, out_dir: &std::path::Path) -> Result<std::path::PathBuf, &'t str>
{
    out_dir.to_str().ok_or("malformed output folder path").and_then(|dir| {
        dir.chars().last()
        .ok_or("empty output folder path")
        .and_then(|last_char| {
            let out_dir = {
                if last_char == '/' {
                    let len = dir.len();
                    &dir[..len - 1]
                }
                else {
                    dir
                }
            };

            let url_parts: Vec<&str> = file_url.as_str().rsplit('/').collect();
            let pdb_parts = &url_parts[..3];

            let mut pdb_filepath = std::path::PathBuf::from(out_dir);
            pdb_filepath.push(pdb_parts[2]); 
            pdb_filepath.push(pdb_parts[1]);
            pdb_filepath.push(pdb_parts[0]);

            Ok(pdb_filepath)
        })
    })
}

fn create_pdb_file<'t>(file_path: &std::path::PathBuf) -> Result<std::fs::File, &'t str> {
    // let to_error_msg = |msg| Err(msg);
    file_path.file_name().ok_or_else(|| "cannot get PDB file name").or_else(|msg| Err(msg))?;

    let file_dir = file_path.parent().ok_or_else(|| "cannot get PDB directory").or_else(|msg| Err(msg))?;
    std::fs::create_dir_all(file_dir).or(Err("cannot create PDB directory"))?;
    
    let file = std::fs::File::create(file_path).or(Err("cannot create PDB file"))?;
    Ok(file)
}

fn save_pdb_file<'t>(file_path: &std::path::PathBuf, file_length: usize, response: &mut reqwest::Response) -> Result<(), &'t str> {
    let last_result;

    match create_pdb_file(&file_path) {
        Ok(out_file) => {
            let mut out_file = std::io::BufWriter::new(out_file);
            let mut buffer = vec![0u8; DOWNLOAD_BUFFER_SIZE]; // capacity = 1024
            let mut downloaded_bytes: usize = 0;

            // println!("file length: {} bytes", file_length);

            let progress_bar = indicatif::ProgressBar::new(file_length as u64);
            progress_bar.set_style(indicatif::ProgressStyle::default_bar()
                // .template("[{elapsed_precise}] {bar:40.cyan/blue} {pos:>7}/{len:7} {msg}")
                // .progress_chars("##-"));
                .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})")
                .progress_chars("=>-"));
        
            loop {
                if let Ok(read_bytes) = response.read(&mut buffer[..]) {
                    buffer.truncate(read_bytes);
                    if let Err(_) = out_file.write_all(&buffer) {
                        // error: cannot write to file
                        last_result = Err("cannot write to file");
                        break;
                    }
                    else {
                        downloaded_bytes += read_bytes;
                        if downloaded_bytes > file_length {
                            // last_result = Ok(downloaded_bytes);
                            last_result = Err("received bytes exceed the file length");
                            break;
                        }
                        else {
                            progress_bar.set_position(downloaded_bytes as u64);
                            if downloaded_bytes == file_length {
                                // last_result = Ok(file_path.clone());
                                last_result = Ok(());
                                break;
                            }
                        }
                    }
                    buffer.resize(DOWNLOAD_BUFFER_SIZE, 0u8);
                }
                else {
                    // cannot read anymore, should check the downloaded bytes
                    if downloaded_bytes != file_length {
                        last_result = Err("invalid file length")
                    }
                    else {
                        // last_result = Ok(file_path.clone());
                        last_result = Ok(())
                    }
                    break;
                }
            }
        },

        Err(msg) => {
            last_result = Err(msg)
        }
    }

    if last_result.is_err() {
        std::fs::remove_file(file_path).ok();
    }

    last_result
}

fn download_file<'t>(file_url: &reqwest::Url, file_length: usize, out_dir: &std::path::Path) -> Result<(), &'t str> {
    
    let file_path = build_pdb_file_path(file_url, out_dir)
    .or_else(|_| Err("bad PDB file path"))?;
    
    let client = reqwest::Client::new();
    
    let mut response = client.get(file_url.clone())
    .header(reqwest::header::UserAgent::new(RAW_USER_AGENT))
    .send()
    .or_else(|_| Err("no GET response"))?;
    
    match response.status() {
        reqwest::StatusCode::Ok => {
            save_pdb_file(&file_path, file_length, &mut response)
        },

        reqwest::StatusCode::MovedPermanently | reqwest::StatusCode::Found |
        reqwest::StatusCode::SeeOther | reqwest::StatusCode::TemporaryRedirect |
        reqwest::StatusCode::PermanentRedirect => {
            let location = response_location(&response)
            .ok_or_else(|| "redirected url not found")
            .or_else(|msg| Err(msg))?;
            
            let redirected_url = reqwest::Url::parse(location)
            .or_else(|_| Err("redirected url malformed"))?;
            
            let mut response = client.get(redirected_url)
            .header(reqwest::header::UserAgent::new(RAW_USER_AGENT))
            .send()
            .or_else(|_| Err("no GET response"))?;

            match response.status() {
                reqwest::StatusCode::Ok => {
                    save_pdb_file(&file_path, file_length, &mut response)
                },

                _ => {
                    Err("file not found")
                }
            }            
        },

        _ => {
            Err("file not found")
        }
    }
}

fn main() {
    // println!("Hello, world!");
    // ::std::process::exit(
    // match run() {
    //     Ok(_) => 0,
    //     Err(_) => 1,
    // })
    let matches = clap::App::new("pdbget")
        .version("0.1.0")
        .author("TA Thanh Dinh <tathanhdinh@gmail.com>")
        .about("Fetch corresponding PDB (Program DataBase) files from a symbol server")
        .arg(clap::Arg::with_name(ARG_NAME_INPUT_PE)
             .multiple(true)
             .index(1)
             .required(true)
             .help("Input PE file(s)"))
        .arg(clap::Arg::with_name(ARG_NAME_SYMBOL_SERVER)
             .short("s")
             .long("server")
             .takes_value(true)
             .required(true)
             .help("URL of the symbol server (e.g. http://msdl.microsoft.com/download/symbols/)"))
        // .arg(clap::Arg::with_name("File searching mode")
        //      .short("r")
        //      .long("recursive")
        //      .help("Recursively looking for input files"))
        .arg(clap::Arg::with_name(ARG_NAME_OUTPUT_FOLDER)
             .short("o")
             .long("output")
             .takes_value(true)
             .help("Location for downloaded PDB(s) (default: current folder)"))
        .get_matches();

    let symbol_server_url = matches.value_of(ARG_NAME_SYMBOL_SERVER).unwrap(); // should not panic
    if let Ok(url) = reqwest::Url::parse(symbol_server_url) {
        let scheme = url.scheme();
        if scheme != "http" && scheme != "https" {
            // error: support only http or https
            println!("{}", "only http or https supported");
            return;
        }
    }
    else {
        // error: invalid url
        println!("{}", "malformed symbol server url");
        return;
    }

    let out_dir = 
        matches.value_of(ARG_NAME_OUTPUT_FOLDER)
        .map_or(std::env::current_dir().or_else(|_| Err("cannot get the current folder")), 
                |dir| {
            let path = std::path::Path::new(dir);
            if path.exists() {
                // let dir_metadata = std::fs::metadata(path).or_else(|_| Err("output location not accessible"));
                std::fs::metadata(path)
                .or_else(|_| Err("output location not accessible"))
                .and_then(|mdt| {
                    if mdt.is_dir() {
                        Ok(path.to_path_buf())
                    }
                    else {
                        Err("output location is not a folder")
                    }
                })
            }
            else {
                // given path doesn't exists
                std::fs::create_dir_all(path)
                .or_else(|_| Err("output location not found"))
                .and_then(|_| Ok(path.to_path_buf()))
            }
        });

    match out_dir {
        Err(msg) => {
            // should print error
            println!("{}", msg);
            return;
        },
        _ => {}
    };

    // let mut console = term::stdout().unwrap();

    let inputs = matches.values_of("PE files").unwrap();
    let options = glob::MatchOptions::new();
    for name in inputs {
        if let Ok(entries) = glob::glob_with(name, &options) {
            for entry in entries {
                if_chain! {
                    if let Ok(entry) = entry;
                    if let Ok(mut fd) = std::fs::File::open(entry.as_path());
                    let mut buffer = Vec::new();
                    if let Ok(_) = fd.read_to_end(&mut buffer);
                    if let Ok(obj) = goblin::Object::parse(&buffer);
                    if let goblin::Object::PE(pe_obj) = obj;
                    if let Some(debug_header) = pe_obj.debug_data;
                    if let Some(codeview_pdb70) = debug_header.codeview_pdb70_debug_info;
                    
                    // get pdb: name, guid, age
                    let base_name =  codeview_pdb70.filename.split(|&c| '\\' as u8 == c)
                                                            .last()
                                                            .unwrap_or(codeview_pdb70.filename);
                                                            
                    if let Ok(pdb_name) = std::str::from_utf8(base_name);
                    let pdb_guid = uuid::Uuid::from_bytes(&codeview_pdb70.signature).unwrap();
                    let pdb_age = codeview_pdb70.age;

                    if let Ok(mut file_url) = make_pdb_file_url(false, 
                                                                symbol_server_url, 
                                                                pdb_name, 
                                                                &pdb_guid, 
                                                                pdb_age);

                    then {
                        // for s in codeview_pdb70.signature.iter() { 
                        //     print!("{:02x} ", s);
                        // }
                        // println!("");

                        let file_length = remote_file_length(&file_url).or_else(|_| {
                            file_url = make_pdb_file_url(true, 
                                                         symbol_server_url, 
                                                         pdb_name, 
                                                         &pdb_guid, 
                                                         pdb_age).unwrap(); // should not panic

                            remote_file_length(&file_url).or_else(|_| Err("PDB file not found"))
                        });

                        println!("{}", file_url);
                        print!("Download PDB for {}", entry.to_string_lossy());
                        
                        match file_length {
                            Ok(file_length) => {
                                println!(" ({} bytes)", file_length);
                                let out_dir = out_dir.as_ref().unwrap();
                                download_file(&file_url, file_length as usize, out_dir).ok();
                            },
                            Err(msg) => {
                                println!(" (error: {})", msg);
                            }
                        }
                    }
                }
            }
        }
        // match glob::glob_with(name, &options) {
        //     Err(_) => {},
        //     Ok(entries) => {
        //     }
        // }
    }
}
