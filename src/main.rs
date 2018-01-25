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
            if let Some(s) = response_length(resp) {
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
            }
            else {
                Err("cannot get file length")
            }
            
        };
        match response.status() {
            reqwest::StatusCode::Ok => {
                handle_file_size(&response)
                // if let Some(file_size) = response_length(&response) {
                //     handle_file_size(file_size)
                //     // if file_size > 0 {
                //     //     if file_size < std::usize::MAX as u64 {
                //     //         Ok(file_size)
                //     //     }
                //     //     else {
                //     //         Err("file too large")
                //     //     }
                //     // }
                //     // else {
                //     //     Err("empty file")
                //     // }
                // }
                // else {
                //     Err("cannot get file length")
                // }
            },

            reqwest::StatusCode::MovedPermanently | reqwest::StatusCode::Found |
            reqwest::StatusCode::SeeOther | reqwest::StatusCode::TemporaryRedirect |
            reqwest::StatusCode::PermanentRedirect => {
                if let Some(location) = response_location(&response) {
                    if let Ok(redirected_url) = reqwest::Url::parse(location) {
                        if let Ok(response) = client.head(redirected_url)
                        .header(reqwest::header::UserAgent::new(RAW_USER_AGENT))
                        .send() {
                            match response.status() {
                                reqwest::StatusCode::Ok => {
                                    handle_file_size(&response)
                                },

                                _ => {
                                    Err("file not found")
                                }
                            }
                        }
                        else {
                            Err("no HEAD response")
                        }
                    }
                    else {
                        Err("malformed redirected url")
                    }
                }
                else {
                    Err("redirected url not found")
                }
            }

            _ => {
                Err("file not found")
            }
        }
    }
    else {
        Err("no HEAD response")
    }

    // if_chain!{
    //     // if let Ok(download_url) = reqwest::Url::parse(url);
    //     // let response_length = |response: &reqwest::Response| -> Option<u64> {
    //     //     response.headers().get::<reqwest::header::ContentLength>().map(|ct_len| **ct_len)
    //     // };

    //     if let Ok(response) = {
    //         // println!("send HEAD to: {}", url);
    //         let client = reqwest::Client::new();
    //         client.head(url.clone())
    //             // .header(USER_AGENT.clone())
    //             .header(reqwest::header::UserAgent::new(RAW_USER_AGENT))
    //             .send()
    //     };
        
    //     if let Some(file_size) = response_length(&response);

    //     then {
    //         if response.status() == reqwest::StatusCode::Ok {
    //             if file_size > 0 {
    //                 Ok(file_size)
    //             }
    //             else {
    //                 Err("empty remote file")
    //             }
    //         }
    //         else {
    //             Err("bad HEAD response")
    //         }
            
    //     }
    //     else {
    //         Err("cannot get remote file length")
    //     }
    // }
}

fn make_pdb_file_url<'t>(compressed: bool, 
                         symbol_server_url: &str, 
                         pdb_name: &str, 
                         pdb_guid: &uuid::Uuid, 
                         pdb_age: u32) -> Result<reqwest::Url, &'t str>
{
    // download url = server_url + "/" + pdb_name + "/" + pdb_guid + pdb_age + "/" + pdb_name
    if let Some(last_char) = symbol_server_url.chars().last() {
        let symbol_server_url = 
            if last_char == '/' {
                let len = symbol_server_url.len();
                &symbol_server_url[..len - 1]
            }
            else {
                symbol_server_url
            };

            // println!("pdb_name: {}, len = {}", pdb_name, pdb_name.len());
        if let Some(last_char) = pdb_name.chars().last() {
            let pdb_name = 
                if last_char == '\0' {
                    let len = pdb_name.len();
                    &pdb_name[..len - 1]
                }
                else {
                    pdb_name
                };
            
            // println!("simple: {}", pdb_guid.simple().to_string());
            // println!("hyphenated: {}", pdb_guid.hyphenated().to_string());

            // let tmp = uuid::Uuid::from_str(pdb_guid.simple().to_string());
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

            if let Ok(file_url) = reqwest::Url::parse(&file_url) {
                Ok(file_url)
            }
            else {
                Err("malformed file url")
            }
        }
        else {
            Err("empty file name")
        }
    }
    else {
        Err("empty symbol server url")
    }
}

fn build_pdb_file_path<'t>(file_url: &reqwest::Url, out_dir: &std::path::Path) -> Result<std::path::PathBuf, &'t str>
{
    // let url_parts: Vec<&str> = file_url.as_str().rsplit('/').collect();
    // let pdb_parts = &url_parts[..3];
    // let mut out_filename = std::path::PathBuf::from(out_dir);
    // if let Some(out_dir) = out_dir.to_str() {

    // }
    // else {

    // }
    if let Some(out_dir) = out_dir.to_str() {
        if let Some(last_char) = out_dir.chars().last() {
            let out_dir = {
                if last_char == '/' {
                    let len = out_dir.len();
                    &out_dir[..len - 1]
                }
                else {
                    out_dir
                }
            };

            let url_parts: Vec<&str> = file_url.as_str().rsplit('/').collect();
            let pdb_parts = &url_parts[..3];
            // let file_path = format!("{}/{}/{}/{}", out_dir, pdb_parts[2], pdb_parts[1], pdb_parts[0]);
            // let pdb_filepath = std::path::PathBuf::from(&file_path);

            // let mut tmp = std::path::PathBuf::from(out_dir);
            // tmp.push(pdb_parts[2]); tmp.push(pdb_parts[1]); tmp.push(pdb_parts[0]);
            // if let Some(tmp) = tmp.to_str() {
            //     println!("tmp: {}", &tmp);
            // }

            let mut pdb_filepath = std::path::PathBuf::from(out_dir);
            pdb_filepath.push(pdb_parts[2]); 
            pdb_filepath.push(pdb_parts[1]);
            pdb_filepath.push(pdb_parts[0]);

            Ok(pdb_filepath)
        }
        else {
            Err("empty output folder path")
        }
    }
    else {
        Err("malformed output folder path")
    }       
}

fn create_pdb_file<'t>(file_path: &std::path::PathBuf) -> Result<std::fs::File, &'t str> {
    if let Some(_) = file_path.file_name() {
        if let Some(file_dir) = file_path.parent() {
            if let Ok(_) = std::fs::create_dir_all(file_dir) {
                if let Ok(file) = std::fs::File::create(file_path) {
                    Ok(file)
                }
                else {
                    Err("cannot create PDB file")
                }
            }
            else {
                Err("cannot create PDB directory")
            }
        }
        else {
            Err("cannot get PDB directory")
        }
    }
    else {
        Err("cannot get PDB file name")
    }
}

fn save_pdb_file<'t>(file_path: &std::path::PathBuf, file_length: usize, response: &mut reqwest::Response) -> Result<std::path::PathBuf, &'t str> {
    let mut last_result;

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
                                last_result = Ok(file_path.clone());
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
                        last_result = Ok(file_path.clone());
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

fn download_file<'t>(file_url: &reqwest::Url, file_length: usize, out_dir: &std::path::Path) -> Result<std::path::PathBuf, &'t str> {
    if let Ok(file_path) = build_pdb_file_path(file_url, out_dir) {
        let client = reqwest::Client::new();
        if let Ok(mut response) = client.get(file_url.clone())
        .header(reqwest::header::UserAgent::new(RAW_USER_AGENT))
        .send() {
            match response.status() {
                reqwest::StatusCode::Ok => {
                    save_pdb_file(&file_path, file_length, &mut response)
                },

                reqwest::StatusCode::SeeOther | reqwest::StatusCode::TemporaryRedirect |
                reqwest::StatusCode::PermanentRedirect => {
                    if let Some(location) = response_location(&response) {
                        if let Ok(redirected_url) = reqwest::Url::parse(location) {
                            if let Ok(mut response) = client.get(redirected_url)
                            .header(reqwest::header::UserAgent::new(RAW_USER_AGENT))
                            .send() {
                                match response.status() {
                                    reqwest::StatusCode::Ok => {
                                        save_pdb_file(&file_path, file_length, &mut response)
                                    },

                                    _ => {
                                        Err("file not found")
                                    }
                                }
                            }
                            else {
                                Err("no GET response")
                            }
                        }
                        else {
                            Err("malformed redirected url")
                        }
                    }
                    else {
                        Err("redirected url not found")
                    }
                },

                _ => {
                    Err("file not found")
                }
            }
        }
        else {
            Err("no GET response")
        }
    }
    else {
        Err("bad PDB file path")
    }
    // if_chain! {
    //     // if let Ok(download_url) = reqwest::Url::parse(&url);
        
    //     if let Ok(mut response) = {
    //         let client = reqwest::Client::new();
    //         client.get(file_url.clone())
    //             // .header(USER_AGENT.clone())
    //             .header(reqwest::header::UserAgent::new(RAW_USER_AGENT))
    //             .send()
    //     };

    //     if let Ok(out_pdb_file_path) = build_pdb_file_path(file_url, out_dir);

    //     // if let Some(size) = response_length(&response);

    //     then {
    //         let download_result = {
    //             // let mut last_result = Ok(file_length);
    //             let mut last_result;
    //             match create_pdb_file(&out_pdb_file_path) {
    //                 Ok(out_file) => {
    //                     let mut out_file = std::io::BufWriter::new(out_file);
    //                     let mut buffer = vec![0u8; DOWNLOAD_BUFFER_SIZE]; // capacity = 1024
    //                     let mut downloaded_bytes: usize = 0;

    //                     // println!("file length: {} bytes", file_length);

    //                     let progress_bar = indicatif::ProgressBar::new(file_length as u64);
    //                     progress_bar.set_style(indicatif::ProgressStyle::default_bar()
    //                         // .template("[{elapsed_precise}] {bar:40.cyan/blue} {pos:>7}/{len:7} {msg}")
    //                         // .progress_chars("##-"));
    //                         .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})")
    //                         .progress_chars("=>-"));
                    
    //                     loop {
    //                         if let Ok(read_bytes) = response.read(&mut buffer[..]) {
    //                             buffer.truncate(read_bytes);
    //                             if let Err(_) = out_file.write_all(&buffer) {
    //                                 // error: cannot write to file
    //                                 last_result = Err("cannot write to file");
    //                                 break;
    //                             }
    //                             else {
    //                                 downloaded_bytes += read_bytes;
    //                                 if downloaded_bytes > file_length {
    //                                     // last_result = Ok(downloaded_bytes);
    //                                     last_result = Err("received bytes exceed the file length");
    //                                     break;
    //                                 }
    //                                 else {
    //                                     progress_bar.set_position(downloaded_bytes as u64);
    //                                     if downloaded_bytes == file_length {
    //                                         last_result = Ok(downloaded_bytes);
    //                                         break;
    //                                     }
    //                                 }
    //                             }
    //                             buffer.resize(DOWNLOAD_BUFFER_SIZE, 0u8);
    //                         }
    //                         else {
    //                             // cannot read anymore, should check the downloaded bytes
    //                             if downloaded_bytes != file_length {
    //                                 last_result = Err("invalid file length")
    //                             }
    //                             else {
    //                                 last_result = Ok(downloaded_bytes);
    //                             }
    //                             break;
    //                         }
    //                     }
    //                 },

    //                 Err(msg) => {
    //                     last_result = Err(msg)
    //                 }
    //             }
                
    //             last_result
    //         };

    //         if let Err(msg) = download_result {
    //             println!("{}", msg);
    //             std::fs::remove_file(out_pdb_file_path).ok();
    //         }
    //     }
    // }
}

fn main() {
    // println!("Hello, world!");
    // ::std::process::exit(
    // match run() {
    //     Ok(_) => 0,
    //     Err(_) => 1,
    // })
    let matches = clap::App::new("pdbfetch")
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

    let symbol_server_url = matches.value_of(ARG_NAME_SYMBOL_SERVER).unwrap();
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
        match matches.value_of(ARG_NAME_OUTPUT_FOLDER) {
            None => {
                if let Ok(path) = std::env::current_dir() {
                    Ok(path)
                }
                else {
                    // error: cannot get current folder
                    Err("cannot get the current folder")
                }
            },
            Some(dir) => {
                let path = std::path::Path::new(dir);
                if path.exists() {
                    if let Ok(dir_metadata) = std::fs::metadata(path) {
                        if dir_metadata.is_dir() {
                            Ok(path.to_path_buf())
                        }
                        else {
                            // error: given folder is not a directory
                            Err("output location is not a folder")
                        }
                    }
                    else {
                        // error: cannot get folder's metadata
                        Err("output location not accessible")
                    }
                }
                else {
                    // given path doesn't exists
                    if let Ok(_) = std::fs::create_dir_all(path) {
                        Ok(path.to_path_buf())
                    }
                    else {
                        Err("output location not found")
                    }
                    
                }
            }
        };

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
                    let base_name = 
                        if let Some(name) = codeview_pdb70.filename.split(|&c| '\\' as u8 == c).last() {
                            name
                        }
                        else {
                            codeview_pdb70.filename
                        };
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
                        

                        let file_length =
                            match remote_file_length(&file_url) {
                                Ok(length) => Ok(length),
                                Err(_) => {
                                    file_url = make_pdb_file_url(true, 
                                                                 symbol_server_url, 
                                                                 pdb_name, 
                                                                 &pdb_guid, 
                                                                 pdb_age).unwrap(); // should not panic

                                    match remote_file_length(&file_url) {
                                        Ok(length) => {
                                            if length > std::usize::MAX as u64 {
                                                Err("PDB file too large")
                                            }
                                            else {
                                                Ok(length)
                                            }
                                        }
                                        Err(_) => {
                                            Err("PDB file not found")
                                        }
                                    }
                                }
                            };

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
