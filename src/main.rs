#![recursion_limit="256"]

extern crate goblin;
extern crate glob;
extern crate uuid;
extern crate reqwest;
extern crate indicatif;
extern crate hex;
// extern crate colored;
extern crate rayon;

#[macro_use]
extern crate clap;

#[macro_use]
extern crate if_chain;

// #[macro_use]
// extern crate lazy_static;

use std::io::Read;
use std::io::Write;
// use colored::*;
use rayon::prelude::*;

static RAW_USER_AGENT: &'static str = "Microsoft-Symbol-Server/10.0.0.0";
static ARG_NAME_INPUT_PE: &'static str = "PE files";
static ARG_NAME_SYMBOL_SERVER: &'static str = "Symbol server";
static ARG_NAME_OUTPUT_FOLDER: &'static str = "Output folder";
// static ARG_NAME_VERBOSE_MODE: &'static str = "Verbose";
static ARG_NAME_CONCURRENT_DONWLOAD: &'static str = "Concurrent download";
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
}

fn make_pdb_file_url<'t>(compressed: bool, 
                         symbol_server_url: &str, 
                         pdb_name: &str, 
                         pdb_guid: &uuid::Uuid, 
                         pdb_age: u32) -> Result<reqwest::Url, &'t str> {
                             
    // download url = server_url + "/" + pdb_name + "/" + pdb_guid + pdb_age + "/" + pdb_name
    symbol_server_url.chars().last().ok_or("empty symbol server url").and_then(|last_char| {
        let symbol_server_url = 
            if last_char == '/' {
                let len = symbol_server_url.len();
                &symbol_server_url[..len - 1]
            } else { symbol_server_url };

        pdb_name.chars().last().ok_or("empty file name").and_then(|last_char| {
            let pdb_name = 
                if last_char == '\0' {
                    let len = pdb_name.len();
                    &pdb_name[..len - 1]
                } else { pdb_name };
            
            // display GUID under Microsoft encoding
            let (first, second, third, last) = pdb_guid.as_fields();
            let mut file_url = format!("{}/{}/{:08X}{:04X}{:04X}{}{:X}/{}", 
                                       symbol_server_url, 
                                       &pdb_name, 
                                       first.swap_bytes(), 
                                       second.swap_bytes(), 
                                       third.swap_bytes(), 
                                       hex::encode_upper(last),
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

fn build_pdb_file_path<'t>(file_url: &reqwest::Url, 
                           out_dir: &std::path::Path) -> Result<std::path::PathBuf, &'t str>
{
    out_dir.to_str().ok_or("malformed output folder path").and_then(|dir| {
        dir.chars().last()
        .ok_or("empty output folder path")
        .and_then(|last_char| {
            let out_dir = {
                if last_char == '/' {
                    let len = dir.len();
                    &dir[..len - 1]
                } else { dir }
            };

            let url_path = file_url.path();
            // let url_parts: Vec<&str> = file_url.as_str().rsplit('/').collect();
            let url_parts: Vec<&str> = url_path.rsplit('/').collect();
            if url_parts.len() < 3 {
                Err("PDB file name's elements are insufficient")
            }
            else {
                let pdb_parts = &url_parts[..3];

                let mut pdb_filepath = std::path::PathBuf::from(out_dir);
                pdb_filepath.push(pdb_parts[2]); 
                pdb_filepath.push(pdb_parts[1]);
                pdb_filepath.push(pdb_parts[0]);

                Ok(pdb_filepath)
            }
        })
    })
}

fn create_pdb_file<'t>(file_path: &std::path::PathBuf) -> Result<std::fs::File, &'t str> {

    file_path.file_name().ok_or_else(|| "cannot get PDB file name").or_else(|msg| Err(msg))?;

    let file_dir = file_path.parent().ok_or_else(|| "cannot get PDB directory").or_else(|msg| Err(msg))?;
    std::fs::create_dir_all(file_dir).or(Err("cannot create PDB directory"))?;
    
    let file = std::fs::File::create(file_path).or(Err("cannot create PDB file"))?;
    Ok(file)
}

fn save_pdb_file<'t>(file_path: &std::path::PathBuf, 
                     file_length: usize, 
                     response: &mut reqwest::Response) -> Result<usize, &'t str> {

    let last_result;

    match create_pdb_file(&file_path) {
        Ok(out_file) => {
            let mut out_file = std::io::BufWriter::new(out_file);
            let mut buffer = vec![0u8; DOWNLOAD_BUFFER_SIZE]; // capacity = 1024
            let mut downloaded_bytes: usize = 0;

            // let progress_bar = indicatif::ProgressBar::new(file_length as u64);
            // progress_bar.set_style(indicatif::ProgressStyle::default_bar()
            //     // .template("[{elapsed_precise}] {bar:40.cyan/blue} {pos:>7}/{len:7} {msg}")
            //     // .progress_chars("##-"));
            //     .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})")
            //     .progress_chars("=>-"));
        
            loop {
                if let Ok(read_bytes) = response.read(&mut buffer[..]) {
                    buffer.truncate(read_bytes);
                    if let Err(_) = out_file.write_all(&buffer) {
                        last_result = Err("cannot write to file");
                        break;
                    }
                    else {
                        downloaded_bytes += read_bytes;
                        if downloaded_bytes > file_length {
                            last_result = Err("received bytes exceed the file length");
                            break;
                        }
                        else {
                            // progress_bar.set_position(downloaded_bytes as u64);
                            if downloaded_bytes == file_length {
                                last_result = Ok(file_length);
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
                        last_result = Ok(file_length)
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

fn download_file<'t>(file_url: &reqwest::Url, 
                     out_dir: &std::path::Path, 
                     /*verbose_mode: bool*/) -> Result<usize, &'t str> {
    
    let client = reqwest::Client::new();
    
    // if verbose_mode {
    //     println!("\ttry with url: {}", file_url);
    // }

    let mut response = client.get(file_url.clone())
    .header(reqwest::header::UserAgent::new(RAW_USER_AGENT))
    .send()
    .or_else(|_| Err("no GET response"))?;

    let get_file_length = |resp: &reqwest::Response| {
            response_length(resp).ok_or("cannot get file length").and_then(|s| {

                if s > 0 {
                    if s < std::usize::MAX as u64 {
                        Ok(s) } else { Err("file too large") }
                } else { Err("empty file") }
            })
        };
    
    match response.status() {
        reqwest::StatusCode::Ok => {
            get_file_length(&response).or(Err("cannot get file length")).and_then(|length| {

                let file_path = build_pdb_file_path(file_url, out_dir)
                .or_else(|msg| Err(msg))?;
                save_pdb_file(&file_path, length as usize, &mut response) 
            })
        },

        reqwest::StatusCode::MovedPermanently | reqwest::StatusCode::Found |
        reqwest::StatusCode::SeeOther | reqwest::StatusCode::TemporaryRedirect |
        reqwest::StatusCode::PermanentRedirect => {

            let location = response_location(&response)
            .ok_or_else(|| "redirected url not found")
            .or_else(|msg| Err(msg))?;
            
            let redirected_url = reqwest::Url::parse(location)
            .or_else(|_| Err("redirected url malformed"))?;
            
            // if verbose_mode {
            //     println!("\ttry with url: {}", redirected_url);
            // }

            let mut response = client.get(redirected_url.clone())
            .header(reqwest::header::UserAgent::new(RAW_USER_AGENT))
            .send()
            .or_else(|_| Err("no GET response"))?;

            match response.status() {
                reqwest::StatusCode::Ok => {

                    get_file_length(&response).or(Err("cannot get file length")).and_then(|length| {
                        let file_path = build_pdb_file_path(&redirected_url, out_dir)
                        .or_else(|msg| Err(msg))?;
                        save_pdb_file(&file_path, length as usize, &mut response) 
                    })
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
    let matches = clap::App::new("pdbget")
        .version("0.1.0")
        .author("TA Thanh Dinh <tathanhdinh@gmail.com>")
        .about("Download PDB (Program DataBase) files from a symbol server")
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
             .help("URL of the symbol server (e.g. https://msdl.microsoft.com/download/symbols/)"))
        .arg(clap::Arg::with_name(ARG_NAME_OUTPUT_FOLDER)
             .short("o")
             .long("output")
             .takes_value(true)
             .help("Location for downloaded PDB(s) [default: current folder]"))
        // .arg(clap::Arg::with_name(ARG_NAME_VERBOSE_MODE)
        //      .short("v")
        //      .long("verbose")
        //      .help("Verbose mode"))
        .arg(clap::Arg::with_name(ARG_NAME_CONCURRENT_DONWLOAD)
            .short("t")
            .long("thread")
            .takes_value(true)
            .help("Number of downloading threads [default or 0: best effort]"))
        .get_matches();

    // let thread_number = value_t!(matches, ARG_NAME_CONCURRENT_DONWLOAD, usize).unwrap_or(1);
    let mut best_effort = false;
    let mut thread_number = 0;
    if matches.is_present(ARG_NAME_CONCURRENT_DONWLOAD) {
        match value_t!(matches, ARG_NAME_CONCURRENT_DONWLOAD, usize) {
            Ok(value) => {
                if value == 0 {
                    best_effort = true;
                }
                else {
                    thread_number = value;
                }
            },

            Err(_) => {
                println!("error: {}", "number of threads invalid");
                return;
            }
        }
    }
    else {
        best_effort = true;
    }

    if !best_effort {
        if rayon::initialize(rayon::Configuration::new().num_threads(thread_number)).is_err() {
            println!("error: cannot set {} downloading threads", thread_number);
            return;
        }
    }

    let symbol_server_url = matches.value_of(ARG_NAME_SYMBOL_SERVER).unwrap(); // should not panic :)
    if let Ok(url) = reqwest::Url::parse(symbol_server_url) {
        let scheme = url.scheme();
        if scheme != "http" && scheme != "https" {
            println!("error: {}", "only http or https is supported");
            return;
        }
    }
    else {
        println!("error: {}", "malformed symbol server url");
        return;
    }

    let out_dir = 
        matches.value_of(ARG_NAME_OUTPUT_FOLDER)
        .map_or(std::env::current_dir().or_else(|_| Err("cannot get the current folder")), 
                |dir| {
            let path = std::path::Path::new(dir);
            if path.exists() {
                std::fs::metadata(path)
                .or_else(|_| Err("output location not accessible"))
                .and_then(|mdt| {
                    if mdt.is_dir() {
                        Ok(path.to_path_buf()) } else { Err("output location is not a folder") }
                })
            }
            else {
                std::fs::create_dir_all(path)
                .or_else(|_| Err("output location not found"))
                .and_then(|_| Ok(path.to_path_buf()))
            }
        });

    // early return
    if let Err(msg) = out_dir {
        println!("error: {}", msg);
        return;
    }

    let out_dir = out_dir.as_ref().unwrap();

    // let verbose_mode = matches.is_present(ARG_NAME_VERBOSE_MODE);

    // let concurrent_download = matches.is_present(ARG_NAME_CONCURRENT_DONWLOAD);

    // let mut download_success_count: usize = 0;
    // let mut download_failed_count: usize = 0;
    // let mut parsing_failed_count: usize = 0;

    let inputs = matches.values_of("PE files").unwrap();
    let options = glob::MatchOptions::new();
    for name in inputs {
        if let Ok(entries) = glob::glob_with(name, &options) {
            let entries: Vec<_> = entries.collect();

            let progress_bar = indicatif::ProgressBar::new(entries.len() as u64);
            progress_bar.set_style(indicatif::ProgressStyle::default_bar()
                // .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})")
                .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos:>7}/{len:7} {msg}")
                .progress_chars("=>-"));

            entries.into_par_iter().for_each(|entry| {
                if_chain! {
                    if let Ok(entry) = entry;
                    let entry_path = entry.as_path();
                    if let Ok(file_mdt) = std::fs::metadata(entry_path);
                    
                    // check if the file is regular since the next open will be blocked
                    // if the file is a pipe
                    if file_mdt.file_type().is_file();

                    if let Ok(mut fd) = std::fs::File::open(entry_path);
                    // if let Ok(_) =  { buffer.clear(); fd.read_to_end(&mut buffer) };
                    let mut buffer = Vec::new();
                    if { /*buffer.clear();*/ fd.read_to_end(&mut buffer) }.is_ok();
                    
                    if let Ok(obj) = goblin::Object::parse(&buffer);
                    if let goblin::Object::PE(pe_obj) = obj;
                    
                    if let Some(debug_header) = pe_obj.debug_data;
                    if let Some(codeview_pdb70) = debug_header.codeview_pdb70_debug_info;
                    
                    // get pdb: name, guid, age
                    let base_name =  codeview_pdb70.filename.split(|&c| '\\' as u8 == c)
                                                            .last()
                                                            .unwrap_or(codeview_pdb70.filename);
                                                            
                    if let Ok(pdb_name) = std::str::from_utf8(base_name);
                    if let Ok(pdb_guid) = uuid::Uuid::from_bytes(&codeview_pdb70.signature);
                    let pdb_age = codeview_pdb70.age;

                    if let Ok(mut file_url) = make_pdb_file_url(false, 
                                                                symbol_server_url, 
                                                                pdb_name, 
                                                                &pdb_guid, 
                                                                pdb_age);
                    then {
                        
                        // println!("Download PDB for {}", entry.to_string_lossy());

                        let _ = download_file(&file_url, out_dir/*, verbose_mode*/).or_else(|_|{
                            file_url = make_pdb_file_url(true, 
                                                        symbol_server_url, 
                                                        pdb_name, 
                                                        &pdb_guid, 
                                                        pdb_age).unwrap(); // should not panic :)
                            download_file(&file_url, out_dir/*, verbose_mode*/) });

                        // if download_result.is_ok() {
                        //     download_success_count += 1;
                        // }
                        progress_bar.set_message(&format!("({} threads)", rayon::current_num_threads()));
                        progress_bar.inc(1);

                        // let download_msg = 
                        //     download_result.map(|length| format!("ok: {} bytes", length).bright_green())
                        //     .unwrap_or_else(|msg| format!("error: {}", msg).bright_red());
                            
                        // println!("\t{}", download_msg);
                    }
                }
            });

            // let msg = format!("Finished, downloaded files at: {}", out_dir.to_string_lossy());
            // progress_bar.finish_with_message(&msg);
            progress_bar.finish();
            println!("Finished, downloaded files at: {}", out_dir.to_string_lossy());
        }
    }
}
