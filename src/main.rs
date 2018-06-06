#![feature(rust_2018_preview, rust_2018_idioms)]
#![feature(generators, generator_trait)]
#![recursion_limit = "128"]

extern crate goblin;
extern crate glob;
extern crate uuid;
extern crate reqwest;
extern crate indicatif;
extern crate hex;
extern crate rayon;
extern crate byteorder;

#[macro_use] extern crate if_chain;
#[macro_use] extern crate structopt;
#[macro_use] extern crate failure;
#[macro_use] extern crate log;
extern crate walkdir;
extern crate env_logger;

#[macro_use] mod error;
mod arg;
mod pdb;

use std::{result};

use indicatif::{ProgressBar, ProgressStyle};
use rayon::prelude::*;

type GlobalResult = result::Result<(), failure::Error>;

fn main() -> GlobalResult {
    env_logger::init();

    let config = arg::Config::new()?;

    // lazy generator
    let pdb_generator = pdb::PdbGenerator::new(config.pe_files);
    let pdbs: Vec<pdb::Pdb> = pdb_generator.to_iter().collect();

    let progress_bar = ProgressBar::new(pdbs.len() as u64);
    progress_bar.set_style(ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] {bar:40.cyan/blue} {pos:>7}/{len:7}")
                // .template("[{elapsed_precise}] {bar:40.cyan/blue} {pos:>7}/{len:7} {msg}")
                // .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})")
                .progress_chars("#>-"));

    let target_dir = config.pdb_dir;
    let symbol_server =config.symbol_server;

    // concurrency: download is costly?
    pdbs.par_iter().for_each(|pdb| {
        if let Err(err) = pdb.download(&symbol_server, &target_dir) {
            warn!("{}", err);
        }
        progress_bar.inc(1);
    });

    progress_bar.finish();

    Ok(())
}
