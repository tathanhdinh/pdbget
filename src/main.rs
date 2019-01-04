#![feature(generators, generator_trait)]
#![recursion_limit = "128"]

#[macro_use]
mod error;
mod arg;
mod pdb;

use std::result;

use {
    indicatif::{ProgressBar, ProgressStyle},
    rayon::prelude::*,
};

type GlobalResult = result::Result<(), failure::Error>;

fn main() -> GlobalResult {
    env_logger::init();

    let config = arg::Config::new()?;

    print!("Scanning PE files, please wait...");
    let pe_files = config.scan_pe_files()?;
    println!("ok. Downloading PDBs...");

    // lazy generator
    let pdb_generator = pdb::PdbGenerator::new(pe_files);
    let pdbs: Vec<pdb::Pdb> = pdb_generator.into_iter().collect();

    let progress_bar = ProgressBar::new(pdbs.len() as u64);
    progress_bar.set_style(ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] {bar:40.cyan/blue} {pos:>7}/{len:7} (eta: {eta})")
                .progress_chars("#>-"));

    let target_dir = config.pdb_dir;
    let symbol_server = config.symbol_server;

    // concurrency: download is costly?
    pdbs.par_iter().for_each(|pdb| {
        if let Err(err) = pdb.download(&symbol_server, &target_dir) {
            log::warn!("{}", err);
        }
        progress_bar.inc(1);
    });

    progress_bar.finish();

    Ok(())
}
