use std::{io, result};

use failure::Fail;
use goblin::error as GoblinError;
use reqwest;

pub type Result<T> = result::Result<T, Error>;

#[derive(Fail, Debug)]
pub enum Error {
    #[fail(display = "I/O error: {}", _0)]
    Io(#[cause] io::Error),

    #[fail(display = "PE parsing error: {}", _0)]
    PeParsing(#[cause] GoblinError::Error),

    #[fail(display = "Url parsing error: {}", _0)]
    UrlParsing(#[cause] reqwest::UrlError),

    #[fail(display = "Connection error: {}", _0)]
    Connection(#[cause] reqwest::Error),

    #[fail(display = "Application error: {}", _0)]
    Application(String),

    #[fail(display = "End of generator")]
    StopGeneration,
}

macro_rules! application_error {
    ($msg:expr) => {
        Error::Application(String::from($msg))
    };
}

macro_rules! fail_with_application_error {
    ($msg:expr) => {
        return Err(application_error!($msg));
    };
}
