use std::{
    io::Error as IOError,
    result};

use {
    failure::Fail,
    goblin::error::Error as GoblinError,
    reqwest};

pub type Result<T> = result::Result<T, Error>;

#[derive(Fail, Debug)]
pub enum Error {
    #[fail(display = "I/O error: {}", _0)]
    IO(#[cause] IOError),

    #[fail(display = "PE parsing error: {}", _0)]
    PeParsing(#[cause] GoblinError),

    #[fail(display = "Url parsing error: {}", _0)]
    UrlParsing(#[cause] reqwest::UrlError),

    #[fail(display = "General network error: {}", _0)]
    Network(#[cause] reqwest::Error),

    #[fail(display = "Application error: {}", _0)]
    Application(String),

    #[fail(display = "End of generator")]
    StopGeneration,
}

impl From<IOError> for Error {
    fn from(err: IOError) -> Self {
        Error::IO(err)
    }
}

impl From<GoblinError> for Error {
    fn from(err: GoblinError) -> Self {
        Error::PeParsing(err)
    }
}

impl From<reqwest::UrlError> for Error {
    fn from(err: reqwest::UrlError) -> Self {
        Error::UrlParsing(err)
    }
}

impl From<reqwest::Error> for Error {
    fn from(err: reqwest::Error) -> Self {
        Error::Network(err)
    }
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
