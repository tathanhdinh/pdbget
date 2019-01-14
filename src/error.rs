use std::{io::Error as IOError, path, result};

use {failure::Fail, goblin::error::Error as GoblinError, reqwest};

pub(crate) type Result<T> = result::Result<T, Error>;

#[derive(Fail, Debug)]
pub(crate) enum Others {
    #[fail(display = "PE debug data not found ({})", _0)]
    PeDebugNotFound(String),

    #[fail(display = "CodeView PDB 7.0 information not found ({})", _0)]
    PeCodeViewPdbNotFound(String),

    #[fail(display = "bad PDB file name ({})", _0)]
    PdbBadName(String),

    #[fail(display = "input not found ({})", _0)]
    InputNotFound(String),

    #[fail(display = "server bad response ({})", _0)]
    ServerBadResponse(String),
}

#[derive(Fail, Debug)]
pub(crate) enum Error {
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

    #[fail(display = "Application error: ")]
    Others,

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
        crate::error::Error::Application(String::from($msg))
    };
}

macro_rules! fail_with_application_error {
    ($msg:expr) => {
        return Err(application_error!($msg));
    };
}
