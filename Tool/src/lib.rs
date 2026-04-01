pub mod app;

mod config;
mod dedup;
mod download;
mod geosite;
mod output;

pub type AppResult<T> = Result<T, String>;
