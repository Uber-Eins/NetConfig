pub mod app;

mod config;
mod dedup;
mod download;
mod geosite;
mod mrs;
mod output;

pub type AppResult<T> = Result<T, String>;
