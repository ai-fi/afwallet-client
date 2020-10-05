


pub mod auth;
pub mod routes;
pub mod storage;
pub mod server;

type Result<T> = std::result::Result<T, failure::Error>;

pub struct Config {
    pub db: storage::db::DB,
}
