use serde::Deserialize;

#[derive(Deserialize, Debug)]
pub struct Definition {
    pub title: String,
    pub hash: String,
}

#[derive(Deserialize, Debug)]
pub struct Definitions {
    pub definitions: Vec<Definition>,
}
