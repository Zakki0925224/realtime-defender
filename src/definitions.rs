use serde::Deserialize;

#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Definition {
    pub title: String,
    pub hash: String,
}

#[derive(Deserialize, Debug)]
pub struct Definitions {
    pub definitions: Vec<Definition>,
}
