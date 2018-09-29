// Copyright 2018 Dario Domizioli
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std;
use serde_json;

/// An error that can be returned by Hieros operations.
#[derive(Debug)]
pub enum HierosError {
    IOError(std::io::Error),
    PassCreationError(String),
    DirectiveParseError(String),
    JSONParseError(serde_json::Error),
    GenericError(String),
}

impl std::convert::From<std::io::Error> for HierosError {
    fn from(e: std::io::Error) -> Self {
        HierosError::IOError(e)
    }
}

impl std::convert::From<serde_json::Error> for HierosError {
    fn from(e: serde_json::Error) -> Self {
        HierosError::JSONParseError(e)
    }
}
