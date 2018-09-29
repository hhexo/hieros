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

//! Hieros is a Rust crate providing a text processing abstraction built on top
//! of [pulldown-cmark](https://github.com/google/pulldown-cmark), along with
//! a few ready-made transformations and operations.
//!
//! The text content is organized in `Part`s, which are "chunks" of CommonMark
//! content and usually correspond to CommonMark files. `Part`s are grouped in a
//! sequence, which forms the `Whole`. `Part`s have a `PartOrigin` which
//! specifies where the content comes from (e.g. whether it comes from a file or
//! it has been created).
//!
//! The text thus collected can be analysed or processed by _passes_. There are
//! three types of passes:
//!
//! * `ReadOnlyPass`, which only reads `Part`s and the `Whole` and usually
//!   constructs some internal state or produces side effects that do not affect
//!   the data structures. For example, a word counter would be such a pass, or
//!   even the final export of the CommonMark content to some output.
//! * `LocalPass`, which can modify the content of `Part`s but not the structure
//!   of the `Whole`. Text substitution functions are usually in this category.
//! * `GlobalPass`, which can modify the structure of the `Whole` as well as
//!   possibly the individual content of `Part`s. For example, something that
//!   creates a table of contents and inserts it at the beginning of the
//!   sequence.
//!
//! A common functionality of all passes is that they can access Hieros
//! Directives specified in the CommonMark content. These are written in the
//! input as CommonMark fenced code blocks with a language info tag equal to
//! `hieros.<id>`, where `.<id>` is an optional identifier for a pass.
//! Directives are obviously not intended to end up in the final output of the
//! text manipulation, therefore a `RemoveDirectivesPass` is provided among the
//! ready-made passes.
//!
//! The internal format of the text in the Hieros directives blocks is entirely
//! arbitrary and may or may not be interpreted by the passes. Each pass is
//! responsible for making use of it as it sees fit, and also for reporting
//! meaningful errors if it detects that the syntax is wrong.
//!
//! # Using `hieros`
//!
//! At the moment Hieros is not available on crates.io, but it will be in the
//! future. Feel free to try it with:
//!
//! `hieros = { git = "https://github.com/hhexo/hieros.git" }`
//!
//! # Example
//!
//! ~~~rust,no_run
//! use hieros::{HierosError, PartOrigin, Part, Whole, ReadOnlyPass, LocalPass, RemoveDirectivesPass, HtmlExporterPass};
//! use std::path::Path;
//! fn example() -> Result<(), HierosError> {
//!
//!     let s1 = r#"
//!     ```hieros.one
//!     blah
//!     ```
//!
//!     foo
//!     "#;
//!     let s2 = r#"
//!     ```hieros.two
//!     blah
//!     ```
//!
//!     bar
//!     "#;
//!     let part1 = Part::from_str(s1, PartOrigin::RawString).unwrap();
//!     let part2 = Part::from_str(s2, PartOrigin::RawString).unwrap();
//!     let mut whole = Whole::from_parts(vec!(part1, part2));
//!     // Remove directives, then output html files for each part
//!     let mut rdp = RemoveDirectivesPass;
//!     let mut hep = HtmlExporterPass::new(&Path::new("/tmp")).unwrap();
//!     whole.parts_iter_mut().try_for_each(|part| {
//!         rdp.apply(part, &mut ())
//!     })?;
//!     let mut files = Vec::new();
//!     hep.apply(&whole, &mut files)
//! }
//! ~~~
//!

extern crate pulldown_cmark;
extern crate serde;
extern crate serde_json;
#[macro_use]
extern crate serde_derive;

mod content;
mod errors;
mod passes;

pub use content::{PartOrigin, Part, Whole};
pub use errors::HierosError;
pub use passes::{ReadOnlyPass, LocalPass, GlobalPass, DirectivePass,
                 RemoveDirectivesPass, HtmlExporterPass, IndexCreationPass};
