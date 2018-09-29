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
use std::path::PathBuf;
use std::slice::{Iter, IterMut};
use pulldown_cmark::{Options, OPTION_ENABLE_TABLES, OPTION_ENABLE_FOOTNOTES, Event, Parser};
use errors::HierosError;

/// This variant represents the origin of a `Part`: for example it can be a file
/// or a string, or it might even have been created by some Hieros pass.
pub enum PartOrigin {
    CommonMarkFile(PathBuf),
    RawString,
    Created,
}

/// A Part represents a chunk of content with a certain origin. The ownership of
/// the raw string content is external to the Part.
pub struct Part<'a> {
    origin: PartOrigin,
    content: Vec<Event<'a>>,
}

impl<'a> Part<'a> {
    /// Creates a Part from a string reference, also specifying its origin. Note
    /// that an external entity must own the actual string.
    pub fn from_str(text: &'a str, origin: PartOrigin) -> Result<Part, HierosError> {
        let mut opts = Options::empty();
        opts.insert(OPTION_ENABLE_TABLES);
        opts.insert(OPTION_ENABLE_FOOTNOTES);
        let p = Parser::new_ext(text, opts);
        let content = p.collect();
        Ok(Part {
            origin: origin,
            content: content,
        })
    }

    pub fn origin(&self) -> &PartOrigin {
        &self.origin
    }

    pub fn content(&self) -> &Vec<Event<'a>> {
        &self.content
    }

    pub fn content_mut(&mut self) -> &mut Vec<Event<'a>> {
        &mut self.content
    }

    pub fn content_iter(&self) -> Iter<Event<'a>> {
        self.content.iter()
    }

    pub fn content_iter_mut(&mut self) -> IterMut<Event<'a>> {
        self.content.iter_mut()
    }

    pub fn swap_content(&mut self, new_content: Vec<Event<'a>>) {
        self.content = new_content
    }
}

/// A Whole represents a collection of Parts. The ownership of the raw string
/// content of each individual Part is external to the Whole.
pub struct Whole<'a> {
    parts: Vec<Part<'a>>,
}

impl<'a> Whole<'a> {
    pub fn from_parts(parts: Vec<Part<'a>>) -> Whole<'a> {
        Whole { parts: parts }
    }

    pub fn parts(&self) -> &Vec<Part<'a>> {
        &self.parts
    }

    pub fn parts_mut(&mut self) -> &mut Vec<Part<'a>> {
        &mut self.parts
    }

    pub fn parts_iter(&self) -> Iter<Part<'a>> {
        self.parts.iter()
    }

    pub fn parts_iter_mut(&mut self) -> IterMut<Part<'a>> {
        self.parts.iter_mut()
    }
}


#[test]
fn test_part_creation() {
    let s1 = r#"
```hieros
blah
```
foo

bar
    "#;
    let s2 = r#"
foo

bar
    "#;
    let part1 = Part::from_str(s1, PartOrigin::RawString).unwrap();
    let part2 = Part::from_str(s2, PartOrigin::RawString).unwrap();
    assert_eq!(part1.content().len(), 9);
    assert_eq!(part2.content().len(), 6);
}

#[test]
fn test_part_swap_content() {
    let s1 = r#"
```hieros
blah
```
foo

bar
    "#;
    let s2 = r#"
foo

bar
    "#;
    let mut part1 = Part::from_str(s1, PartOrigin::RawString).unwrap();
    assert_eq!(part1.content().len(), 9);
    let mut opts = Options::empty();
    opts.insert(OPTION_ENABLE_TABLES);
    opts.insert(OPTION_ENABLE_FOOTNOTES);
    let p = Parser::new_ext(s2, opts);
    let content2 = p.collect();
    part1.swap_content(content2);
    assert_eq!(part1.content().len(), 6);
}
