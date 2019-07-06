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
use pulldown_cmark;
use pulldown_cmark::{Event, Tag, CowStr, LinkType};
use serde_json;

use std::path::{Path, PathBuf};
use std::fs::File;
use std::io::Write;
use std::collections::BTreeMap;

use content::{PartOrigin, Part, Whole};
use errors::HierosError;

/// This trait is implemented by all passes that only read the `Whole` and
/// update an external state as a side effect.
pub trait ReadOnlyPass<ExternalState> {
    fn apply(&mut self, w: &Whole, state: &mut ExternalState) -> Result<(), HierosError>;
}

/// This trait is implemented by all passes that modify one `Part` at a time but
/// cannot modify the `Whole`; an external state may be updated as a side effect
/// too.
pub trait LocalPass<ExternalState> {
    fn apply(&mut self, p: &mut Part, state: &mut ExternalState) -> Result<(), HierosError>;
}

/// This trait is implemented by all passes that modify `Part`s and the `Whole`;
/// an external state may be updated as a side effect too.
pub trait GlobalPass<ExternalState> {
    fn apply(&mut self, w: &mut Whole, state: &mut ExternalState) -> Result<(), HierosError>;
}

/// This represents the type of Hieros directive encountered.
#[derive(Clone,Copy,PartialEq,Eq)]
pub enum HierosDirectiveType {
    FromFencedCodeblock,
    FromInlineCodeblock
}

/// This utility `LocalPass` can be used to scan a `Part` and perform an
/// operation upon encountering each Hieros directive that matches the specified
/// id; if no id is provided, this Pass executes the operation on all Hieros
/// directives. While performing operations, this Pass creates a new vector of
/// `pulldown_cmark::Event`s as new content which will be swapped with the one
/// in the `Part` at the end of the process: the vector does not contain the
/// `Event`s for the directive but it can be modified by the operation,
/// therefore allowing the Pass to replace the directive with some generated
/// new text (or even preserve the directive - see `restore_directive()`).
/// Furthermore, if an error is encountered performing operations then the new
/// content will not be swapped and the `Part` will be unchanged.
pub struct DirectivePass<ExternalState> {
    id: Option<String>,
    op: fn(directive_type: HierosDirectiveType,
           directive_id: &str,
           directive_text: &str,
           new_content: &mut Vec<Event>,
           state: &mut ExternalState)
           -> Result<(), HierosError>,
}

impl<ExternalState> DirectivePass<ExternalState> {
    /// Creates a new DirectivePass.
    pub fn new(
        id: Option<String>,
        operation: fn(directive_type: HierosDirectiveType,
                      directive_id: &str,
                      directive_text: &str,
                      new_content: &mut Vec<Event>,
                      state: &mut ExternalState)
                      -> Result<(), HierosError>,
    ) -> DirectivePass<ExternalState> {
        DirectivePass {
            id: id,
            op: operation,
        }
    }

    /// Used to preserve an existing fenced codeblock directive after
    /// processing. The default is to eliminate it, but this function can be
    /// called from within the provided operation so that the Hieros directive
    /// can be reconstructed.
    pub fn restore_directive(
        directive_type: HierosDirectiveType,
        directive_id: &str,
        directive_text: &str,
        new_content: &mut Vec<Event>,
    ) {
        match directive_type {
            HierosDirectiveType::FromFencedCodeblock => {
                let e1 = Event::Start(Tag::CodeBlock(CowStr::Boxed(directive_id.to_owned().into_boxed_str())));
                let e2 = Event::Text(CowStr::Boxed(directive_text.to_owned().into_boxed_str()));
                let e3 = Event::End(Tag::CodeBlock(CowStr::Boxed(directive_id.to_owned().into_boxed_str())));
                new_content.push(e1);
                new_content.push(e2);
                new_content.push(e3);
            },
            HierosDirectiveType::FromInlineCodeblock => {
                let e = Event::Code(CowStr::Boxed(format!("{}: {}", directive_id, directive_text).into_boxed_str()));
                new_content.push(e);
            },
        }
    }
}

impl<ExternalState> LocalPass<ExternalState> for DirectivePass<ExternalState> {
    fn apply(&mut self, p: &mut Part, state: &mut ExternalState) -> Result<(), HierosError> {
        let mut new_content = Vec::new();
        let mut results = Vec::new();
        // State machine here is very simple. We scan the vector until we find
        // a structure that corresponds to a Hieros directive (either a fenced
        // codeblock or an inline codeblock), and we extract the directive id
        // and text. Then we run the self.op function and proceed.
        // While iterating, we only keep the directive events in the vector if
        // self.kp is false. If an error is encountered, the scan continues
        // but performs no further operations and ultimately returns the error.
        #[derive(Debug, Clone, Copy)]
        enum DirectiveParseState {
            Normal,
            WithinDirective,
            ErrorFound,
        }
        let mut parse_state = DirectiveParseState::Normal;
        let mut directive_id = String::new();
        let mut directive_text = String::new();
        p.content_iter().fold(&mut new_content, |new_content, evt| {
            match parse_state {
                DirectiveParseState::Normal => {
                    match evt {
                        Event::Code(full_text) => {
                            // Could be an inline code directive.
                            let splits: Vec<String> = full_text.split(":").map(|s| s.to_owned()).collect();
                            if splits.len() > 1 {
                                let expected_tag_pattern = match self.id {
                                    None => "hieros".to_string(),
                                    Some(ref id) => format!("hieros.{}", id),
                                };
                                if splits[0].starts_with(&expected_tag_pattern) {
                                    directive_id = splits[0].clone();
                                    directive_text = splits[1..].iter().fold(String::new(), |mut a, s| {
                                        let empty = a.len() == 0;
                                        if !empty {
                                            a.push_str(":");
                                        }
                                        a.push_str(&s);
                                        a
                                    }).trim_start().to_string();
                                    let res = (self.op)(HierosDirectiveType::FromInlineCodeblock, &directive_id, &directive_text, new_content, state);
                                    parse_state = match res {
                                        Ok(_) => DirectiveParseState::Normal,
                                        Err(_) => DirectiveParseState::ErrorFound,
                                    };
                                    results.push(res);
                                    directive_id.clear();
                                    directive_text.clear();
                                    new_content
                                } else {
                                    new_content.push(evt.clone());
                                    new_content
                                }
                            } else {
                                new_content.push(evt.clone());
                                new_content
                            }
                        },
                        Event::Start(t) => {
                            match t {
                                Tag::CodeBlock(cow) => {
                                    let expected_tag_pattern = match self.id {
                                        None => "hieros".to_string(),
                                        Some(ref id) => format!("hieros.{}", id),
                                    };
                                    if cow.starts_with(&expected_tag_pattern) {
                                        directive_id = cow.to_string();
                                        parse_state = DirectiveParseState::WithinDirective;
                                        new_content
                                    } else {
                                        new_content.push(evt.clone());
                                        new_content
                                    }
                                }
                                _ => {
                                    new_content.push(evt.clone());
                                    new_content
                                },
                            }
                        }
                        _ => {
                            new_content.push(evt.clone());
                            new_content
                        },
                    }
                },
                DirectiveParseState::WithinDirective => {
                    match evt {
                        Event::Text(ref text) => {
                            directive_text.push_str(text);
                            new_content
                        },
                        Event::End(t) => {
                            match t {
                                Tag::CodeBlock(_) => {
                                    let res = (self.op)(HierosDirectiveType::FromFencedCodeblock, &directive_id, &directive_text, new_content, state);
                                    parse_state = match res {
                                        Ok(_) => DirectiveParseState::Normal,
                                        Err(_) => DirectiveParseState::ErrorFound,
                                    };
                                    results.push(res);
                                    directive_id.clear();
                                    directive_text.clear();
                                    new_content
                                }
                                _ => {
                                    results.push(Err(HierosError::DirectiveParseError(
                                        "Unexpected pulldown_cmark End Event within a CommonMark fenced codeblock.".to_string())));
                                    parse_state = DirectiveParseState::ErrorFound;
                                    new_content
                                },
                            }
                        }
                        _ => {
                            results.push(Err(HierosError::DirectiveParseError(
                                "Unexpected pulldown_cmark Event within a CommonMark fenced codeblock.".to_string())));
                            parse_state = DirectiveParseState::ErrorFound;
                            new_content
                        },
                    }
                },
                DirectiveParseState::ErrorFound => {
                    new_content
                }
            }
        });
        // In all cases where there was an error, the error was pushed last and
        // no further results were pushed. Therefore, we can just return the
        // last element if present. If no directives were matched, the vector
        // is empty and we just return Ok.
        match results.pop() {
            None => {
                p.swap_content(new_content);
                Ok(())
            }
            Some(res) => {
                match res {
                    Ok(_) => {
                        p.swap_content(new_content);
                        Ok(())
                    }
                    _ => res,
                }
            }
        }
    }
}

#[test]
fn test_directive_nop_pass_preserving_directives() {
    let s = r#"
```hieros.one
blah
```

foo

```hieros
blah
```

`hieros.two: blah:blah`

bar
    "#;
    let mut part = Part::from_str(s, PartOrigin::RawString).unwrap();
    assert_eq!(part.content().len(), 16);
    let mut pass = DirectivePass::new(None, |directive_type, directive_id, directive_text, new_content, _| {
        DirectivePass::<()>::restore_directive(directive_type, directive_id, directive_text, new_content);
        Ok(())
    });
    pass.apply(&mut part, &mut ()).unwrap();
    assert_eq!(part.content().len(), 16);
}



/// A `LocalPass` that removes all Hieros directives from the `Part` it is
/// applied to; usually used to clean up before the final export.
pub struct RemoveDirectivesPass;

impl LocalPass<()> for RemoveDirectivesPass {
    fn apply(&mut self, p: &mut Part, state: &mut ()) -> Result<(), HierosError> {
        // This pass is just a DirectivePass which does not do anything with
        // the directives and eliminates them.
        let mut directive_pass = DirectivePass::new(None, |_, _, _, _, _| Ok(()));
        directive_pass.apply(p, state)
    }
}

#[test]
fn test_remove_directives() {
    let s = r#"
```hieros.one
blah
```

foo

```hieros
blah
```

`hieros.two: blah:blah`

bar
    "#;
    let mut part = Part::from_str(s, PartOrigin::RawString).unwrap();
    assert_eq!(part.content().len(), 16);
    let mut pass = RemoveDirectivesPass;
    pass.apply(&mut part, &mut ()).unwrap();
    assert_eq!(part.content().len(), 9);
    let mut rendered = String::new();
    pulldown_cmark::html::push_html(&mut rendered, part.content().iter().map(|evt| evt.clone()));
    assert_eq!(rendered, "<p>foo</p>\n<p></p>\n<p>bar\n</p>\n");
}

#[test]
fn test_remove_directives_preserves_content_when_no_directives() {
    let s = r#"
foo

bar
    "#;
    let mut part = Part::from_str(s, PartOrigin::RawString).unwrap();
    let mut pass = RemoveDirectivesPass;
    pass.apply(&mut part, &mut ()).unwrap();
    let mut rendered = String::new();
    pulldown_cmark::html::push_html(&mut rendered, part.content().iter().map(|evt| evt.clone()));
    assert_eq!(rendered, "<p>foo</p>\n<p>bar\n</p>\n");
}


/// A `ReadOnlyPass` which will output the content of the `Whole` as a
/// collection of HTML files laid flat under a specified directory.
pub struct HtmlExporterPass {
    output_dir: PathBuf,
}

impl HtmlExporterPass {
    /// Creates a HtmlExporterPass with the specified output directory.
    pub fn new(dir: &Path) -> Result<HtmlExporterPass, HierosError> {
        if !dir.is_dir() {
            return Err(HierosError::PassCreationError(
                format!("{} is not a directory", dir.display()),
            ));
        }
        Ok(HtmlExporterPass { output_dir: dir.to_path_buf() })
    }
}

impl ReadOnlyPass<Vec<PathBuf>> for HtmlExporterPass {
    fn apply(&mut self, w: &Whole, filenames: &mut Vec<PathBuf>) -> Result<(), HierosError> {
        filenames.clear();
        w.parts().iter().try_for_each(|part| {
            let cur_filename = match part.origin() {
                &PartOrigin::RawString |
                &PartOrigin::Created => format!("{:0>4}.html", filenames.len()),
                &PartOrigin::CommonMarkFile(ref path) => {
                    format!(
                        "{:0>4}-{}.html",
                        filenames.len(),
                        path.file_name().unwrap().to_str().unwrap()
                    )
                }
            };
            let mut cur_filepath = self.output_dir.clone();
            cur_filepath.push(cur_filename);

            let mut rendered = String::new();
            pulldown_cmark::html::push_html(
                &mut rendered,
                part.content().iter().map(|evt| evt.clone()),
            );
            let mut file = File::create(&cur_filepath)?;
            file.write_all(rendered.as_bytes())?;

            filenames.push(cur_filepath);
            Ok(())
        })
    }
}


/// A `GlobalPass` which parses all `hieros.index` directives and constructs a
/// `Part` at the end of the sequence, containing an analytical index of all the
/// terms encountered while processing the directives.
///
/// Index directives are of the form:
/// ~~~text
///    ```hieros.index
///    { "entry": "abc", "tag": "xyz" }
///    ```
/// ~~~
/// Which means that the index will contain something like:
///
/// > **Abc**: xyz
///
/// Where "xyz" is a hyperlink to the location where the `hieros.index`
/// directive was. The directive is elided by the pass.
///
/// If multiple directives are found with the same "entry", the index will
/// generate hyperlinks for all "tags" on a single line. This:
/// ~~~text
///    ```hieros.index
///    { "entry": "abc", "tag": "xyz" }
///    ```
///
///    ...
///
///    ```hieros.index
///    { "entry": "abc", "tag": "123" }
///    ```
/// ~~~
/// results in this:
///
/// > **Abc**: xyz, 123
///
pub struct IndexCreationPass {
    title: String,
}

impl IndexCreationPass {
    pub fn new(title: &str) -> IndexCreationPass {
        IndexCreationPass {
            title: title.to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct IndexEntry {
    entry: String,
    tag: String,
}

struct IndexLink {
    tag: String,
    link: String,
}

impl IndexEntry {
    fn entry_hash(&self) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        self.entry.hash(&mut hasher);
        self.tag.hash(&mut hasher);
        format!("{}", hasher.finish())
    }

    fn anchor(&self) -> String {
        format!("<a id=\"idx_{}\"></a>", self.entry_hash())
    }

    fn link_dest(&self) -> IndexLink {
        IndexLink {
            tag: self.tag.clone(),
            link: format!("#idx_{}", self.entry_hash()),
        }
    }
}

impl GlobalPass<()> for IndexCreationPass {
    /// Applies the pass and generates the index.
    fn apply(&mut self, w: &mut Whole, _: &mut ()) -> Result<(), HierosError> {
        // First of all gather all `hieros.index` directives and generate the
        // index map.
        let mut map : BTreeMap<String, Vec<IndexLink>> = BTreeMap::new();
        let mut gather = DirectivePass::new(Some("index".to_string()), |_, _, text, new_content, state: &mut BTreeMap<String, Vec<IndexLink>>| {
            let ie: IndexEntry = serde_json::from_str(text)?;
            let me = state.entry(ie.entry.clone()).or_insert(Vec::new());
            me.push(ie.link_dest());
            new_content.push(Event::Html(CowStr::Boxed(ie.anchor().clone().into_boxed_str())));
            Ok(())
        });
        w.parts_iter_mut().try_for_each(|part| gather.apply(part, &mut map) )?;
        // Then generate one last Part with the index content.
        let mut events = Vec::new();
        events.push(Event::Start(Tag::Header(1)));
        events.push(Event::Text(CowStr::Boxed(format!("{}", self.title).into_boxed_str())));
        events.push(Event::End(Tag::Header(1)));
        map.iter().for_each(|(entry, links)| {
            events.push(Event::Start(Tag::Paragraph));
            events.push(Event::Start(Tag::Strong));
            events.push(Event::Text(CowStr::Boxed(format!("{}: ", entry).into_boxed_str())));
            events.push(Event::End(Tag::Strong));
            let prev_size = events.len();
            links.iter().fold(&mut events, |events, link| {
                events.push(Event::Start(Tag::Link(LinkType::Inline, CowStr::Boxed(link.link.to_owned().into_boxed_str()), CowStr::Boxed(String::new().into_boxed_str()))));
                events.push(Event::Text(CowStr::Boxed(format!("{}", link.tag.clone()).into_boxed_str())));
                events.push(Event::End(Tag::Link(LinkType::Inline, CowStr::Boxed(link.link.to_owned().into_boxed_str()), CowStr::Boxed(String::new().into_boxed_str()))));
                events.push(Event::Text(CowStr::Borrowed(", ")));
                events
            });
            if events.len() > prev_size {
                // We've added something, remove last trailing comma
                events.pop().unwrap();
            }
            events.push(Event::End(Tag::Paragraph));
        });
        w.parts_mut().push(Part::from_raw(PartOrigin::Created, events));
        Ok(())
    }
}

#[test]
fn test_index_creation_pass() {
    let s = r#"
```hieros.index
{"entry": "foo", "tag": "definition"}
```
foo

```hieros.index
{"entry": "bar", "tag": "definition"}
```
bar

`hieros.index: {"entry": "foo", "tag": "reference"}` another foo
    "#;
    let part = Part::from_str(s, PartOrigin::RawString).unwrap();
    let mut whole = Whole::from_parts(vec!(part));
    let mut pass = IndexCreationPass::new("Index");
    pass.apply(&mut whole, &mut ()).unwrap();
    let mut rendered = String::new();
    whole.parts_iter().for_each(|part| {
        pulldown_cmark::html::push_html(&mut rendered, part.content().iter().map(|evt| evt.clone()));
    });
    let expected = r##"<a id="idx_2779447855341772346"></a>
<p>foo</p>
<a id="idx_11561231166754964973"></a>
<p>bar</p>
<p><a id="idx_12124113799365418005"></a> another foo
</p>
<h1>Index</h1>
<p><strong>bar: </strong><a href="#idx_11561231166754964973">definition</a></p>
<p><strong>foo: </strong><a href="#idx_2779447855341772346">definition</a>, <a href="#idx_12124113799365418005">reference</a></p>
"##;
    assert_eq!(rendered, expected);
}
