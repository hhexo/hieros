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
use pulldown_cmark::{Event, Tag};

use std::path::{Path, PathBuf};
use std::fs::File;
use std::io::Write;
use std::borrow::Cow;

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
    op: fn(directive_id: &str,
           directive_text: &str,
           new_content: &mut Vec<Event>,
           state: &mut ExternalState)
           -> Result<(), HierosError>,
}

impl<ExternalState> DirectivePass<ExternalState> {
    /// Creates a new DirectivePass.
    pub fn new(
        id: Option<String>,
        operation: fn(directive_id: &str,
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

    /// Used to preserve an existing directive after processing. The default is
    /// to eliminate it, but this function can be called from within the
    /// provided operation so that the Hieros directive can be reconstructed.
    pub fn restore_directive(
        directive_id: &str,
        directive_text: &str,
        new_content: &mut Vec<Event>,
    ) {
        let e1 = Event::Start(Tag::CodeBlock(Cow::Owned(directive_id.to_string())));
        let e2 = Event::Text(Cow::Owned(directive_text.to_string()));
        let e3 = Event::End(Tag::CodeBlock(Cow::Owned(directive_id.to_string())));
        new_content.push(e1);
        new_content.push(e2);
        new_content.push(e3);
    }
}

impl<ExternalState> LocalPass<ExternalState> for DirectivePass<ExternalState> {
    fn apply(&mut self, p: &mut Part, state: &mut ExternalState) -> Result<(), HierosError> {
        let mut new_content = Vec::new();
        let mut results = Vec::new();
        // State machine here is very simple. We scan the vector until we find
        // a Start event for a codeblock with the Hieros directive, at which
        // point we expect one or more text events containing the directive
        // text, and we collect the text; finally, upon an End event for the
        // codeblock we run the self.op function and revert to normal state.
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
            println!("Parse state: {:?}", parse_state);
            match parse_state {
                DirectiveParseState::Normal => {
                    match evt {
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
                                    let res = (self.op)(&directive_id, &directive_text, new_content, state);
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
        println!("New content size: {}", new_content.len());
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

```hieros.two
blah
```

bar
    "#;
    let mut part = Part::from_str(s, PartOrigin::RawString).unwrap();
    assert_eq!(part.content().len(), 15);
    let mut pass = DirectivePass::new(None, |directive_id, directive_text, new_content, _| {
        DirectivePass::<()>::restore_directive(directive_id, directive_text, new_content);
        Ok(())
    });
    pass.apply(&mut part, &mut ()).unwrap();
    assert_eq!(part.content().len(), 15);
}



/// A `LocalPass` that removes all Hieros directives from the `Part` it is
/// applied to; usually used to clean up before the final export.
pub struct RemoveDirectivesPass;

impl LocalPass<()> for RemoveDirectivesPass {
    fn apply(&mut self, p: &mut Part, state: &mut ()) -> Result<(), HierosError> {
        // This pass is just a DirectivePass which does not do anything with
        // the directives and eliminates them.
        let mut directive_pass = DirectivePass::new(None, |_, _, _, _| Ok(()));
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

```hieros.two
blah
```

bar
    "#;
    let mut part = Part::from_str(s, PartOrigin::RawString).unwrap();
    assert_eq!(part.content().len(), 15);
    let mut pass = RemoveDirectivesPass;
    pass.apply(&mut part, &mut ()).unwrap();
    assert_eq!(part.content().len(), 6);
    let mut rendered = String::new();
    pulldown_cmark::html::push_html(&mut rendered, part.content().iter().map(|evt| evt.clone()));
    assert_eq!(rendered, "<p>foo</p>\n<p>bar</p>\n");
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
    assert_eq!(rendered, "<p>foo</p>\n<p>bar</p>\n");
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
                &PartOrigin::Created => format!("{:0>4}.md", filenames.len()),
                &PartOrigin::CommonMarkFile(ref path) => {
                    format!(
                        "{:0>4}-{}.md",
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
