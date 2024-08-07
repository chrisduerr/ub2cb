use std::cmp::Ordering;
use std::fmt::{self, Display, Formatter};

use bitflags::bitflags;

pub mod content_blocker;
pub mod ublock;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Rule {
    url_regex: String,

    selector: Option<String>,

    resource_types: ResourceTypes,
    load_context: LoadContext,
    load_type: LoadType,

    // Domain only supports leading `*` for subdomain matching, no regex.
    unless_domains: Vec<String>,
    if_domains: Vec<String>,

    case_sensitive: bool,
    important: bool,

    /// Disable other rules for this resource.
    inverse: bool,
}

impl Rule {
    fn new(url_regex: impl Into<String>) -> Self {
        Self {
            resource_types: ResourceTypes::empty(),
            url_regex: url_regex.into(),
            case_sensitive: Default::default(),
            unless_domains: Default::default(),
            load_context: Default::default(),
            if_domains: Default::default(),
            important: Default::default(),
            load_type: Default::default(),
            selector: Default::default(),
            inverse: Default::default(),
        }
    }
}

impl Ord for Rule {
    fn cmp(&self, other: &Self) -> Ordering {
        // Important items are always last, so they aren't overwritten.
        match self.important.cmp(&other.important) {
            Ordering::Equal => (),
            ordering => return ordering,
        }

        // CSS rules are before other rules, for performance reasons.
        match self.selector.cmp(&other.selector) {
            Ordering::Equal => (),
            Ordering::Less => return Ordering::Greater,
            Ordering::Greater => return Ordering::Less,
        }

        // Inverse rules are after normal rules, so they actually work.
        match self.inverse.cmp(&other.inverse) {
            Ordering::Equal => (),
            ordering => return ordering,
        }

        // Otherwise we fall back to the other fields.
        (
            &self.url_regex,
            &self.resource_types,
            &self.load_type,
            &self.load_type,
            &self.unless_domains,
            &self.if_domains,
            &self.case_sensitive,
        )
            .cmp(&(
                &other.url_regex,
                &other.resource_types,
                &other.load_type,
                &other.load_type,
                &other.unless_domains,
                &other.if_domains,
                &other.case_sensitive,
            ))
    }
}

impl PartialOrd for Rule {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

bitflags! {
    /// Request resource purpose.
    #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
    struct ResourceTypes: u16 {
        const DOCUMENT     = 0b0000_0000_0000_0001;
        const IMAGE        = 0b0000_0000_0000_0010;
        const STYLE_SHEET  = 0b0000_0000_0000_0100;
        const SCRIPT       = 0b0000_0000_0000_1000;
        const FONT         = 0b0000_0000_0001_0000;
        const RAW          = 0b0000_0000_0010_0000;
        const SVG_DOCUMENT = 0b0000_0000_0100_0000;
        const MEDIA        = 0b0000_0000_1000_0000;
        const POPUP        = 0b0000_0001_0000_0000;
        const PING         = 0b0000_0010_0000_0000;
        const FETCH        = 0b0000_0100_0000_0000;
        const WEBSOCKET    = 0b0000_1000_0000_0000;
        const OTHER        = 0b0001_0000_0000_0000;
    }
}

impl Display for ResourceTypes {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "[")?;

        let mut flags = *self;
        if flags.contains(Self::DOCUMENT) {
            flags.remove(Self::DOCUMENT);
            if flags.is_empty() {
                write!(f, "\"document\"")?;
            } else {
                write!(f, "\"document\",")?;
            }
        }
        if flags.contains(Self::IMAGE) {
            flags.remove(Self::IMAGE);
            if flags.is_empty() {
                write!(f, "\"image\"")?;
            } else {
                write!(f, "\"image\",")?;
            }
        }
        if flags.contains(Self::STYLE_SHEET) {
            flags.remove(Self::STYLE_SHEET);
            if flags.is_empty() {
                write!(f, "\"style-sheet\"")?;
            } else {
                write!(f, "\"style-sheet\",")?;
            }
        }
        if flags.contains(Self::SCRIPT) {
            flags.remove(Self::SCRIPT);
            if flags.is_empty() {
                write!(f, "\"script\"")?;
            } else {
                write!(f, "\"script\",")?;
            }
        }
        if flags.contains(Self::FONT) {
            flags.remove(Self::FONT);
            if flags.is_empty() {
                write!(f, "\"font\"")?;
            } else {
                write!(f, "\"font\",")?;
            }
        }
        if flags.contains(Self::RAW) {
            flags.remove(Self::RAW);
            if flags.is_empty() {
                write!(f, "\"raw\"")?;
            } else {
                write!(f, "\"raw\",")?;
            }
        }
        if flags.contains(Self::SVG_DOCUMENT) {
            flags.remove(Self::SVG_DOCUMENT);
            if flags.is_empty() {
                write!(f, "\"svg-document\"")?;
            } else {
                write!(f, "\"svg-document\",")?;
            }
        }
        if flags.contains(Self::MEDIA) {
            flags.remove(Self::MEDIA);
            if flags.is_empty() {
                write!(f, "\"media\"")?;
            } else {
                write!(f, "\"media\",")?;
            }
        }
        if flags.contains(Self::POPUP) {
            flags.remove(Self::POPUP);
            if flags.is_empty() {
                write!(f, "\"popup\"")?;
            } else {
                write!(f, "\"popup\",")?;
            }
        }
        if flags.contains(Self::PING) {
            flags.remove(Self::PING);
            if flags.is_empty() {
                write!(f, "\"ping\"")?;
            } else {
                write!(f, "\"ping\",")?;
            }
        }
        if flags.contains(Self::FETCH) {
            flags.remove(Self::FETCH);
            if flags.is_empty() {
                write!(f, "\"fetch\"")?;
            } else {
                write!(f, "\"fetch\",")?;
            }
        }
        if flags.contains(Self::WEBSOCKET) {
            flags.remove(Self::WEBSOCKET);
            if flags.is_empty() {
                write!(f, "\"websocket\"")?;
            } else {
                write!(f, "\"websocket\",")?;
            }
        }
        if flags.contains(Self::OTHER) {
            flags.remove(Self::OTHER);
            if flags.is_empty() {
                write!(f, "\"other\"")?;
            } else {
                write!(f, "\"other\",")?;
            }
        }

        write!(f, "]")?;

        Ok(())
    }
}

/// Contexts a rule applies to.
#[derive(Default, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum LoadContext {
    #[default]
    Both,
    TopFrame,
    ChildFrame,
    /// Equivalent of `[Self::Both]`, but it can't be transitioned out of.
    ExplicitBoth,
}

impl LoadContext {
    /// Set this rule context as applying to child frames.
    fn set_child_frame(&mut self) {
        *self = match self {
            Self::Both => Self::ChildFrame,
            Self::ChildFrame => Self::ChildFrame,
            Self::TopFrame | Self::ExplicitBoth => Self::ExplicitBoth,
        };
    }

    /// Set this rule context as applying to top frames.
    fn set_top_frame(&mut self) {
        *self = match self {
            Self::Both => Self::TopFrame,
            Self::TopFrame => Self::TopFrame,
            Self::ChildFrame | Self::ExplicitBoth => Self::ExplicitBoth,
        };
    }
}

impl Display for LoadContext {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Both | Self::ExplicitBoth => write!(f, "[\"top-frame\", \"child-frame\"]"),
            Self::TopFrame => write!(f, "[\"top-frame\"]"),
            Self::ChildFrame => write!(f, "[\"child-frame\"]"),
        }
    }
}

/// Load type a rule applies to.
#[derive(Default, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum LoadType {
    #[default]
    Both,
    FirstParty,
    ThirdParty,
}

impl Display for LoadType {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Both => write!(f, "both"),
            Self::FirstParty => write!(f, "first-party"),
            Self::ThirdParty => write!(f, "third-party"),
        }
    }
}
