//! uBlock filter format handling.

use std::mem;

use log::debug;

use crate::{LoadType, ResourceTypes, Rule};

/// Regex matching any one separator character
const SEPARATOR_REGEX: &str = "[^A-Za-z0-9_.%-]";

/// Regex matching separator or EOL.
const SEPARATOR_REGEX_EOL: &str = "([^A-Za-z0-9_.%-].*)?$";

/// Regex matching any allowed url scheme.
///
/// Usually this should just match http(s)/ws(s), but disjunctions (`|`) are not
/// supported by content blocker's regex engine.
const SCHEMES_REGEX: &str = "[a-z]://";

/// Regex matching all subdomains.
const SUBDOMAIN_REGEX: &str = "[A-Za-z\\.-]*";

/// Regex matching any whitespace, equivalent to \s for ASCII.
const ANY_WHITESPACE_REGEX: &str = "[\\f\\n\\r\\t\\v ]";

/// Regex matching everything but whitespace, equivalent to \S for ASCII.
const NOT_WHITESPACE_REGEX: &str = "[^\\f\\n\\r\\t\\v ]";

/// Parse a uBlock filter.
pub fn parse(mut filter: &str) -> Vec<Rule> {
    // Strip BOM.
    filter = filter.strip_prefix('\u{feff}').unwrap_or(filter);

    filter.lines().filter_map(parse_line).collect()
}

/// Parse a line in a uBlock filter.
fn parse_line(line: &str) -> Option<Rule> {
    // Ignore comments and empty lines.
    let trimmed = line.trim_start();
    if trimmed.is_empty() || trimmed.starts_with('!') {
        return None;
    }

    // Ignore rules in unsupported formats.
    const UNSUPPORTED_SYNTAX: &[&str] =
        &["#@#", "#$#", "#?#", "#@?#", "#$?#", "#$@?#", "#%#", "##+js"];
    if UNSUPPORTED_SYNTAX.iter().any(|unsupported| line.contains(unsupported)) {
        debug!("Ignoring rule due to unsupported syntax:");
        debug!("    {line}");
        return None;
    }

    if let Some((domains, selector)) = line.split_once("##") {
        parse_cosmetic_rule(domains, selector)
    } else {
        parse_basic_rule(line)
    }
}

/// Parse element hiding rules.
fn parse_cosmetic_rule(domains: &str, selector: &str) -> Option<Rule> {
    // Create the rule with the associated cosmetic selector.
    let mut rule = Rule::new(".*");
    rule.selector = Some(selector.into());

    // Add all domains and their exceptions to which this rule applies.
    if add_domains(&mut rule.url_regexes, &mut rule.unless_domains, true, domains, ',').is_err() {
        debug!("Ignoring cosmetic rule due to unsupported domains format:");
        debug!("    {domains}##{selector}");
        return None;
    }

    // Remove the generic filter if there are specific ones.
    if rule.url_regexes.len() > 1 {
        rule.url_regexes.swap_remove(0);
    }

    Some(rule)
}

/// Parse basic request-blocking rules.
fn parse_basic_rule(line: &str) -> Option<Rule> {
    // Handle rule exceptions.
    let stripped_inverse = line.strip_prefix("@@");
    let inverse = stripped_inverse.is_some();
    let stripped_line = stripped_inverse.unwrap_or(line);

    // Separate domain matcher from modifier attributes.
    let split_domain = if stripped_line.starts_with('/') {
        // Check if this is a regex rule by looking for the terminating sequence.
        let mut split_index = None;
        let mut start_offset = 0;
        for i in 0..stripped_line.len() {
            match stripped_line[start_offset..i + 1].as_bytes() {
                // Avoid counting an escaped backslash as escape itself.
                [.., b'\\', b'\\'] => start_offset = i + 1,
                // Ignore terminating sequence if slash is escaped.
                [.., b'\\', b'/', b'$'] => (),
                [.., b'/', b'$'] => {
                    split_index = Some(i);
                    break;
                },
                _ => (),
            }
        }

        split_index.map(|i| {
            let (address, modifiers) = stripped_line.split_at(i);
            (address, &modifiers[1..])
        })
    } else {
        stripped_line.split_once('$')
    };
    let (address, modifiers) = split_domain.unwrap_or((stripped_line, ""));

    // Convert domain matcher to regex.
    let url_regex = match normalize_address(address) {
        Some(url_regex) => url_regex,
        None => {
            debug!("Ignoring rule due to non-ascii character in domain:");
            debug!("    {line}");
            return None;
        },
    };
    let normalized_regex = normalize_regex(&url_regex)?;
    let mut rule = Rule::new(normalized_regex);
    rule.inverse = inverse;

    // Add all modifiers to the rule.
    match add_modifiers(&mut rule, modifiers) {
        Ok(()) => Some(rule),
        Err(ParsingError::UnknownModifier(modifier)) => {
            debug!("Ignoring rule due to unknown modifier {modifier:?}:");
            debug!("    {line}");
            None
        },
        Err(ParsingError::RegexDomain | ParsingError::UnsupportedRegex) => {
            debug!("Ignoring rule due to regex in domain modifier:");
            debug!("    {line}");
            None
        },
        Err(ParsingError::NonAscii) => {
            debug!("Ignoring rule due to non-ascii character domain modifier:");
            debug!("    {line}");
            None
        },
    }
}

/// Convert filter address into its regex representation.
fn normalize_address(mut address: &str) -> Option<String> {
    // Only ASCII is supported in `url-filter.
    if !address.is_ascii() {
        return None;
    }

    // Handle empty addresses.
    if address.is_empty() {
        return Some(".*".into());
    }

    // Handle addresses that already use regex.
    if let Some(start) = address.strip_prefix('/') {
        if let Some(regex) = start.strip_suffix('/') {
            return Some(regex.into());
        }
    }

    let mut regex = String::with_capacity(address.len());

    if let Some(stripped) = address.strip_prefix("||") {
        // Handle scheme/subdomain wildcard.
        address = stripped;
        regex.push_str(SCHEMES_REGEX);
        regex.push_str(SUBDOMAIN_REGEX);
    } else if let Some(stripped) = address.strip_prefix('|') {
        // Handle anchored addresses.
        address = stripped;
        regex.push('^');
    }

    for (i, c) in address.chars().enumerate() {
        match c {
            '*' => regex.push_str(".*"),
            '^' if i + 1 == address.len() => regex.push_str(SEPARATOR_REGEX_EOL),
            '^' => regex.push_str(SEPARATOR_REGEX),
            '|' if i + 1 == address.len() => regex.push('$'),
            _ => push_regex_char(&mut regex, c),
        }
    }

    Some(regex)
}

/// Parse a list of modifiers and add them to a rule.
///
/// Returns the list with all unknown modifiers.
fn add_modifiers(rule: &mut Rule, modifiers: &str) -> Result<(), ParsingError> {
    for modifier in modifiers.split(',') {
        // Handle domain requirements and exceptions.
        if let Some(domains) =
            modifier.strip_prefix("domain=").or_else(|| modifier.strip_prefix("from="))
        {
            add_domains(&mut rule.if_domains, &mut rule.unless_domains, false, domains, '|')?;
            continue;
        }

        match modifier {
            "match-case" => rule.case_sensitive = true,
            "important" => rule.important = true,
            "strict1p" | "1p" | "first-party" | "~third-party" => {
                rule.load_type = LoadType::FirstParty
            },
            "strict3p" | "3p" | "third-party" => rule.load_type = LoadType::ThirdParty,
            "subdocument" => rule.load_context.set_child_frame(),
            "document" => rule.load_context.set_top_frame(),
            "xmlhttprequest" | "xhr" => rule.resource_types.insert(ResourceTypes::RAW),
            "stylesheet" | "css" => rule.resource_types.insert(ResourceTypes::STYLE_SHEET),
            "websocket" => rule.resource_types.insert(ResourceTypes::WEBSOCKET),
            "script" => rule.resource_types.insert(ResourceTypes::SCRIPT),
            "image" => rule.resource_types.insert(ResourceTypes::IMAGE),
            "media" => rule.resource_types.insert(ResourceTypes::MEDIA),
            "other" => rule.resource_types.insert(ResourceTypes::OTHER),
            "popup" => rule.resource_types.insert(ResourceTypes::POPUP),
            "font" => rule.resource_types.insert(ResourceTypes::FONT),
            "ping" => rule.resource_types.insert(ResourceTypes::PING),
            "all" => rule.resource_types.insert(ResourceTypes::all()),
            "" => (),
            modifier => return Err(ParsingError::UnknownModifier(modifier.into())),
        }
    }

    Ok(())
}

/// Parse a list of domains and add them to a whitelist or blacklist.
fn add_domains(
    whitelist: &mut Vec<String>,
    blacklist: &mut Vec<String>,
    whitelist_regex: bool,
    domains: &str,
    separator: char,
) -> Result<(), ParsingError> {
    // Split domain at separators, unless they're escaped using `\`.
    let mut last_is_escape = false;
    let mut in_regex = false;
    let mut start = 0;
    for (i, c) in domains.char_indices() {
        // Find unescaped domain separators.
        if c == separator && !last_is_escape && !in_regex {
            let last_start = mem::replace(&mut start, i + 1);
            add_domain(whitelist, blacklist, whitelist_regex, &domains[last_start..i])?;
        } else if c == '/' {
            in_regex = (in_regex && last_is_escape) || i == start;
        } else {
            last_is_escape = c == '\\';
            continue;
        }
    }

    // Handle last domain without separator.
    if start < domains.len() {
        add_domain(whitelist, blacklist, whitelist_regex, &domains[start..])?;
    }

    Ok(())
}

/// Parse an individual domain and add it to a rule.
fn add_domain(
    whitelist: &mut Vec<String>,
    blacklist: &mut Vec<String>,
    whitelist_regex: bool,
    mut domain: &str,
) -> Result<(), ParsingError> {
    // All of `url-filter`, `if-domain`, and `unless-domain` only support ASCII.
    if !domain.is_ascii() {
        return Err(ParsingError::NonAscii);
    }

    // Check if domain is negated.
    let stripped_inverse = domain.strip_prefix('~');
    let inverse = stripped_inverse.is_some();
    domain = stripped_inverse.unwrap_or(domain);

    let output_regex = !inverse && whitelist_regex;
    let domain = if domain.ends_with(".*")
        || domain == "*"
        || (domain.starts_with('/') && domain.ends_with('/'))
    {
        if output_regex {
            if domain == "*" {
                // There seems to be a special `*` domain which matches any domain.
                ".*".into()
            } else {
                // Forward regex domains directly.
                let stripped = domain.strip_prefix('/').and_then(|d| d.strip_suffix('/'));
                match normalize_regex(stripped.unwrap_or(domain)) {
                    Some(regex) => regex,
                    None => return Err(ParsingError::UnsupportedRegex),
                }
            }
        } else {
            // TLD wildcards and regexes are only supported in the `domain` modifier, WebKit
            // however does not support regex in `if/unless-domain`.
            return Err(ParsingError::RegexDomain);
        }
    } else if output_regex {
        // Escape the only valid regex character in domains (`.`).
        let domain = domain.replace('.', "\\.");

        // Automatically match all subdomains.
        format!("{SCHEMES_REGEX}{SUBDOMAIN_REGEX}{domain}{SEPARATOR_REGEX_EOL}")
    } else {
        // Automatically match all subdomains.
        format!("*{domain}")
    };

    if inverse {
        blacklist.push(domain);
    } else {
        whitelist.push(domain);
    }

    Ok(())
}

/// Add a char to a string, escaping special regex characters.
fn push_regex_char(regex: &mut String, c: char) {
    if matches!(
        c,
        '(' | ')' | '[' | ']' | '{' | '}' | '*' | '+' | '.' | '$' | '^' | '\\' | '|' | '?'
    ) {
        regex.push('\\');
    }
    regex.push(c);
}

/// Try to convert a regex into its WebKit representation.
fn normalize_regex(regex: &str) -> Option<String> {
    let mut output = String::with_capacity(regex.len());
    let mut lastchars = ['\0'; 5];
    for (i, c) in regex.chars().enumerate() {
        let last_is_escape = lastchars[0] == '\\';

        lastchars.rotate_right(1);
        lastchars[0] = c;

        // Add a generic character to the output regex.
        let mut push = |c: char| {
            if last_is_escape {
                output.push('\\')
            }
            output.push(c);
        };

        match lastchars {
            ['\\', '\\', ..] => {
                output.push_str("\\\\");
                lastchars = ['\0'; 5];
            },
            ['\\', ..] => (),

            // Normalize character classes that are not supported through their shorthand.
            ['d', '\\', ..] => output.push_str("[0-9]"),
            ['D', '\\', ..] => output.push_str("[^0-9]"),
            ['w', '\\', ..] => output.push_str("[A-Za-z0-9_]"),
            ['W', '\\', ..] => output.push_str("[^A-Za-z0-9_]"),
            ['s', '\\', ..] => output.push_str(ANY_WHITESPACE_REGEX),
            ['S', '\\', ..] => output.push_str(NOT_WHITESPACE_REGEX),

            // Ignore escaped lookahead/lookbehind.
            ['=', '?', '(', '\\', ..]
            | ['!', '?', '(', '\\', ..]
            | ['=', '<', '?', '(', '\\', ..]
            | ['=', '!', '?', '(', '\\', ..] => push(c),
            // Abort on actual lookahead/lookbehind.
            ['=', '?', '(', ..]
            | ['!', '?', '(', ..]
            | ['=', '<', '?', '(', ..]
            | ['=', '!', '?', '(', ..] => return None,

            // Abort on non-escaped disjunctions.
            ['|', '\\', ..] => push(c),
            ['|', ..] => return None,

            // Abort on non-escaped start/end of line in the middle of the regex.
            ['^', '\\', ..] | ['^', '[', ..] | ['$', '\\', ..] => push(c),
            ['^', ..] | ['$', ..] if i != 0 && i + 1 != regex.len() => return None,

            // Abort on non-escaped atom repetitions.
            ['{', '\\', ..] => push('{'),
            ['{', ..] => return None,

            [c, ..] => push(c),
        }
    }

    Some(output)
}

/// Error while parsing a uBlock filter.
enum ParsingError {
    UnknownModifier(String),
    UnsupportedRegex,
    RegexDomain,
    NonAscii,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::LoadContext;

    #[test]
    fn comments() {
        let rule = "! This is a comment";
        assert_eq!(parse_line(rule), None);
    }

    #[test]
    fn empty() {
        let rule = "   ";
        assert_eq!(parse_line(rule), None);
    }

    #[test]
    fn address_simple() {
        let rule = "example.org";
        let expected = Rule::new("example\\.org");
        assert_eq!(parse_line(rule), Some(expected));
    }

    #[test]
    fn address_regex() {
        let rule = "/banners?/";
        let expected = Rule::new("banners?");
        assert_eq!(parse_line(rule), Some(expected));
    }

    #[test]
    fn address_anchored_start() {
        let rule = "|https://example.org";
        let expected = Rule::new("^https://example\\.org");
        assert_eq!(parse_line(rule), Some(expected));
    }

    #[test]
    fn address_anchored_end() {
        let rule = "example.org|";
        let expected = Rule::new("example\\.org$");
        assert_eq!(parse_line(rule), Some(expected));
    }

    #[test]
    fn address_separator() {
        let rule = "example.org^test";
        let expected = Rule::new(format!("example\\.org{SEPARATOR_REGEX}test"));
        assert_eq!(parse_line(rule), Some(expected));
    }

    #[test]
    fn address_separator_end() {
        let rule = "example.org^";
        let expected = Rule::new(format!("example\\.org{SEPARATOR_REGEX_EOL}"));
        assert_eq!(parse_line(rule), Some(expected));
    }

    #[test]
    fn address_wildcard() {
        let rule = "|https://example.org/*/test";
        let expected = Rule::new("^https://example\\.org/.*/test");
        assert_eq!(parse_line(rule), Some(expected));
    }

    #[test]
    fn address_any_scheme_or_sub() {
        let rule = "||example.org";
        let expected = Rule::new(format!("{SCHEMES_REGEX}{SUBDOMAIN_REGEX}example\\.org"));
        assert_eq!(parse_line(rule), Some(expected));
    }

    #[test]
    fn inverse() {
        let rule = "@@|https://example.org";
        let mut expected = Rule::new("^https://example\\.org");
        expected.inverse = true;
        assert_eq!(parse_line(rule), Some(expected));
    }

    #[test]
    fn modifier_load_type_thirdparty() {
        let rule = "|https://example.org$third-party";
        let mut expected = Rule::new("^https://example\\.org");
        expected.load_type = LoadType::ThirdParty;
        assert_eq!(parse_line(rule), Some(expected));
    }

    #[test]
    fn modifier_load_type_firstparty() {
        let rule = "|https://example.org$first-party";
        let mut expected = Rule::new("^https://example\\.org");
        expected.load_type = LoadType::FirstParty;
        assert_eq!(parse_line(rule), Some(expected));
    }

    #[test]
    fn modifier_load_type_duplicate() {
        let rule = "|https://example.org$first-party,third-party";
        let mut expected = Rule::new("^https://example\\.org");
        expected.load_type = LoadType::ThirdParty;
        assert_eq!(parse_line(rule), Some(expected));
    }

    #[test]
    fn modifier_load_type_none() {
        let rule = "|https://example.org";
        let mut expected = Rule::new("^https://example\\.org");
        expected.load_type = LoadType::Both;
        assert_eq!(parse_line(rule), Some(expected));
    }

    #[test]
    fn modifier_resource_type() {
        let rule = "|https://example.org$image";
        let mut expected = Rule::new("^https://example\\.org");
        expected.resource_types.insert(ResourceTypes::IMAGE);
        assert_eq!(parse_line(rule), Some(expected));

        let rule = "|https://example.org$stylesheet";
        let mut expected = Rule::new("^https://example\\.org");
        expected.resource_types.insert(ResourceTypes::STYLE_SHEET);
        assert_eq!(parse_line(rule), Some(expected));

        let rule = "|https://example.org$script";
        let mut expected = Rule::new("^https://example\\.org");
        expected.resource_types.insert(ResourceTypes::SCRIPT);
        assert_eq!(parse_line(rule), Some(expected));

        let rule = "|https://example.org$font";
        let mut expected = Rule::new("^https://example\\.org");
        expected.resource_types.insert(ResourceTypes::FONT);
        assert_eq!(parse_line(rule), Some(expected));

        let rule = "|https://example.org$xmlhttprequest";
        let mut expected = Rule::new("^https://example\\.org");
        expected.resource_types.insert(ResourceTypes::RAW);
        assert_eq!(parse_line(rule), Some(expected));

        let rule = "|https://example.org$xhr";
        let mut expected = Rule::new("^https://example\\.org");
        expected.resource_types.insert(ResourceTypes::RAW);
        assert_eq!(parse_line(rule), Some(expected));

        let rule = "|https://example.org$media";
        let mut expected = Rule::new("^https://example\\.org");
        expected.resource_types.insert(ResourceTypes::MEDIA);
        assert_eq!(parse_line(rule), Some(expected));

        let rule = "|https://example.org$popup";
        let mut expected = Rule::new("^https://example\\.org");
        expected.resource_types.insert(ResourceTypes::POPUP);
        assert_eq!(parse_line(rule), Some(expected));

        let rule = "|https://example.org$ping";
        let mut expected = Rule::new("^https://example\\.org");
        expected.resource_types.insert(ResourceTypes::PING);
        assert_eq!(parse_line(rule), Some(expected));

        let rule = "|https://example.org$websocket";
        let mut expected = Rule::new("^https://example\\.org");
        expected.resource_types.insert(ResourceTypes::WEBSOCKET);
        assert_eq!(parse_line(rule), Some(expected));

        let rule = "|https://example.org$other";
        let mut expected = Rule::new("^https://example\\.org");
        expected.resource_types.insert(ResourceTypes::OTHER);
        assert_eq!(parse_line(rule), Some(expected));
    }

    #[test]
    fn modifier_multiple_resource_types() {
        let rule = "|https://example.org$script,popup,media";
        let mut expected = Rule::new("^https://example\\.org");
        expected.resource_types.insert(ResourceTypes::SCRIPT);
        expected.resource_types.insert(ResourceTypes::POPUP);
        expected.resource_types.insert(ResourceTypes::MEDIA);
        assert_eq!(parse_line(rule), Some(expected));
    }

    #[test]
    fn modifier_domain_basic() {
        let rule = "|https://example.org$domain=example.org";
        let mut expected = Rule::new("^https://example\\.org");
        expected.if_domains.push("*example.org".into());
        assert_eq!(parse_line(rule), Some(expected));
    }

    #[test]
    fn modifier_domain_inverse() {
        let rule = "|https://example.org$domain=~example.org";
        let mut expected = Rule::new("^https://example\\.org");
        expected.unless_domains.push("*example.org".into());
        assert_eq!(parse_line(rule), Some(expected));
    }

    #[test]
    fn modifier_domain_any_tld() {
        // NOTE: WebKit does not support any sort of regex for domains,
        // so wildcard tld domain rules should be ignored.

        let rule = "|https://example.org$domain=example.*";
        assert_eq!(parse_line(rule), None);

        let rule = "|https://example.org$domain=~example.*";
        assert_eq!(parse_line(rule), None);
    }

    #[test]
    fn modifier_domain_regex() {
        // NOTE: WebKit does not support any sort of regex for domains,
        // so wildcard tld domain rules should be ignored.

        let rule = "|https://example.org$domain=/.*.test.com/";
        assert_eq!(parse_line(rule), None);

        let rule = "|https://example.org$domain=~/.*.test.com/";
        assert_eq!(parse_line(rule), None);
    }

    #[test]
    fn modifier_domain_multiple() {
        let rule = "|https://example.org$domain=~example.org|~/test.*\\/123/|~asd.*|~github.com";
        assert_eq!(parse_line(rule), None);

        let rule = "|https://example.org$domain=example.org|~sub.example.org|github.com";
        let mut expected = Rule::new("^https://example\\.org");
        expected.if_domains.push("*example.org".into());
        expected.if_domains.push("*github.com".into());
        expected.unless_domains.push("*sub.example.org".into());
        assert_eq!(parse_line(rule), Some(expected));
    }

    #[test]
    fn modifier_domain_mixed_inverse() {
        // NOTE: While `if_domain` and `unless_domain` are exclusive in WebKit's content
        // blocker API, we can still simulate it by using `ignore-previous-rules`.

        let rule = "|https://example.org$domain=example.org|~other.example.org";
        let mut expected = Rule::new("^https://example\\.org");
        expected.if_domains.push("*example.org".into());
        expected.unless_domains.push("*other.example.org".into());
        assert_eq!(parse_line(rule), Some(expected));
    }

    #[test]
    fn modifier_load_context() {
        let rule = "|https://example.org$document";
        let mut expected = Rule::new("^https://example\\.org");
        expected.load_context = LoadContext::TopFrame;
        assert_eq!(parse_line(rule), Some(expected));

        let rule = "|https://example.org$subdocument";
        let mut expected = Rule::new("^https://example\\.org");
        expected.load_context = LoadContext::ChildFrame;
        assert_eq!(parse_line(rule), Some(expected));

        let rule = "|https://example.org";
        let mut expected = Rule::new("^https://example\\.org");
        expected.load_context = LoadContext::Both;
        assert_eq!(parse_line(rule), Some(expected));

        let rule = "|https://example.org$document,subdocument";
        let mut expected = Rule::new("^https://example\\.org");
        expected.load_context = LoadContext::ExplicitBoth;
        assert_eq!(parse_line(rule), Some(expected));
    }

    #[test]
    fn modifier_multiple() {
        let rule = "|https://example.org$domain=example.org,font,subdocument,third-party,important";
        let mut expected = Rule::new("^https://example\\.org");
        expected.if_domains.push("*example.org".into());
        expected.resource_types.insert(ResourceTypes::FONT);
        expected.load_context = LoadContext::ChildFrame;
        expected.load_type = LoadType::ThirdParty;
        expected.important = true;
        assert_eq!(parse_line(rule), Some(expected));
    }

    #[test]
    fn modifier_important() {
        let rule = "|https://example.org$important";
        let mut expected = Rule::new("^https://example\\.org");
        expected.important = true;
        assert_eq!(parse_line(rule), Some(expected));
    }

    #[test]
    fn modifier_all() {
        let rule = "|https://example.org$font,script,all,popup";
        let mut expected = Rule::new("^https://example\\.org");
        expected.resource_types = ResourceTypes::all();
        assert_eq!(parse_line(rule), Some(expected));
    }

    #[test]
    fn modifier_replace() {
        let rule = "|https://example.org$font,replace=/test\\,/test/gm,script";
        assert_eq!(parse_line(rule), None);
    }

    #[test]
    fn cosmetic() {
        let rule = "###bad";
        let mut expected = Rule::new(".*");
        expected.selector = Some("#bad".into());
        assert_eq!(parse_line(rule), Some(expected));
    }

    #[test]
    fn cosmetic_single_domain() {
        let rule = "example.org##.bad";
        let mut expected = Rule::new(format!(
            "{SCHEMES_REGEX}{SUBDOMAIN_REGEX}example\\.org{SEPARATOR_REGEX_EOL}"
        ));
        expected.selector = Some(".bad".into());
        assert_eq!(parse_line(rule), Some(expected));
    }

    #[test]
    fn cosmetic_inverse_domain() {
        let rule = "~example.org##.bad";
        let mut expected = Rule::new(".*");
        expected.selector = Some(".bad".into());
        expected.unless_domains.push("*example.org".into());
        assert_eq!(parse_line(rule), Some(expected));
    }

    #[test]
    fn cosmetic_multi_domain() {
        let rule = "example.org,github.com##.bad";
        let mut expected =
            Rule::new(format!("{SCHEMES_REGEX}{SUBDOMAIN_REGEX}github\\.com{SEPARATOR_REGEX_EOL}"));
        expected
            .url_regexes
            .push(format!("{SCHEMES_REGEX}{SUBDOMAIN_REGEX}example\\.org{SEPARATOR_REGEX_EOL}"));
        expected.selector = Some(".bad".into());
        assert_eq!(parse_line(rule), Some(expected));
    }

    #[test]
    fn cosmetic_mixed_inverse_domain() {
        let rule = "example.org,~not.example.org,github.com##.bad";
        let mut expected =
            Rule::new(format!("{SCHEMES_REGEX}{SUBDOMAIN_REGEX}github\\.com{SEPARATOR_REGEX_EOL}"));
        expected.selector = Some(".bad".into());
        expected
            .url_regexes
            .push(format!("{SCHEMES_REGEX}{SUBDOMAIN_REGEX}example\\.org{SEPARATOR_REGEX_EOL}"));
        expected.unless_domains.push("*not.example.org".into());
        assert_eq!(parse_line(rule), Some(expected));
    }

    #[test]
    fn regex_domain() {
        let rule = "/whatever[0-9a-z]+\\/\\.[a-z]/##a[href=\"/test/\"]";
        let mut expected = Rule::new("whatever[0-9a-z]+\\/\\.[a-z]");
        expected.selector = Some("a[href=\"/test/\"]".into());
        assert_eq!(parse_line(rule), Some(expected));
    }

    #[test]
    fn js_scriptlet() {
        let rule = "example.org##+js()";
        assert_eq!(parse_line(rule), None);
    }

    #[test]
    fn wildcard_css() {
        let rule = "*##.bad";
        let mut expected = Rule::new(".*");
        expected.selector = Some(".bad".into());
        assert_eq!(parse_line(rule), Some(expected));
    }

    #[test]
    fn empty_domain() {
        let rule = "$domain=zdnet.fr";
        let mut expected = Rule::new(".*");
        expected.if_domains.push("*zdnet.fr".into());
        assert_eq!(parse_line(rule), Some(expected));
    }

    #[test]
    fn normalize_regex() {
        let rule = "/\\d\\D\\w\\W\\s\\S/";
        let expected = Rule::new(format!(
            "[0-9][^0-9][A-Za-z0-9_][^A-Za-z0-9_]{ANY_WHITESPACE_REGEX}{NOT_WHITESPACE_REGEX}"
        ));
        assert_eq!(parse_line(rule), Some(expected));
    }

    #[test]
    fn invalid_regex() {
        // (Negative) lookahead/lookbehind.
        assert_eq!(parse_line("/(?=pattern)/"), None);
        assert_eq!(parse_line("/(?!pattern)/"), None);
        assert_eq!(parse_line("/(?<=pattern)/"), None);
        assert_eq!(parse_line("/(?!=pattern)/"), None);

        // Disjunctions.
        assert_eq!(parse_line("/a|b/"), None);

        // End/Start of line in the middle of expression.
        assert_eq!(parse_line("/a^b/"), None);
        assert_eq!(parse_line("/a$b/"), None);

        // Arbitrary atom repetitions.
        assert_eq!(parse_line("/a{6}/"), None);
    }

    #[test]
    fn escaped_invalid_regex() {
        // (Negative) lookahead/lookbehind.
        let expected = Rule::new("\\(?=pattern)");
        assert_eq!(parse_line("/\\(?=pattern)/"), Some(expected));
        let expected = Rule::new("\\(?!pattern)");
        assert_eq!(parse_line("/\\(?!pattern)/"), Some(expected));
        let expected = Rule::new("\\(?<=pattern)");
        assert_eq!(parse_line("/\\(?<=pattern)/"), Some(expected));
        let expected = Rule::new("\\(?!=pattern)");
        assert_eq!(parse_line("/\\(?!=pattern)/"), Some(expected));

        // Disjunctions.
        let expected = Rule::new("a\\|b");
        assert_eq!(parse_line("/a\\|b/"), Some(expected));

        // End/Start of line in the middle of expression.
        let expected = Rule::new("a\\^b");
        assert_eq!(parse_line("/a\\^b/"), Some(expected));
        let expected = Rule::new("a\\$b");
        assert_eq!(parse_line("/a\\$b/"), Some(expected));

        // Arbitrary atom repetitions.
        let expected = Rule::new("a\\{6\\}");
        assert_eq!(parse_line("/a\\{6\\}/"), Some(expected));
    }

    #[test]
    fn non_unicode_domain() {
        let rule = "tööt.smöl";
        assert_eq!(parse_line(rule), None);

        let rule = "$domain=růst";
        assert_eq!(parse_line(rule), None);
    }

    #[test]
    fn dollar_in_regex() {
        let rule = "/bad.js$/$script";
        let mut expected = Rule::new("bad.js$");
        expected.resource_types = ResourceTypes::SCRIPT;
        assert_eq!(parse_line(rule), Some(expected));
    }

    #[test]
    fn filter() {
        let filter = "|https://example.org\nexample.org##.bad";
        let block_rule = Rule::new("^https://example\\.org");
        let mut cosmetic_rule = Rule::new(format!(
            "{SCHEMES_REGEX}{SUBDOMAIN_REGEX}example\\.org{SEPARATOR_REGEX_EOL}"
        ));
        cosmetic_rule.selector = Some(".bad".into());
        assert_eq!(parse(filter), vec![block_rule, cosmetic_rule]);
    }
}
