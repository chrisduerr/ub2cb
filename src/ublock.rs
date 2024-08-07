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

/// Parse a uBlock filter.
pub fn parse(filter: &str) -> Vec<Rule> {
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
    const UNSUPPORTED_SYNTAX: &[&str] = &["#@#", "#$#", "#?#", "#@?#", "#$?#", "#$@?#", "#%#"];
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
    for domain in domains.split(',').filter(|domain| !domain.is_empty()) {
        let _ = add_domain(&mut rule.if_domains, &mut rule.unless_domains, domain);
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
    let (address, modifiers) = stripped_line.split_once('$').unwrap_or((stripped_line, ""));

    // Convert domain matcher to regex.
    let url_regex = normalize_address(address);
    let mut rule = Rule::new(url_regex);
    rule.inverse = inverse;

    // Add all modifiers to the rule.
    match add_modifiers(&mut rule, modifiers) {
        Ok(()) => Some(rule),
        Err(ParsingError::UnknownModifier(modifier)) => {
            debug!("Ignoring rule due to unknown modifier {modifier:?}:");
            debug!("    {line}");
            None
        },
        Err(ParsingError::RegexDomain) => {
            debug!("Ignoring rule due to regex in domain modifier:");
            debug!("    {line}");
            None
        },
    }
}

/// Convert filter address into its regex representation.
fn normalize_address(mut address: &str) -> String {
    // Handle addresses that already use regex.
    if let Some(start) = address.strip_prefix('/') {
        if let Some(regex) = start.strip_suffix('/') {
            return regex.into();
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

    regex
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
            add_domain_modifiers(&mut rule.if_domains, &mut rule.unless_domains, domains)?;
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

/// Parse a list of domain modifiers and add them to a whitelist or blacklist.
fn add_domain_modifiers(
    whitelist: &mut Vec<String>,
    blacklist: &mut Vec<String>,
    domains: &str,
) -> Result<(), ParsingError> {
    // Split domain at `|` separators, ignoring the escaped `\|`.
    let mut last_is_escape = false;
    let mut start = 0;
    for (i, c) in domains.char_indices() {
        // Find unescaped domain separators.
        if c == '|' && !last_is_escape {
            let last_start = mem::replace(&mut start, i + 1);
            add_domain(whitelist, blacklist, &domains[last_start..i])?;
        } else {
            last_is_escape = c == '\\';
            continue;
        }
    }

    // Handle last domain without separator.
    add_domain(whitelist, blacklist, &domains[start..])
}

/// Parse an individual domain and add it to a rule.
fn add_domain(
    whitelist: &mut Vec<String>,
    blacklist: &mut Vec<String>,
    mut domain: &str,
) -> Result<(), ParsingError> {
    // Check if domain is negated.
    let stripped_inverse = domain.strip_prefix('~');
    let inverse = stripped_inverse.is_some();
    domain = stripped_inverse.unwrap_or(domain);

    // TLD wildcards and regexes are only supported in the `domain` modifier, WebKit
    // however does not support regex in `if/unless-domain`.
    if domain.ends_with(".*") || (domain.starts_with('/') && domain.ends_with('/')) {
        return Err(ParsingError::RegexDomain);
    }

    // uBlock domains automatically accept all subdomains.
    let domain = format!("*{domain}");

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

/// Error while parsing a uBlock filter.
enum ParsingError {
    UnknownModifier(String),
    RegexDomain,
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
        let rule = "/banner\\d+/";
        let expected = Rule::new("banner\\d+");
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
        let mut expected = Rule::new(".*");
        expected.selector = Some(".bad".into());
        expected.if_domains.push("*example.org".into());
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
        let mut expected = Rule::new(".*");
        expected.if_domains.push("*example.org".into());
        expected.if_domains.push("*github.com".into());
        expected.selector = Some(".bad".into());
        assert_eq!(parse_line(rule), Some(expected));
    }

    #[test]
    fn cosmetic_mixed_inverse_domain() {
        let rule = "example.org,~not.example.org,github.com##.bad";
        let mut expected = Rule::new(".*");
        expected.selector = Some(".bad".into());
        expected.if_domains.push("*example.org".into());
        expected.if_domains.push("*github.com".into());
        expected.unless_domains.push("*not.example.org".into());
        assert_eq!(parse_line(rule), Some(expected));
    }

    #[test]
    fn filter() {
        let filter = "|https://example.org\nexample.org##.bad";
        let block_rule = Rule::new("^https://example\\.org");
        let mut cosmetic_rule = Rule::new(".*");
        cosmetic_rule.selector = Some(".bad".into());
        cosmetic_rule.if_domains.push("*example.org".into());
        assert_eq!(parse(filter), vec![block_rule, cosmetic_rule]);
    }
}
