//! WebKit content blocker format handling.

use std::io::{Error, Write};
use std::mem;

use crate::{LoadContext, LoadType, Rule};

/// Write the content blocker JSON format of a list of rules to a destination.
pub fn write_json<W>(dst: &mut W, mut rules: Vec<Rule>) -> Result<(), Error>
where
    W: Write,
{
    // Minimize the size of the filter.
    rules.sort_unstable();
    rules.dedup();

    write!(dst, "[")?;

    for (i, rule) in rules.into_iter().enumerate() {
        if i != 0 {
            write!(dst, ", ")?;
        }

        write_rule(dst, rule)?;
    }

    writeln!(dst, "]")?;

    Ok(())
}

/// Write one rule to the destination.
fn write_rule<W>(dst: &mut W, rule: Rule) -> Result<(), Error>
where
    W: Write,
{
    // Ignore inverse rules that have if- and unless-domain set,
    // since they're unreasonable to get working with WebKit.
    if !rule.if_domains.is_empty() && !rule.unless_domains.is_empty() && rule.inverse {
        return Ok(());
    }

    write!(dst, "{{\n\t\"trigger\": {{\n\t\t\"url-filter\": ")?;
    write_json_string(dst, &rule.url_regex)?;

    if rule.case_sensitive {
        write!(dst, ",\n\t\t\"url-filter-is-case-sensitive\": true")?;
    }

    // Wrapper for writing if/unless-domain fields.
    let mut write_domains = |name: &str, domains: &[String]| -> Result<(), Error> {
        write!(dst, ",\n\t\t\"{name}\": [")?;
        for (i, domain) in domains.iter().enumerate() {
            if i == 0 {
                write!(dst, "\n\t\t\t\"{}\"", domain)?;
            } else {
                write!(dst, ",\n\t\t\t\"{}\"", domain)?;
            }
        }
        write!(dst, "\n\t\t]")?;
        Ok(())
    };

    if !rule.if_domains.is_empty() {
        write_domains("if-domain", &rule.if_domains)?;
    } else if !rule.unless_domains.is_empty() {
        write_domains("unless-domain", &rule.unless_domains)?;
    }

    if !rule.resource_types.is_empty() {
        write!(dst, ",\n\t\t\"resource-type\": {}", rule.resource_types)?;
    }

    if rule.load_type != LoadType::Both {
        write!(dst, ",\n\t\t\"load-type\": [\"{}\"]", rule.load_type)?;
    }

    if rule.load_context != LoadContext::Both {
        write!(dst, ",\n\t\t\"load-context\": {}", rule.load_context)?;
    }

    write!(dst, "\n\t}},\n\t\"action\": {{\n\t\t\"type\": ")?;

    match &rule.selector {
        _ if rule.inverse => write!(dst, "\"ignore-previous-rules\"\n\t}}\n}}")?,
        Some(selector) => {
            write!(dst, "\"css-display-none\",\n\t\t\"selector\": ")?;
            write_json_string(dst, selector)?;
            write!(dst, "\n\t}}\n}}")?;
        },
        None => write!(dst, "\"block\"\n\t}}\n}}")?,
    }

    // If both if- and unless-domains are provided, we add the unless-domains as an
    // inverse rule.
    if !rule.if_domains.is_empty() && !rule.unless_domains.is_empty() {
        writeln!(dst, ",")?;

        let mut rule = rule.clone();
        rule.if_domains = mem::take(&mut rule.unless_domains);
        rule.inverse = true;

        write_rule(dst, rule)?;
    }

    Ok(())
}

// Write JSON string with special characters escaped.
fn write_json_string<W>(dst: &mut W, s: &str) -> Result<(), Error>
where
    W: Write,
{
    write!(dst, "\"")?;
    for c in s.chars() {
        match c {
            '\\' | '"' => write!(dst, "\\{c}")?,
            _ => write!(dst, "{c}")?,
        }
    }
    write!(dst, "\"")
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use serde::Deserialize;

    use super::*;
    use crate::ResourceTypes;

    #[derive(Deserialize, PartialEq, Eq, Debug)]
    struct CBRule {
        trigger: Trigger,
        action: Action,
    }

    #[derive(Deserialize, PartialEq, Eq, Debug)]
    #[serde(rename_all = "kebab-case")]
    struct Trigger {
        url_filter: String,
        url_filter_is_case_sensitive: Option<bool>,
        if_domain: Option<Vec<String>>,
        unless_domain: Option<Vec<String>>,
        resource_type: Option<Vec<String>>,
        load_type: Option<Vec<String>>,
        if_top_url: Option<Vec<String>>,
        unless_top_url: Option<Vec<String>>,
        load_context: Option<Vec<String>>,
    }

    #[derive(Deserialize, PartialEq, Eq, Debug)]
    #[serde(rename_all = "kebab-case")]
    struct Action {
        #[serde(rename = "type")]
        action_type: String,
        selector: Option<String>,
    }

    #[test]
    fn empty() {
        let rules = Vec::new();

        let mut buffer = Cursor::new(Vec::new());
        write_json(&mut buffer, rules).unwrap();
        let output = String::from_utf8(buffer.into_inner()).unwrap();

        let rules: Vec<CBRule> = serde_json::from_str(&output).unwrap();
        assert!(rules.is_empty());
    }

    #[test]
    fn basic() {
        let rules = vec![Rule::new(".*")];

        let mut buffer = Cursor::new(Vec::new());
        write_json(&mut buffer, rules).unwrap();
        let output = String::from_utf8(buffer.into_inner()).unwrap();

        let rules: Vec<CBRule> = serde_json::from_str(&output).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].trigger.url_filter, ".*".to_string());
        assert_eq!(rules[0].action.action_type, "block".to_string());
    }

    #[test]
    fn complex() {
        let mut rule = Rule::new("example.org$");
        rule.resource_types = ResourceTypes::IMAGE;
        rule.load_context = LoadContext::ChildFrame;
        rule.load_type = LoadType::ThirdParty;
        rule.if_domains.push("*example.org".into());
        rule.case_sensitive = true;
        let rules = vec![rule];

        let mut buffer = Cursor::new(Vec::new());
        write_json(&mut buffer, rules).unwrap();
        let output = String::from_utf8(buffer.into_inner()).unwrap();

        let rules: Vec<CBRule> = serde_json::from_str(&output).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].trigger.url_filter, "example.org$".to_string());
        assert_eq!(rules[0].trigger.resource_type, Some(vec!["image".into()]));
        assert_eq!(rules[0].trigger.load_context, Some(vec!["child-frame".into()]));
        assert_eq!(rules[0].trigger.load_type, Some(vec!["third-party".into()]));
        assert_eq!(rules[0].trigger.if_domain, Some(vec!["*example.org".into()]));
        assert_eq!(rules[0].trigger.url_filter_is_case_sensitive, Some(true));
        assert_eq!(rules[0].action.action_type, "block".to_string());
    }

    #[test]
    fn cosmetic() {
        let mut rule = Rule::new(".*");
        rule.selector = Some(".bad".into());
        let rules = vec![rule];

        let mut buffer = Cursor::new(Vec::new());
        write_json(&mut buffer, rules).unwrap();
        let output = String::from_utf8(buffer.into_inner()).unwrap();

        let rules: Vec<CBRule> = serde_json::from_str(&output).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].trigger.url_filter, ".*".to_string());
        assert_eq!(rules[0].action.action_type, "css-display-none".to_string());
    }

    #[test]
    fn conflicting_domains() {
        let mut rule = Rule::new(".*");
        rule.if_domains.push("*example.org".into());
        rule.unless_domains.push("*sub.example.org".into());
        let rules = vec![rule];

        let mut buffer = Cursor::new(Vec::new());
        write_json(&mut buffer, rules).unwrap();
        let output = String::from_utf8(buffer.into_inner()).unwrap();

        let rules: Vec<CBRule> = serde_json::from_str(&output).unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].trigger.url_filter, ".*".to_string());
        assert_eq!(rules[0].trigger.if_domain, Some(vec!["*example.org".into()]));
        assert_eq!(rules[0].action.action_type, "block".to_string());
        assert_eq!(rules[1].trigger.url_filter, ".*".to_string());
        assert_eq!(rules[1].trigger.if_domain, Some(vec!["*sub.example.org".into()]));
        assert_eq!(rules[1].action.action_type, "ignore-previous-rules".to_string());
    }

    #[test]
    fn escape_json() {
        let rule = Rule::new("\\n");
        let rules = vec![rule];

        let mut buffer = Cursor::new(Vec::new());
        write_json(&mut buffer, rules).unwrap();
        let output = String::from_utf8(buffer.into_inner()).unwrap();

        let rules: Vec<CBRule> = serde_json::from_str(&output).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].trigger.url_filter, "\\n".to_string());
        assert_eq!(rules[0].action.action_type, "block".to_string());
    }

    #[test]
    fn resource_type() {
        let mut rule = Rule::new(".*");
        rule.resource_types = ResourceTypes::SCRIPT | ResourceTypes::RAW;
        let rules = vec![rule];

        let mut buffer = Cursor::new(Vec::new());
        write_json(&mut buffer, rules).unwrap();
        let output = String::from_utf8(buffer.into_inner()).unwrap();

        let rules: Vec<CBRule> = serde_json::from_str(&output).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].trigger.url_filter, ".*".to_string());
        assert_eq!(rules[0].trigger.resource_type, Some(vec!["script".into(), "raw".into()]));
        assert_eq!(rules[0].action.action_type, "block".to_string());
    }

    #[test]
    fn important_last() {
        let normal_rule = Rule::new("normal");
        let mut important_rule = Rule::new("important");
        important_rule.important = true;
        let rules = vec![important_rule, normal_rule];

        let mut buffer = Cursor::new(Vec::new());
        write_json(&mut buffer, rules).unwrap();
        let output = String::from_utf8(buffer.into_inner()).unwrap();

        let rules: Vec<CBRule> = serde_json::from_str(&output).unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].trigger.url_filter, "normal".to_string());
        assert_eq!(rules[1].trigger.url_filter, "important".to_string());
    }

    #[test]
    fn cosmetic_first() {
        let normal_rule = Rule::new("normal");
        let mut cosmetic_rule = Rule::new("cosmetic");
        cosmetic_rule.selector = Some(".bad".into());
        let rules = vec![normal_rule, cosmetic_rule];

        let mut buffer = Cursor::new(Vec::new());
        write_json(&mut buffer, rules).unwrap();
        let output = String::from_utf8(buffer.into_inner()).unwrap();

        let rules: Vec<CBRule> = serde_json::from_str(&output).unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].trigger.url_filter, "cosmetic".to_string());
        assert_eq!(rules[1].trigger.url_filter, "normal".to_string());
    }

    #[test]
    fn exceptions_last() {
        let normal_rule = Rule::new("normal");
        let mut exception_rule = Rule::new("exception");
        exception_rule.inverse = true;
        let rules = vec![exception_rule, normal_rule];

        let mut buffer = Cursor::new(Vec::new());
        write_json(&mut buffer, rules).unwrap();
        let output = String::from_utf8(buffer.into_inner()).unwrap();

        let rules: Vec<CBRule> = serde_json::from_str(&output).unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].trigger.url_filter, "normal".to_string());
        assert_eq!(rules[1].trigger.url_filter, "exception".to_string());
    }
}
