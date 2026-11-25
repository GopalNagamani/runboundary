//! Heuristic detection and display redaction for credential-like source text.
//! This protects review output only; it is not a secret store or DLP boundary.

pub fn redact_text(input: &str) -> (String, bool) {
    let mut output = String::with_capacity(input.len());
    let mut detected = false;
    let mut in_private_key = false;

    for segment in input.split_inclusive('\n') {
        let (line, newline) = segment
            .strip_suffix('\n')
            .map_or((segment, ""), |line| (line, "\n"));
        if in_private_key {
            detected = true;
            output.push_str("[REDACTED PRIVATE KEY MATERIAL]");
            output.push_str(newline);
            if line.contains("-----END ") && line.contains("PRIVATE KEY-----") {
                in_private_key = false;
            }
            continue;
        }
        if line.contains("-----BEGIN ") && line.contains("PRIVATE KEY-----") {
            detected = true;
            output.push_str("[REDACTED PRIVATE KEY]");
            output.push_str(newline);
            in_private_key = !line.contains("-----END ");
            continue;
        }
        if let Some((start, end)) = sensitive_assignment_value(line) {
            let value = line[start..end].trim();
            if !is_placeholder(value) {
                detected = true;
                output.push_str(&line[..start]);
                output.push_str("[REDACTED]");
                output.push_str(&line[end..]);
                output.push_str(newline);
                continue;
            }
        }
        let (redacted, found_token) = redact_known_tokens(line);
        detected |= found_token;
        output.push_str(&redacted);
        output.push_str(newline);
    }
    (output, detected || in_private_key)
}

fn sensitive_assignment_value(line: &str) -> Option<(usize, usize)> {
    for delimiter in line.char_indices().filter(|(_, c)| *c == '=' || *c == ':') {
        let key_start = line[..delimiter.0]
            .rfind([',', '{', ';'])
            .map_or(0, |index| index + 1);
        let key = line[key_start..delimiter.0]
            .trim()
            .trim_matches(['"', '\'', '`'])
            .chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .flat_map(char::to_lowercase)
            .collect::<String>();
        if [
            "password",
            "passwd",
            "secret",
            "token",
            "apikey",
            "accesskey",
            "privatekey",
            "credential",
            "authorization",
            "clientsecret",
        ]
        .iter()
        .any(|needle| key.contains(needle))
        {
            let value_start = delimiter.0 + delimiter.1.len_utf8();
            let mut value_end = line.len();
            while value_end > value_start
                && matches!(line.as_bytes()[value_end - 1], b' ' | b'\t' | b',' | b';')
            {
                value_end -= 1;
            }
            return Some((value_start, value_end));
        }
    }
    None
}

fn redact_known_tokens(line: &str) -> (String, bool) {
    let mut remaining = line;
    let mut output = String::with_capacity(line.len());
    let mut found = false;
    while let Some((start, end)) = known_token_span(remaining) {
        output.push_str(&remaining[..start]);
        output.push_str("[REDACTED TOKEN]");
        remaining = &remaining[end..];
        found = true;
    }
    output.push_str(remaining);
    (output, found)
}

fn known_token_span(line: &str) -> Option<(usize, usize)> {
    let lower = line.to_ascii_lowercase();
    let markers = [
        "github_pat_",
        "ghp_",
        "glpat-",
        "xoxb-",
        "xoxp-",
        "sk-",
        "akia",
        "aiza",
        "eyj",
        "bearer ",
    ];
    let (start, marker) = markers
        .iter()
        .filter_map(|marker| lower.find(marker).map(|index| (index, *marker)))
        .min_by_key(|(index, _)| *index)?;
    let mut end = start + marker.len();
    let bytes = line.as_bytes();
    while end < bytes.len()
        && !matches!(
            bytes[end],
            b' ' | b'\t' | b'\r' | b'\n' | b'"' | b'\'' | b'`' | b',' | b';' | b')' | b']' | b'}'
        )
    {
        end += 1;
    }
    Some((start, end))
}

fn is_placeholder(value: &str) -> bool {
    let value = value
        .trim()
        .trim_matches(['"', '\'', '`'])
        .trim_end_matches([',', ';'])
        .to_ascii_lowercase();
    value.is_empty()
        || value.starts_with("your_")
        || value.starts_with("your-")
        || value.starts_with("example")
        || value.starts_with("placeholder")
        || value.starts_with("replace_me")
        || value.starts_with("changeme")
        || value.starts_with("change_me")
        || value.starts_with("dummy")
        || value.starts_with("fake_")
        || value.starts_with("test_")
        || (value.starts_with('<') && value.ends_with('>'))
}

#[cfg(test)]
mod tests {
    use super::redact_text;

    #[test]
    fn redacts_secret_assignments_tokens_and_private_key_blocks() {
        let input = concat!(
            "OPENAI_API_KEY=sk-live-secret-value\n",
            "{\"client_secret\": \"oauth-secret\",}\n",
            "Authorization: Bearer abc.def.ghi\n",
            "-----BEGIN RSA PRIVATE KEY-----\n",
            "private-material-should-not-appear\n",
            "-----END RSA PRIVATE KEY-----\n",
        );
        let (output, detected) = redact_text(input);
        assert!(detected);
        for secret in [
            "sk-live-secret-value",
            "oauth-secret",
            "abc.def.ghi",
            "private-material-should-not-appear",
        ] {
            assert!(!output.contains(secret), "leaked {secret:?}: {output}");
        }
        assert!(output.contains("OPENAI_API_KEY=[REDACTED]"));
        assert!(output.contains("[REDACTED PRIVATE KEY MATERIAL]"));
    }

    #[test]
    fn keeps_example_values_and_ordinary_text_visible() {
        let input = "API_KEY=your_api_key_here\nlet token = example-token;\nsource code\n";
        let (output, detected) = redact_text(input);
        assert!(!detected);
        assert_eq!(output, input);
    }

    #[test]
    fn redacts_multiple_credentials_in_one_json_line() {
        let input = r#"{"service":"ordinary","apiKey":"sk-one-secret","password":"second-secret"}"#;
        let (output, detected) = redact_text(input);
        assert!(detected);
        assert!(!output.contains("sk-one-secret"));
        assert!(!output.contains("second-secret"));
    }

    #[test]
    fn flags_an_unterminated_private_key_block() {
        let (output, detected) = redact_text("-----BEGIN OPENSSH PRIVATE KEY-----\npartial\n");
        assert!(detected);
        assert!(!output.contains("partial"));
    }
}
