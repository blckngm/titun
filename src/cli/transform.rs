use std::fmt::Write;

fn need_transform(input: &str) -> bool {
    for l in input.lines() {
        let l = l.trim();
        if l == "[Peer]" {
            // Not toml.
            return true;
        }
        if l.starts_with('#') || l.starts_with('[') {
            continue;
        }
        if l.contains('"') || l.contains('[') {
            // Is toml.
            return false;
        }
    }
    // No `"` or `[`, not toml.
    true
}

fn transform_value(value: &str) -> String {
    let value = value.trim();
    if value.contains(',') {
        // Array of strings.
        let a: toml::value::Array = value
            .split(',')
            .map(|v| toml::Value::String(v.trim().into()))
            .collect();
        return toml::to_string(&a).unwrap();
    }

    for c in value.chars() {
        if !c.is_digit(10) {
            // String.
            return toml::to_string(&toml::Value::String(value.into())).unwrap();
        }
    }

    // Number.
    value.into()
}

/// Convert wg config files to toml format.
pub fn maybe_transform(input: String) -> String {
    if !need_transform(&input) {
        return input;
    }

    let lines = input.lines();
    let mut output = String::new();
    for l in lines {
        let l_trim = l.trim();
        if l_trim.is_empty() || l_trim.starts_with("[Interface]") || l_trim.starts_with('#') {
            output.push_str(l);
            output.push_str("\n");
        } else if l_trim.starts_with("[Peer]") {
            output.push_str("[[Peer]]\n");
        } else {
            let mut kv = l.splitn(2, '=');
            let k = kv.next().unwrap();
            if let Some(v) = kv.next() {
                writeln!(output, "{} = {}", k.trim(), transform_value(v)).unwrap();
            } else {
                output.push_str(l);
                output.push_str("\n");
            }
        }
    }
    output
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_transform() {
        assert_eq!(
            super::maybe_transform(
                r##"
[General]
log = info

  # Some comment
[Interface]
ListenPort = 7777
PrivateKey = INZz5evbJBekyvtjRLHdnigrKeJ7HxOXR7lLm6yqMW4=

# Some more comment.
[Peer]
PublicKey = NGnPOc0pxlnOjQz5DDSBJsSM6rf2T1MjBduxmvKBLiU=
# Some more comment.
AllowedIPs = 192.168.77.2/32, 192.168.77.4/32
Endpoint = 192.168.3.2:7777
"##
                .into()
            ),
            r##"
[General]
log = "info"

  # Some comment
[Interface]
ListenPort = 7777
PrivateKey = "INZz5evbJBekyvtjRLHdnigrKeJ7HxOXR7lLm6yqMW4="

# Some more comment.
[[Peer]]
PublicKey = "NGnPOc0pxlnOjQz5DDSBJsSM6rf2T1MjBduxmvKBLiU="
# Some more comment.
AllowedIPs = ["192.168.77.2/32", "192.168.77.4/32"]
Endpoint = "192.168.3.2:7777"
"##
        );
    }
}
