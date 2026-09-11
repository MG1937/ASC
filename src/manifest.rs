use anyhow::{Context, Result, bail};
use axmldecoder::{Node, XmlDocument};
use std::fmt::Write;

pub fn decode(data: &[u8]) -> Result<String> {
    if let Ok(text) = std::str::from_utf8(data)
        && text.trim_start().starts_with('<')
    {
        return Ok(text.to_owned());
    }
    let document = axmldecoder::parse(data).context("decode binary Android XML")?;
    render(&document)
}

fn render(document: &XmlDocument) -> Result<String> {
    let root = document
        .get_root()
        .as_ref()
        .context("AndroidManifest.xml has no root element")?;
    let mut output = String::from("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n");
    render_node(root, 0, &mut output)?;
    Ok(output)
}

fn render_node(node: &Node, depth: usize, output: &mut String) -> Result<()> {
    match node {
        Node::Cdata(cdata) => {
            indent(depth, output);
            output.push_str("<![CDATA[");
            output.push_str(&cdata.get_data().replace("]]>", "]] ]]><![CDATA[>"));
            output.push_str("]]>");
        }
        Node::Element(element) => {
            let tag = element.get_tag();
            if tag.is_empty() {
                bail!("binary XML contains an empty element name");
            }
            indent(depth, output);
            write!(output, "<{tag}")?;
            for (name, value) in element.get_attributes() {
                write!(output, " {name}=\"")?;
                escape_xml(value, true, output);
                output.push('"');
            }
            if element.get_children().is_empty() {
                output.push_str(" />");
                return Ok(());
            }
            output.push('>');
            for child in element.get_children() {
                output.push('\n');
                render_node(child, depth + 1, output)?;
            }
            output.push('\n');
            indent(depth, output);
            write!(output, "</{tag}>")?;
        }
    }
    Ok(())
}

fn indent(depth: usize, output: &mut String) {
    for _ in 0..depth {
        output.push_str("    ");
    }
}

fn escape_xml(value: &str, attribute: bool, output: &mut String) {
    for ch in value.chars() {
        match ch {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '>' => output.push_str("&gt;"),
            '"' if attribute => output.push_str("&quot;"),
            '\'' if attribute => output.push_str("&apos;"),
            _ => output.push(ch),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_plain_xml_manifests() {
        let input = b"<?xml version=\"1.0\"?><manifest package=\"example\"/>";
        assert_eq!(decode(input).unwrap().as_bytes(), input);
    }

    #[test]
    fn escapes_xml_attribute_values() {
        let mut output = String::new();
        escape_xml("a&<>'\"", true, &mut output);
        assert_eq!(output, "a&amp;&lt;&gt;&apos;&quot;");
    }
}
