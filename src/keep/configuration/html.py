"""HTML panel sanitizing (REV-57).

The allowlist is the user's accepted REV-57 default. The frontend applies the same
allowlist before display, so keep the two in step.
"""

from html.parser import HTMLParser
import re

import nh3

MAX_HTML = 16_000
TAGS = {
    "p", "br", "strong", "em", "b", "i", "u", "s", "code", "pre", "blockquote",
    "ul", "ol", "li", "h3", "h4", "h5", "h6", "table", "thead", "tbody", "tr", "th",
    "td", "a", "span", "div", "hr",
}
# Removed together with their content; every other disallowed tag keeps its text.
DROPPED = {"script", "style", "iframe", "object", "embed", "template", "noscript", "textarea", "select"}
ATTRIBUTES = {
    "*": {"style"},
    "a": {"href", "title"},
    "th": {"colspan", "rowspan", "scope"},
    "td": {"colspan", "rowspan"},
}
SCHEMES = {"http", "https", "mailto"}
STYLES = {
    "color", "background-color", "font-size", "font-weight", "font-style", "text-align",
    "text-decoration", "border-radius",
    "padding", "padding-top", "padding-right", "padding-bottom", "padding-left",
    "margin", "margin-top", "margin-right", "margin-bottom", "margin-left",
    "border", "border-top", "border-right", "border-bottom", "border-left",
    "border-color", "border-style", "border-width",
}
# A value that could load a resource, run script or escape the declaration. This
# blocklist is enough only because no allowed property accepts an image; adding
# one such as background or list-style needs a per-property value check instead.
UNSAFE_VALUE = re.compile(r"url\(|expression|javascript:|/\*|\*/|[\\<>@{}]", re.I)


def _style(value):
    kept = []
    for declaration in value.split(";"):
        name, colon, rest = declaration.partition(":")
        name, rest = name.strip().lower(), rest.strip()
        if colon and name in STYLES and rest and not UNSAFE_VALUE.search(rest):
            kept.append(f"{name}: {rest}")
    return "; ".join(kept) or None


def _filter(tag, attribute, value):
    if attribute == "style":
        return _style(value)
    return value


def sanitize(html):
    """Return the HTML a panel stores and shows."""
    return nh3.clean(
        html,
        tags=TAGS,
        clean_content_tags=DROPPED,
        attributes=ATTRIBUTES,
        attribute_filter=_filter,
        url_schemes=SCHEMES,
        url_relative="deny",
        link_rel="noopener noreferrer",
        set_tag_attribute_values={"a": {"target": "_blank"}},
        strip_comments=True,
    ).strip()


class _Report(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.removed = []

    def note(self, what):
        self.removed.append({"line": self.getpos()[0], "what": what})

    def handle_starttag(self, tag, attrs):
        if tag not in TAGS:
            self.note(f"<{tag}> element" if tag in DROPPED else f"<{tag}> tag (text kept)")
            return
        allowed = ATTRIBUTES["*"] | ATTRIBUTES.get(tag, set())
        if tag == "a":
            # The sanitizer sets these itself, so stored links report nothing.
            allowed = allowed | {"target", "rel"}
        for name, value in attrs:
            if name not in allowed:
                self.note(f"{name} attribute")
            elif name == "href":
                value = (value or "").strip()
                scheme = value.split(":", 1)[0].lower() if ":" in value else ""
                if not scheme:
                    self.note("relative link")
                elif scheme not in SCHEMES:
                    self.note(f"{scheme}: link")
            elif name == "style":
                kept = _style(value or "") or ""
                kept_names = {item.split(":", 1)[0] for item in kept.split("; ") if item}
                for declaration in (value or "").split(";"):
                    name = declaration.partition(":")[0].strip().lower()
                    if name and name not in kept_names:
                        self.note(f"{name} style")

    handle_startendtag = handle_starttag

    def handle_comment(self, data):
        self.note("comment")


def removals(html):
    """List what sanitizing removes, with the source line of each removal."""
    report = _Report()
    report.feed(html)
    report.close()
    return report.removed
