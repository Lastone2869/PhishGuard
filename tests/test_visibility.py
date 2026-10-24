"""
test_visibility.py
Visibility and accessibility testing for PhishGuard UI components.
Tests element visibility, initial hidden states, conditional rendering,
color contrast classes, and accessibility attributes in HTML, CSS, and JS logic.
"""

import os
import re
from html.parser import HTMLParser
import pytest

# Paths
FRONTEND_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "frontend")
HTML_PATH = os.path.join(FRONTEND_DIR, "index.html")
CSS_PATH = os.path.join(FRONTEND_DIR, "styles.css")
JS_PATH = os.path.join(FRONTEND_DIR, "app.js")

class ElementCollector(HTMLParser):
    def __init__(self):
        super().__init__()
        self.elements = []
        self.by_id = {}

    def handle_starttag(self, tag, attrs):
        attr_dict = dict(attrs)
        el_info = {"tag": tag, "attrs": attr_dict}
        self.elements.append(el_info)
        if "id" in attr_dict:
            self.by_id[attr_dict["id"]] = el_info

def parse_html_elements():
    with open(HTML_PATH, "r", encoding="utf-8") as f:
        content = f.read()
    parser = ElementCollector()
    parser.feed(content)
    return content, parser.by_id, parser.elements

# =========================================================================
# 1. Initial State Visibility & Hidden Classes Tests
# =========================================================================

def test_visibility_results_card_hidden_initially():
    """Verifies that the assessment results card is hidden prior to user analysis."""
    _, by_id, _ = parse_html_elements()
    assert "results-card" in by_id, "results-card element not found in HTML"
    card_classes = by_id["results-card"]["attrs"].get("class", "").split()
    assert "hidden" in card_classes, "results-card must have 'hidden' class initially"

def test_visibility_defanged_container_hidden_initially():
    """Verifies that the defanged URLs container is hidden before analysis."""
    _, by_id, _ = parse_html_elements()
    assert "defanged-container" in by_id, "defanged-container element not found in HTML"
    classes = by_id["defanged-container"]["attrs"].get("class", "").split()
    assert "hidden" in classes, "defanged-container must have 'hidden' class initially"

def test_visibility_css_hidden_rule():
    """Verifies that CSS defines .hidden with display: none !important."""
    with open(CSS_PATH, "r", encoding="utf-8") as f:
        css = f.read()
    # Search for .hidden rule
    hidden_match = re.search(r"\.hidden\s*\{([^}]+)\}", css)
    assert hidden_match is not None, ".hidden class rule not found in styles.css"
    rule_body = hidden_match.group(1)
    assert "display:none" in re.sub(r"\s+", "", rule_body)
    assert "!important" in rule_body

# =========================================================================
# 2. Form Controls & Interactive Elements Visibility
# =========================================================================

def test_visibility_form_controls_and_labels():
    """Verifies that message textarea and sender input have visible, associated labels."""
    content, by_id, _ = parse_html_elements()
    
    # Message textarea
    assert "msg-text" in by_id
    assert by_id["msg-text"]["tag"] == "textarea"
    assert re.search(r'<label[^>]*for=["\']msg-text["\']', content), "Label for msg-text is missing"

    # Sender input
    assert "msg-sender" in by_id
    assert by_id["msg-sender"]["tag"] == "input"
    assert re.search(r'<label[^>]*for=["\']msg-sender["\']', content), "Label for msg-sender is missing"

    # Submit button
    assert "btn-submit" in by_id
    assert by_id["btn-submit"]["tag"] == "button"

def test_visibility_sample_scenario_pills():
    """Verifies that scenario sample pills exist and are visible for quick testing."""
    content, _, _ = parse_html_elements()
    assert "loadSample('vit_phish')" in content
    assert "loadSample('vit_legit')" in content
    assert "loadSample('gpay_phish')" in content
    assert "loadSample('peer_chat')" in content

# =========================================================================
# 3. Accessibility & Contrast Visibility Attributes
# =========================================================================

def test_visibility_accessibility_aria_attributes():
    """Verifies aria-live and aria-hidden attributes for accessible screen reader experience."""
    _, by_id, elements = parse_html_elements()
    
    # results-card should announce dynamic updates
    assert by_id["results-card"]["attrs"].get("aria-live") == "polite"
    
    # Decorative icons should be hidden from screen readers
    aria_hidden_elements = [el for el in elements if el["attrs"].get("aria-hidden") == "true"]
    assert len(aria_hidden_elements) >= 2, "Expected decorative icons to have aria-hidden='true'"

def test_visibility_color_contrast_tokens():
    """Verifies that styles.css defines high-contrast accessible color tokens."""
    with open(CSS_PATH, "r", encoding="utf-8") as f:
        css = f.read()
    # High-contrast text colors on dark backgrounds
    assert "--text-primary: #f0fdf4;" in css
    assert "--color-safe: #10b981;" in css
    assert "--color-warn: #f59e0b;" in css
    assert "--color-danger: #ef4444;" in css

# =========================================================================
# 4. Controller Dynamic Visibility Logic Tests
# =========================================================================

def test_visibility_controller_results_unhidden_logic():
    """Verifies that app.js explicitly removes the hidden class when results arrive."""
    with open(JS_PATH, "r", encoding="utf-8") as f:
        js = f.read()
    assert 'card.classList.remove("hidden")' in js

def test_visibility_controller_defanged_conditional_logic():
    """Verifies that app.js unhides defanged container only when URLs exist."""
    with open(JS_PATH, "r", encoding="utf-8") as f:
        js = f.read()
    assert 'defangedContainer.classList.remove("hidden")' in js
    assert 'defangedContainer.classList.add("hidden")' in js

def test_visibility_controller_verdict_badge_classes():
    """Verifies that app.js applies the correct badge color class."""
    with open(JS_PATH, "r", encoding="utf-8") as f:
        js = f.read()
    assert 'badge.classList.add("badge-red")' in js
    assert 'badge.classList.add("badge-amber")' in js
    assert 'badge.classList.add("badge-emerald")' in js

def test_visibility_controller_recommendation_rendered():
    """Verifies that app.js populates the recommendation banner."""
    with open(JS_PATH, "r", encoding="utf-8") as f:
        js = f.read()
    assert 'document.getElementById("verdict-recommendation")' in js
    assert 'recEl.textContent = data.recommendation' in js
