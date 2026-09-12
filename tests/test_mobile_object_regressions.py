from pathlib import Path


def test_incident_mobile_location_is_split_into_two_lines() -> None:
    incidents = Path("src/monitoring/templates/incidents.html").read_text(encoding="utf-8")
    css = Path("src/monitoring/static/app.css").read_text(encoding="utf-8")
    assert 'class="incident-location"' in incidents
    assert 'class="incident-site-name"' in incidents
    assert 'class="incident-address"' in incidents
    assert 'class="incident-location-separator"' in incidents
    assert ".incident-location-separator { display: none; }" in css
    assert ".incident-location {" in css and "grid-template-columns: minmax(0, 1fr);" in css


def test_ios_objects_layout_is_strictly_contained() -> None:
    css = Path("src/monitoring/static/app.css").read_text(encoding="utf-8")
    assert "html {\n  width: 100%;\n  max-width: 100%;\n  overflow-x: hidden;" in css
    assert "overscroll-behavior-x: none;" in css
    assert "input, select, textarea { max-width: 100%; }" in css
    assert ".responsive-table tbody tr:not(.edit-row) {\n    width: calc(100% - 20px);" in css
    assert ".responsive-table .edit-row {\n    width: calc(100% - 20px);" in css
    assert (
        ".targets-table,\n  .targets-table tbody,\n  .targets-table tr,\n  .targets-table td { overflow-x: clip; }"
        in css
    )


def test_mobile_object_tools_keep_badges_on_the_right() -> None:
    css = Path("src/monitoring/static/app.css").read_text(encoding="utf-8")
    tools = Path("src/monitoring/templates/_target_tools.html").read_text(encoding="utf-8")
    assert "target-notification-badge" in tools
    assert '.targets-table td[data-label="Название"] .target-tools {' in css
    assert ".targets-table .target-tools > .icon-action," in css
    assert ".targets-table .target-tools > .badge { order: 2; }" in css
    assert ".targets-table .target-tools > .badge:first-of-type { margin-left: auto; }" in css
