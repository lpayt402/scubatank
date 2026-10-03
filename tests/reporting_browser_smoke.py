"""Opt-in offline browser smoke check; not part of core unittest dependencies.

Run: python tests/reporting_browser_smoke.py [--report path/to/report.html]
Requires Playwright and an installed Chromium browser. Does not install them.
"""
import argparse
import copy
import importlib.metadata
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def accessibility_checks(page) -> dict:
    """Check the rendered controls and text; this is not a complete WCAG audit."""
    page.keyboard.press("Tab")
    skip = page.get_by_role("link", name="Skip to report", exact=True)
    assert skip.evaluate("node => node === document.activeElement"), "Skip link is not first in keyboard order"
    assert skip.bounding_box()["y"] >= 0, "Focused skip link is hidden"
    assert skip.evaluate("node => getComputedStyle(node).outlineStyle") != "none", "Keyboard focus has no visible outline"
    skip.press("Enter")
    assert page.locator("main").evaluate("node => node === document.activeElement"), "Skip link did not focus the main report"
    table = page.get_by_role("table", name="Result counts", exact=True)
    assert table.get_by_role("columnheader").all_text_contents() == ["Result", "Count", "Meaning"], "Result table lacks associated headers"
    assert table.get_by_role("rowheader").count() == 6, "Result table omits a supported state"
    contrast = page.evaluate("""() => {
        const rgb = value => value.match(/[\\d.]+/g).map(Number);
        const luminance = color => color.slice(0,3).map(v => v/255).map(v => v <= .04045 ? v/12.92 : ((v+.055)/1.055)**2.4).reduce((sum,v,i) => sum+v*[.2126,.7152,.0722][i],0);
        const ratio = (a,b) => (Math.max(a,b)+.05)/(Math.min(a,b)+.05);
        let minimum = 21, checked = 0; const failures = [];
        for (const node of document.querySelectorAll('body *')) {
            const style = getComputedStyle(node);
            if (!node.getClientRects().length || style.visibility === 'hidden') continue;
            if (!Array.from(node.childNodes).some(n => n.nodeType === Node.TEXT_NODE && n.textContent.trim()) && !node.matches('input,select')) continue;
            let background = node, color;
            do { color = rgb(getComputedStyle(background).backgroundColor); background = background.parentElement; } while (background && color[3] === 0);
            const foreground = rgb(style.color);
            const contrast = ratio(luminance(foreground),luminance(color));
            minimum = Math.min(minimum,contrast); checked++;
            if (contrast < 4.5) failures.push({tag:node.tagName,text:node.textContent.slice(0,60),contrast});
        }
        return {minimum,checked,failures};
    }""")
    assert contrast["checked"] > 0 and not contrast["failures"], f"Low text contrast: {contrast['failures']}"
    for width in (390, 320):
        page.set_viewport_size({"width": width, "height": 844})
        assert page.evaluate("document.documentElement.scrollWidth <= innerWidth + 1"), f"Report overflows at {width}px"
    original_size = page.evaluate("parseFloat(getComputedStyle(document.body).fontSize)")
    page.evaluate("document.documentElement.style.fontSize = '200%'")
    assert page.evaluate("parseFloat(getComputedStyle(document.body).fontSize)") >= original_size * 2, "Report text did not resize to 200%"
    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth + 1"), "Enlarged report text overflows at 320px"
    page.evaluate("document.documentElement.style.fontSize = ''")
    return {"text_contrast_minimum": contrast["minimum"], "text_elements_checked": contrast["checked"],
            "narrow_widths": [390, 320], "text_resize_percent": 200,
            "checks": ["skip-link-focus", "visible-keyboard-focus", "table-headers", "text-contrast", "narrow-reflow", "text-resize"]}


def smoke(report_path: Path, output: Path) -> dict:
    from playwright.sync_api import expect, sync_playwright

    output.mkdir(parents=True, exist_ok=True)
    requests, errors = [], []
    finding_sections_checked = False
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        version = browser.version
        context = browser.new_context(viewport={"width": 1440, "height": 1000}, offline=True)
        page = context.new_page()
        page.on("request", lambda request: requests.append(request.url) if not request.url.startswith("file:") else None)
        page.on("pageerror", lambda error: errors.append(str(error)))
        page.on("console", lambda message: errors.append(message.text) if message.type == "error" else None)
        page.goto(report_path.resolve().as_uri(), wait_until="load")
        assert page.title().startswith("ScubaTank assessment"), "Wrong report title"
        assert page.locator("main").count() == 1, "Missing main landmark"
        assert page.locator('label[for="status-filter"]').count() == 1, "Missing filter label"
        assert page.locator('label[for="search"]').count() == 1, "Missing search label"
        broken = page.evaluate("""() => Array.from(document.querySelectorAll('a[href^="#"]')).map(link => link.getAttribute('href').slice(1)).filter(id => !document.getElementById(id))""")
        assert not broken, f"Broken report fragment targets: {broken}"
        states = page.locator(".finding").evaluate_all("nodes => nodes.map(node => node.dataset.status)")
        for state in sorted(set(states)):
            page.locator("#status-filter").select_option(state)
            assert page.locator(".finding:visible").count() == states.count(state), f"Incorrect {state} filter"
        for link in page.locator("[data-filter]").all():
            state = link.get_attribute("data-filter")
            link.click()
            assert page.locator("#status-filter").input_value() == state, "Summary link did not select its result"
            assert page.locator(".finding:visible").count() == states.count(state), f"Incorrect {state} summary link"
        page.locator("#status-filter").select_option("all")
        page.locator("#search").fill("no-such-object-cf812bc9")
        assert page.locator(".finding:visible").count() == 0, "Search filter did not hide unmatched findings"
        page.locator("#search").fill("")
        assert page.locator(".finding:visible").count() == len(states), "Search reset did not restore findings"
        if states:
            section = page.locator("details.finding").first
            if section.count():
                finding_sections_checked = True
                toggle = section.locator(":scope > summary")
                toggle.focus()
                toggle.press("Enter")
                expect(section).not_to_have_attribute("open", "")
                toggle.press("Enter")
                expect(section).to_have_attribute("open", "")
                toggle.press("Enter")
                fragment = "#" + section.get_attribute("id")
                page.locator("#search").fill("no-such-object-cf812bc9")
                page.evaluate("fragment => location.hash = fragment", fragment)
                expect(section).to_have_attribute("open", "")
                expect(section).to_be_visible()
                assert page.locator("#search").input_value() == "", "Finding link did not reset the filter"
            summary = page.locator(".finding details summary").first
            summary.focus()
            summary.press("Enter")
            assert page.locator(".finding details").first.get_attribute("open") is not None, "Keyboard disclosure did not open"
            link = page.locator('.finding a[href^="#evidence-"]').first
            if link.count():
                target = link.get_attribute("href")
                link.click()
                expect(page.locator(target)).to_have_attribute("open", "")
        page.goto(report_path.resolve().as_uri(), wait_until="load")
        page.screenshot(path=str(output / "report-desktop.png"), full_page=True)
        page.set_viewport_size({"width": 390, "height": 844})
        assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth + 1"), "Narrow viewport overflows horizontally"
        page.screenshot(path=str(output / "report-mobile.png"), full_page=True)
        page.goto(report_path.resolve().as_uri(), wait_until="load")
        accessibility = accessibility_checks(page) if page.locator("table.results").count() else {"checks": [], "layout": "legacy"}
        no_script = browser.new_context(viewport={"width": 390, "height": 844}, offline=True, java_script_enabled=False)
        plain = no_script.new_page()
        plain.on("request", lambda request: requests.append(request.url) if not request.url.startswith("file:") else None)
        plain.goto(report_path.resolve().as_uri(), wait_until="load")
        assert plain.locator(".finding:visible").count() == len(states), "Disabling JavaScript hid findings"
        if states:
            section = plain.locator("details.finding").first
            if section.count():
                section.locator(":scope > summary").click()
                assert section.get_attribute("open") is None, "Native finding section did not collapse"
                section.locator(":scope > summary").click()
                assert section.get_attribute("open") is not None, "Native finding section requires JavaScript"
            plain.locator(".finding details summary").first.click()
            assert plain.locator(".finding details").first.get_attribute("open") is not None, "Native disclosure requires JavaScript"
        assert not requests, f"Report made outbound requests: {requests}"
        assert not errors, f"Browser errors: {errors}"
        browser.close()
    result = {"playwright_version": importlib.metadata.version("playwright"), "chromium_version": version,
              "report": str(report_path.resolve()), "findings": len(states), "tested_states": sorted(set(states)),
              "external_requests": requests, "browser_errors": errors, "broken_fragments": broken,
              "accessibility": accessibility,
              "checks": ["offline", "filters", "summary-links", "search", "keyboard-disclosure", "evidence-expansion", "local-links", "mobile-layout", "no-script-disclosure"]}
    if finding_sections_checked:
        result["checks"].extend(["finding-section-keyboard", "finding-link-reveal", "no-script-finding-section"])
    (output / "browser-smoke.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


def main():
    parser = argparse.ArgumentParser(description="Check a local ScubaTank report in an offline Chromium browser.")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--output", type=Path, default=ROOT / ".build" / "reporting-smoke")
    args = parser.parse_args()
    path = args.report
    if path is None:
        from test_reporting import example
        from scubatank.reporting import build_report, write_reports

        finding, metadata = example()
        unknown = copy.deepcopy(finding)
        unknown.update(finding_id="finding-unknown", status="Unknown", missing_evidence=["Current identity link"],
                       confidence="Unknown", message="The identity link needs current evidence.", paths=[], remediation=[])
        passing = copy.deepcopy(finding)
        passing.update(finding_id="finding-pass", status="Pass", coverage="complete",
                       message="The bounded predicate is disproved by complete required evidence.", paths=[], remediation=[])
        path = write_reports(build_report([finding, unknown, passing], **metadata), args.output)["html"]
    print(json.dumps(smoke(path, args.output), indent=2))


if __name__ == "__main__":
    main()
