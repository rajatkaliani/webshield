from playwright.sync_api import sync_playwright

def render_dynamic_dom(url: str, max_elements: int = 600):
    results = []

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page(user_agent="Mozilla/5.0")

        # Load and render the page fully
        page.goto(url, wait_until="networkidle", timeout=20000)

        # Scroll to trigger lazy elements
        page.evaluate("window.scrollTo(0, document.body.scrollHeight)")

        elements = page.query_selector_all("body *")

        for i, handle in enumerate(elements):
            if i >= max_elements:
                break

            try:
                tag = handle.evaluate("el => el.tagName.toLowerCase()")
                text = (handle.inner_text(timeout=500) or "").strip()[:200]
                href = handle.get_attribute("href")
                bbox = handle.bounding_box()
                visible = handle.is_visible()

                style = handle.evaluate(
                    """
                    el => {
                        const s = window.getComputedStyle(el);
                        return {
                            display: s.display,
                            visibility: s.visibility,
                            opacity: s.opacity,
                            pointerEvents: s.pointerEvents,
                            zIndex: s.zIndex
                        };
                    }
                    """
                )

                results.append({
                    "tag": tag,
                    "text": text,
                    "href": href,
                    "bounding_box": bbox,
                    "computed_style": style,
                    "is_visible": visible
                })

            except Exception:
                continue

        browser.close()

    return results