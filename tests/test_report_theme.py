"""The light/dark toggle, and the head it lives in.

It sits in `HEAD` rather than in either header, because the two reports build
their headers separately — putting it in one would mean adding it to the other
and remembering to keep them in step.
"""

from pylon import reportkit


def test_both_reports_get_the_toggle():
    """The reason it is in HEAD: `report.py` writes its own header markup and
    `report_detections.py` uses `page()`. Anything added to one alone drifts."""
    assert 'id="themetoggle"' in reportkit.HEAD
    shell = reportkit.page("Example", [("workspace", "w")], "<section></section>")
    assert 'id="themetoggle"' in shell


def test_the_button_starts_hidden():
    """It does nothing without JavaScript, and a dead button is worse than no
    button. The script unhides it once it has wired the click up."""
    assert '<button class="themetoggle" id="themetoggle" type="button" hidden>' \
        in reportkit.HEAD


def test_local_storage_is_wrapped():
    """localStorage THROWS rather than returning null in a private window. An
    unhandled error stops the rest of the script and leaves the button dead."""
    script = reportkit.HEAD[reportkit.HEAD.index("<script>"):]
    # One try per access, counted rather than hard-coded, so adding a third
    # localStorage call without wrapping it fails here.
    assert script.count("try {") >= script.count("localStorage.")
    assert script.count("catch") >= script.count("localStorage.")


def test_the_script_runs_before_the_body():
    """A saved dark choice applied after paint is a white flash on every open."""
    assert reportkit.HEAD.index("<script>") < reportkit.HEAD.index("</style>") + 4000
    body = reportkit.page("Example", [], "<section></section>")
    assert body.index("themetoggle") < body.index('<div class="wrap">')


def test_all_three_theme_states_are_defined():
    """A toggle that only overrides one direction cannot switch back: an
    explicit `light` has to beat the system's dark preference, which is what
    the :not([data-theme="light"]) guard is for."""
    css = reportkit.HEAD
    assert "@media (prefers-color-scheme: dark)" in css
    assert ':root:not([data-theme="light"])' in css
    assert ':root[data-theme="dark"]' in css


def test_the_toggle_is_not_printed():
    assert "@media print { .themetoggle { display:none; } }" in reportkit.HEAD


def test_the_lead_block_carries_no_border_of_its_own():
    """The header's line already separates it. Two dividers 3.5rem apart were
    dividing the same thing."""
    assert "border-top:2px solid var(--ink)" not in reportkit.HEAD


class TestThePageIsMeantToBeExported:
    """A report people export needs print rules, not just screen ones.

    Two of these are the difference between a usable PDF and a bad one. The
    viewer's dark mode is a screen preference; inheriting it puts a dark
    rectangle on every sheet. And a detection is the unit a reader judges, so
    splitting one across a page break is the one break that must not happen.
    """

    def test_print_forces_light_colours(self):
        block = reportkit.HEAD[reportkit.HEAD.index("@media print {\n  :root"):]
        assert "--paper:#FFFFFF" in block
        assert '[data-theme="dark"]' in block.split("@page")[0], (
            "the dark override must be beaten in print, or a reader who chose "
            "dark mode exports black pages"
        )

    def test_a_detection_is_not_split_across_a_page(self):
        assert "break-inside:avoid" in reportkit.HEAD
        assert "page-break-inside:avoid" in reportkit.HEAD

    def test_the_query_wraps_on_paper_rather_than_scrolling(self):
        # `.scroll` is a horizontal scroller, and there is nothing to scroll on
        # a sheet of paper -- the overflow is simply gone.
        printed = reportkit.HEAD[reportkit.HEAD.index("@media print"):]
        assert "white-space:pre-wrap" in printed
        assert ".scroll { overflow-x:visible; }" in printed
