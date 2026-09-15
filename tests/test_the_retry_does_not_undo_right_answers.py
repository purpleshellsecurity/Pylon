"""A warning is not an error, and the corrective retry must not treat it as one.

`run_detection_phase` gets ONE retry per detection. It built that prompt from
`result.errors + result.warnings` as a single list under "Fix every listed
error and return the corrected detection."

Only the errors are things the query got wrong. A warning is frequently the
validator saying a CHECK COULD NOT RUN:

    AzureActivity: "CategoryValue" is not a column the prompt teaches.
    Microsoft's column list could not be fetched, so this was NOT checked
    against it -- verify the name before deploying.

`CategoryValue` is a real AzureActivity column. Told to fix it, the model
deletes a correct filter, and the one retry the run pays for is spent undoing a
right answer -- the same shape as the comment that got a query rejected for
naming the column it was warning against.

This asserts on the prompt TEXT rather than on a live run: the split is a
property of what the model is told, and a test that needed a model call would
not run here.
"""

import inspect
import re

from pylon import engine

SRC = inspect.getsource(engine.run_detection_phase)


def test_the_two_lists_are_not_concatenated():
    """The defect itself: one list, one instruction."""
    assert "result.errors + result.warnings" not in SRC, (
        "errors and warnings are merged into one list the model is told to fix")


def test_errors_are_still_named_as_things_to_fix():
    assert "result.errors" in SRC
    assert re.search(r"These are errors\. Fix every one", SRC), SRC[:0] or "gone"


def test_warnings_are_named_as_advisory():
    assert "result.warnings" in SRC
    assert "did NOT fail the query" in SRC
    assert "cannot alter what" in SRC


def test_the_warning_this_was_written_for_is_still_a_warning():
    """If this ever became an error the split above would not save it."""
    from pylon.validation.validate_kql import validate_kql

    query = ('AzureActivity\n'
             '| where OperationNameValue =~ "Microsoft.Storage/storageAccounts/write"\n'
             '| where CategoryValue == "Administrative"\n'
             '| project TimeGenerated, Caller\n')
    result = validate_kql(query, "AzureActivity", documented=None)
    assert any("CategoryValue" in w for w in result.warnings), result.warnings
    assert not any("CategoryValue" in x for x in result.errors), result.errors
