"""Fixes to pinned pySigma backends, used by tests/convert_rules.py instead of the originals.

`backend` in pipelines/targets.yml names the installed backend; a class here replaces it for
conversion. Each fix is for output the backend produces without an error but that the
platform rejects or reads differently. Re-check them when a backend version is bumped.
"""

from __future__ import annotations

from sigma.backends.elasticsearch import EqlBackend
from sigma.backends.kusto import KustoBackend
from sigma.conditions import ConditionAND, ConditionFieldEqualsValueExpression, ConditionOR
from sigma.conversion.state import ConversionState
from sigma.types import SigmaNumber, SigmaString


def _values(cond: ConditionOR | ConditionAND) -> list:
    return [arg.value for arg in cond.args if isinstance(arg, ConditionFieldEqualsValueExpression)]


class _NumberLists:
    """A list of numbers becomes `field in (1, 2)`, not a list of quoted strings.

    Both backends turn a list of values into their case-insensitive list operator (`like~`
    in EQL, `in~` in KQL), which compares strings.
    """

    def convert_condition_as_in_expression(self, cond: ConditionOR | ConditionAND, state: ConversionState) -> str:
        values = _values(cond)
        if isinstance(cond, ConditionOR) and values and all(isinstance(value, SigmaNumber) for value in values):
            field = self.escape_and_quote_field(cond.args[0].field)
            return f"{field} in ({', '.join(str(value) for value in values)})"
        return super().convert_condition_as_in_expression(cond, state)


class RepoEqlBackend(_NumberLists, EqlBackend):
    """EQL with numbers and IP addresses compared the way EQL accepts.

    pySigma-backend-elasticsearch 2.1.1 compares a number with `:` (`destination.port:4444`)
    and a list of numbers or IP addresses with `like~`. EQL allows `:` and `like~` only
    between strings, so a query that uses them on a number or IP field fails as a whole.
    Numbers use `==` and `in`, as Elastic's own EQL rules do (`destination.port in (445,
    139)`). A list of IP addresses, or of numbers mixed with strings, becomes separate
    comparisons joined by `or`, so each value gets an operator EQL accepts for it. A single
    address already uses `==`.
    """

    def convert_condition_field_eq_val_num(self, cond: ConditionFieldEqualsValueExpression, state: ConversionState) -> str:
        return f"{self.escape_and_quote_field(cond.field)} == {cond.value}"

    def decide_convert_condition_as_in_expression(self, cond: ConditionOR | ConditionAND, state: ConversionState) -> bool:
        values = _values(cond)
        numbers = [value for value in values if isinstance(value, SigmaNumber)]
        if numbers and len(numbers) != len(values):
            return False
        if any(isinstance(value, SigmaString) and self.is_ip(value) for value in values):
            return False
        return super().decide_convert_condition_as_in_expression(cond, state)


class RepoKustoBackend(_NumberLists, KustoBackend):
    """KQL with lists of numbers unquoted.

    pySigma-backend-kusto 1.0.1 quotes the numbers in a list (`DestinationPort in~ ("443",
    "80")`), so the list no longer compares with an int column
    (https://github.com/AttackIQ/pySigma-backend-kusto/issues/47). A single number already
    uses `==`.
    """


# Backend name in pipelines/targets.yml -> class used for conversion.
BACKENDS = {
    "eql": RepoEqlBackend,
    "kusto": RepoKustoBackend,
}
