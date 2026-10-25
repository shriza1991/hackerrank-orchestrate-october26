"""Small shared field contracts; preserve supplied values without rewriting them."""

from typing import Annotated

from pydantic import StringConstraints


# A required string must contain at least one non-whitespace character.
# Do not strip text: request wording and original identifiers are evidence.
NonBlankStr = Annotated[str, StringConstraints(pattern=r"\S")]
