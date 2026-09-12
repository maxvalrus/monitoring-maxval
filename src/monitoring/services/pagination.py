from dataclasses import dataclass
from urllib.parse import urlencode

from fastapi import Request


def positive_int(raw: str | None, default: int, maximum: int | None = None) -> int:
    try:
        value = int(raw or "")
    except ValueError:
        return default
    if value < 1:
        return default
    return min(value, maximum) if maximum is not None else value


@dataclass(frozen=True, slots=True)
class Pagination:
    page: int
    pages: int
    per_page: int
    total: int
    offset: int

    @classmethod
    def from_request(
        cls,
        request: Request,
        total: int,
        *,
        default_per_page: int = 100,
        maximum_per_page: int = 1000,
    ) -> "Pagination":
        per_page = positive_int(
            request.query_params.get("per_page"),
            default_per_page,
            maximum_per_page,
        )
        requested_page = positive_int(request.query_params.get("page"), 1)
        pages = max(1, (total + per_page - 1) // per_page)
        page = min(requested_page, pages)
        return cls(
            page=page,
            pages=pages,
            per_page=per_page,
            total=total,
            offset=(page - 1) * per_page,
        )


@dataclass(frozen=True, slots=True)
class SortState:
    column: str
    direction: str

    @classmethod
    def from_request(
        cls,
        request: Request,
        allowed_columns: set[str],
        default_column: str,
        default_direction: str = "asc",
        *,
        column_parameter: str = "sort",
        direction_parameter: str = "direction",
    ) -> "SortState":
        column = request.query_params.get(column_parameter, default_column)
        if column not in allowed_columns:
            column = default_column
        direction = request.query_params.get(direction_parameter, default_direction)
        if direction not in {"asc", "desc"}:
            direction = default_direction
        return cls(column=column, direction=direction)

    def order(self, expression):
        return expression.desc() if self.direction == "desc" else expression.asc()


def page_url(request: Request, page: int, per_page: int) -> str:
    parameters = dict(request.query_params)
    parameters.pop("notice", None)
    parameters.pop("error", None)
    parameters["page"] = str(page)
    parameters["per_page"] = str(per_page)
    return f"{request.url.path}?{urlencode(parameters)}"


def sort_url(
    request: Request,
    column: str,
    current_column: str,
    current_direction: str,
    column_parameter: str = "sort",
    direction_parameter: str = "direction",
) -> str:
    parameters = dict(request.query_params)
    parameters.pop("notice", None)
    parameters.pop("error", None)
    parameters[column_parameter] = column
    parameters[direction_parameter] = (
        "desc" if column == current_column and current_direction == "asc" else "asc"
    )
    parameters["page"] = "1"
    return f"{request.url.path}?{urlencode(parameters)}"
