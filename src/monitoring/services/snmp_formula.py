"""Safe, small expression language for derived SNMP metrics.

Formula metrics deliberately refer to source OIDs rather than to other metric
records.  A derived value can therefore be useful without exposing auxiliary
raw counters in the user interface or storing their history.
"""

from __future__ import annotations

import ast
from collections.abc import Mapping
from dataclasses import dataclass
from decimal import ROUND_HALF_UP, Decimal, InvalidOperation

from monitoring.services.snmp_oid_catalog import canonical_oid

MAX_FORMULA_LENGTH = 2000
MAX_FORMULA_SOURCE_OIDS = 16
KIB = Decimal(1024)
MIB = KIB * KIB
GIB = MIB * KIB
_CONSTANTS = {"KiB": KIB, "MiB": MIB, "GiB": GIB}
_HR_STORAGE_BASE = "1.3.6.1.2.1.25.2.3.1"
_STORAGE_FUNCTIONS = frozenset(
    {
        "hr_storage_total_bytes",
        "hr_storage_used_bytes",
        "hr_storage_free_bytes",
        "hr_storage_free_percent",
    }
)
_SIMPLE_FUNCTIONS = frozenset({"oid", "min", "max", "abs", "round"})


class FormulaError(ValueError):
    """A formula is invalid or cannot be evaluated from the current poll."""


def _decimal(value: object) -> Decimal:
    try:
        result = Decimal(str(value))
    except (InvalidOperation, ValueError) as exc:
        raise FormulaError("Формула получила нечисловое значение") from exc
    if not result.is_finite():
        raise FormulaError("Значения формулы должны быть конечными")
    return result


def _storage_oids(index: int) -> tuple[str, str, str]:
    if not 1 <= index <= 2_147_483_647:
        raise FormulaError("Индекс hrStorage должен быть положительным")
    return tuple(f"{_HR_STORAGE_BASE}.{column}.{index}" for column in (4, 5, 6))


@dataclass(frozen=True, slots=True)
class CompiledSnmpFormula:
    expression: str
    tree: ast.Expression
    source_oids: tuple[str, ...]

    def evaluate(self, values: Mapping[str, Decimal]) -> Decimal:
        def source(oid: str) -> Decimal:
            try:
                return values[oid]
            except KeyError as exc:
                raise FormulaError(f"Источник OID {oid} не вернул числовое значение") from exc

        def visit(node: ast.AST) -> Decimal:
            if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
                return _decimal(node.value)
            if isinstance(node, ast.Name) and node.id in _CONSTANTS:
                return _CONSTANTS[node.id]
            if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.UAdd, ast.USub)):
                value = visit(node.operand)
                return value if isinstance(node.op, ast.UAdd) else -value
            if isinstance(node, ast.BinOp) and isinstance(
                node.op, (ast.Add, ast.Sub, ast.Mult, ast.Div)
            ):
                left, right = visit(node.left), visit(node.right)
                if isinstance(node.op, ast.Add):
                    return left + right
                if isinstance(node.op, ast.Sub):
                    return left - right
                if isinstance(node.op, ast.Mult):
                    return left * right
                if right == 0:
                    raise FormulaError("Деление на ноль")
                return left / right
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
                raise FormulaError("Недопустимая конструкция формулы")
            name = node.func.id
            if name == "oid":
                return source(canonical_oid(str(node.args[0].value)))
            if name in _STORAGE_FUNCTIONS:
                index = int(node.args[0].value)
                allocation, total, used = (source(oid) for oid in _storage_oids(index))
                total_bytes, used_bytes = total * allocation, used * allocation
                if name == "hr_storage_total_bytes":
                    return total_bytes
                if name == "hr_storage_used_bytes":
                    return used_bytes
                if name == "hr_storage_free_bytes":
                    return total_bytes - used_bytes
                if total_bytes == 0:
                    raise FormulaError("Общий размер hrStorage равен нулю")
                return (total_bytes - used_bytes) * Decimal(100) / total_bytes
            arguments = [visit(argument) for argument in node.args]
            if name == "min":
                return min(arguments)
            if name == "max":
                return max(arguments)
            if name == "abs":
                return abs(arguments[0])
            if name == "round":
                places = int(arguments[1]) if len(arguments) == 2 else 0
                return arguments[0].quantize(Decimal(1).scaleb(-places), rounding=ROUND_HALF_UP)
            raise FormulaError("Недопустимая функция формулы")

        result = visit(self.tree.body)
        if not result.is_finite():
            raise FormulaError("Результат формулы должен быть конечным")
        return result


def compile_snmp_formula(expression: str) -> CompiledSnmpFormula:
    source = expression.strip()
    if not source or len(source) > MAX_FORMULA_LENGTH:
        raise FormulaError(f"Формула должна содержать от 1 до {MAX_FORMULA_LENGTH} символов")
    try:
        tree = ast.parse(source, mode="eval")
    except SyntaxError as exc:
        raise FormulaError("Синтаксис формулы некорректен") from exc

    source_oids: list[str] = []

    def add_source(oid: str) -> None:
        if oid not in source_oids:
            source_oids.append(oid)
        if len(source_oids) > MAX_FORMULA_SOURCE_OIDS:
            raise FormulaError(f"В одной формуле допустимо не более {MAX_FORMULA_SOURCE_OIDS} OID")

    def validate(node: ast.AST) -> None:
        if isinstance(node, ast.Expression):
            validate(node.body)
            return
        if isinstance(node, ast.Constant):
            if isinstance(node.value, bool) or not isinstance(node.value, (int, float)):
                raise FormulaError("Недопустимое значение в формуле")
            return
        if isinstance(node, ast.Name):
            if node.id not in _CONSTANTS:
                raise FormulaError(f"Неизвестное имя в формуле: {node.id}")
            return
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.UAdd, ast.USub)):
            validate(node.operand)
            return
        if isinstance(node, ast.BinOp) and isinstance(
            node.op, (ast.Add, ast.Sub, ast.Mult, ast.Div)
        ):
            validate(node.left)
            validate(node.right)
            return
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
            raise FormulaError("Разрешены только арифметика и встроенные функции")
        name = node.func.id
        if node.keywords or name not in _SIMPLE_FUNCTIONS | _STORAGE_FUNCTIONS:
            raise FormulaError("Недопустимая функция формулы")
        if name == "oid":
            if (
                len(node.args) != 1
                or not isinstance(node.args[0], ast.Constant)
                or not isinstance(node.args[0].value, str)
            ):
                raise FormulaError('oid() ожидает OID в кавычках: oid("1.3.6.1…")')
            try:
                add_source(canonical_oid(node.args[0].value))
            except ValueError as exc:
                raise FormulaError(str(exc)) from exc
            return
        if name in _STORAGE_FUNCTIONS:
            if (
                len(node.args) != 1
                or not isinstance(node.args[0], ast.Constant)
                or isinstance(node.args[0].value, bool)
                or not isinstance(node.args[0].value, int)
            ):
                raise FormulaError(f"{name}() ожидает числовой индекс hrStorage")
            for oid in _storage_oids(node.args[0].value):
                add_source(oid)
            return
        allowed_counts = {"min": (2, None), "max": (2, None), "abs": (1, 1), "round": (1, 2)}
        minimum, maximum = allowed_counts[name]
        if len(node.args) < minimum or (maximum is not None and len(node.args) > maximum):
            raise FormulaError(f"Некорректное число аргументов {name}()")
        for argument in node.args:
            validate(argument)
        if name == "round" and len(node.args) == 2:
            places = node.args[1]
            if (
                not isinstance(places, ast.Constant)
                or isinstance(places.value, bool)
                or not isinstance(places.value, int)
                or not 0 <= places.value <= 9
            ):
                raise FormulaError("round() поддерживает от 0 до 9 знаков после запятой")

    validate(tree)
    return CompiledSnmpFormula(source, tree, tuple(source_oids))
