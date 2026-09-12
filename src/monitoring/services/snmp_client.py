from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True, slots=True)
class SnmpRequest:
    address: str
    port: int
    community: str
    timeout_seconds: int
    retries: int
    version: str = "v2c"


@dataclass(frozen=True, slots=True)
class SnmpVarBind:
    oid: str
    value: str | None
    detected_type: str
    error: str | None = None


@dataclass(frozen=True, slots=True)
class SnmpWalkResult:
    items: tuple[SnmpVarBind, ...]
    truncated: bool = False


class SnmpClientError(RuntimeError):
    """A transport or protocol error affecting an SNMP request as a whole."""


class SnmpClient(Protocol):
    async def get(
        self, request: SnmpRequest, oids: Sequence[str]
    ) -> list[SnmpVarBind]: ...

    async def walk(
        self, request: SnmpRequest, root_oid: str, *, max_results: int
    ) -> SnmpWalkResult: ...


class PySnmpClient:
    """Small PySNMP adapter kept outside the SNMP business service."""

    @staticmethod
    def _community_data(community_data, request: SnmpRequest):
        """Build an SNMP community credential for the configured protocol version."""
        return community_data(request.community, mpModel=0 if request.version == "v1" else 1)

    async def get(
        self, request: SnmpRequest, oids: Sequence[str]
    ) -> list[SnmpVarBind]:
        # Import lazily so unit tests can use a fake client without PySNMP installed.
        from pysnmp.hlapi.v3arch.asyncio import (  # type: ignore[import-not-found]
            CommunityData,
            ContextData,
            ObjectIdentity,
            ObjectType,
            SnmpEngine,
            UdpTransportTarget,
            get_cmd,
        )

        engine = SnmpEngine()
        try:
            transport = await UdpTransportTarget.create(
                (request.address, request.port),
                timeout=request.timeout_seconds,
                retries=request.retries,
            )
            error_indication, error_status, _error_index, var_binds = await get_cmd(
                engine,
                self._community_data(CommunityData, request),
                transport,
                ContextData(),
                *(ObjectType(ObjectIdentity(oid)) for oid in oids),
            )
            if error_indication:
                raise SnmpClientError("Ошибка транспорта SNMP")
            if error_status:
                raise SnmpClientError("Ошибка протокола SNMP")
            result: list[SnmpVarBind] = []
            for oid_value, value in var_binds:
                result.append(self._var_bind(oid_value, value))
            return result
        except SnmpClientError:
            raise
        except Exception as exc:
            # PySNMP errors may contain request details. Never expose them to UI or logs.
            raise SnmpClientError("Не удалось выполнить запрос SNMP") from exc
        finally:
            engine.close_dispatcher()

    async def walk(
        self, request: SnmpRequest, root_oid: str, *, max_results: int
    ) -> SnmpWalkResult:
        if max_results <= 0:
            return SnmpWalkResult((), truncated=True)

        from pysnmp.hlapi.v3arch.asyncio import (  # type: ignore[import-not-found]
            CommunityData,
            ContextData,
            ObjectIdentity,
            ObjectType,
            SnmpEngine,
            UdpTransportTarget,
            bulk_walk_cmd,
            walk_cmd,
        )

        engine = SnmpEngine()
        result: list[SnmpVarBind] = []
        try:
            transport = await UdpTransportTarget.create(
                (request.address, request.port),
                timeout=request.timeout_seconds,
                retries=request.retries,
            )
            if request.version == "v1":
                # SNMPv1 has no GETBULK; use the equivalent GETNEXT walk.
                iterator = walk_cmd(
                    engine,
                    self._community_data(CommunityData, request),
                    transport,
                    ContextData(),
                    ObjectType(ObjectIdentity(root_oid)),
                    lexicographicMode=False,
                    maxRows=max_results,
                )
            else:
                iterator = bulk_walk_cmd(
                    engine,
                    self._community_data(CommunityData, request),
                    transport,
                    ContextData(),
                    0,
                    25,
                    ObjectType(ObjectIdentity(root_oid)),
                    lexicographicMode=False,
                )
            async for error_indication, error_status, _error_index, var_binds in iterator:
                if error_indication:
                    raise SnmpClientError("Ошибка транспорта SNMP")
                if error_status:
                    raise SnmpClientError("Ошибка протокола SNMP")
                for oid_value, value in var_binds:
                    type_name = value.__class__.__name__
                    if type_name == "EndOfMibView":
                        return SnmpWalkResult(tuple(result), truncated=False)
                    result.append(self._var_bind(oid_value, value))
                    if len(result) >= max_results:
                        return SnmpWalkResult(tuple(result), truncated=True)
            return SnmpWalkResult(tuple(result), truncated=False)
        except SnmpClientError:
            raise
        except Exception as exc:
            # Do not leak community or low-level request details.
            raise SnmpClientError("Не удалось выполнить SNMP Discovery") from exc
        finally:
            engine.close_dispatcher()

    @staticmethod
    def _var_bind(oid_value, value) -> SnmpVarBind:
        type_name = value.__class__.__name__
        is_missing = type_name in {"NoSuchObject", "NoSuchInstance"}
        return SnmpVarBind(
            oid=str(oid_value),
            value=None if is_missing else value.prettyPrint(),
            detected_type=type_name,
            error=("Объект OID не существует" if is_missing else None),
        )
