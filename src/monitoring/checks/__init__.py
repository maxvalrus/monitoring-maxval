from monitoring.checks.dns import DnsChecker
from monitoring.checks.http import HttpChecker, HttpsChecker
from monitoring.checks.icmp import IcmpChecker
from monitoring.checks.registry import checker_registry
from monitoring.checks.rtsp import RtspChecker
from monitoring.checks.tcp import TcpChecker

checker_registry.register(TcpChecker())
checker_registry.register(HttpChecker())
checker_registry.register(HttpsChecker())
checker_registry.register(IcmpChecker())
checker_registry.register(RtspChecker())
checker_registry.register(DnsChecker())
checker_registry.load_entry_points()

__all__ = ["checker_registry"]
