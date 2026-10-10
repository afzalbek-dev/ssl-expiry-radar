"""Multi-domain scanner and alert categorization for SSL Radar."""
from typing import List, Dict, Any
from .checker import CertInspector

class DomainScanner:
    def __init__(self, warning_days: int = 30, critical_days: int = 7, timeout: float = 5.0):
        self.warning_days = warning_days
        self.critical_days = critical_days
        self.inspector = CertInspector(timeout=timeout)

    def classify_status(self, check_result: Dict[str, Any]) -> str:
        if not check_result.get("valid", False):
            return "ERROR"
        days = check_result.get("days_remaining", 0)
        if days == 0:
            return "EXPIRED"
        if days <= self.critical_days:
            return "CRITICAL"
        if days <= self.warning_days:
            return "WARNING"
        return "HEALTHY"

    def scan_domains(self, domains: List[str]) -> List[Dict[str, Any]]:
        results = []
        for domain in domains:
            domain = domain.strip()
            if not domain or domain.startswith("#"):
                continue
            res = self.inspector.check_host(domain)
            res["status"] = self.classify_status(res)
            results.append(res)
        return results
