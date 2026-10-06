from dataclasses import replace

from .detectors import Finding


class IpAnonymizer:
    """Replace source IPs with stable labels for one run.

    Labels are numbered in first-seen order, so the same IP always gets the
    same label within a run and no part of the address is kept. The mapping
    is never written anywhere.
    """

    def __init__(self) -> None:
        self._labels: dict[str, str] = {}

    def label(self, ip: str) -> str:
        if ip not in self._labels:
            self._labels[ip] = f"ip-{len(self._labels) + 1:03d}"
        return self._labels[ip]

    def finding(self, finding: Finding) -> Finding:
        return replace(finding, source_ip=self.label(finding.source_ip))
