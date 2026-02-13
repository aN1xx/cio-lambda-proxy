"""
HTTP utilities for the Lambda proxy.
"""

from typing import Dict


class Request:
    def __init__(
        self,
        host: str,
        method: str,
        path: str,
        headers: Dict[str, str],
    ):
        self.host = host
        self.method = method
        self.path = path
        self.headers = headers
