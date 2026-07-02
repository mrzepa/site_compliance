from __future__ import annotations

import base64
import binascii
import json
import logging
from typing import Any

import pyotp
import requests
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
logger = logging.getLogger(__name__)


DEVICE_ENDPOINTS = ["/proxy/network/api/s/{site}/stat/device", "/api/s/{site}/stat/device"]


class UnifiClient:
    def __init__(self, controller: dict[str, Any], timeout: int = 20, verify_tls: bool = False):
        self.name = controller.get("name") or controller["base_url"]
        self.base_url = controller["base_url"].rstrip("/")
        self.timeout = timeout
        self.verify_tls = verify_tls
        self.api_key = controller.get("api_key")
        self.username = controller.get("username")
        self.password = controller.get("password")
        self.mfa_secret = controller.get("mfa_secret")
        self.session = requests.Session()
        if self.api_key:
            self.session.headers.update({"X-API-KEY": self.api_key, "Accept": "application/json"})

    def login(self) -> None:
        if self.api_key:
            return
        if not self.username or not self.password:
            raise ValueError(f"Missing UniFi credentials for {self.name}")
        endpoints = ["/api/auth/login", "/api/login"]
        payload: dict[str, Any] = {"username": self.username, "password": self.password, "rememberMe": False}
        if self.mfa_secret:
            mfa_secret = "".join(self.mfa_secret.split())
            try:
                payload["token"] = pyotp.TOTP(mfa_secret).now()
            except binascii.Error as exc:
                raise ValueError(f"MFA secret for {self.name} must be a base32 TOTP seed.") from exc
        for endpoint in endpoints:
            response = self.session.post(
                f"{self.base_url}{endpoint}",
                json=payload,
                timeout=self.timeout,
                verify=self.verify_tls,
            )
            if response.status_code == 200:
                self._set_csrf_header()
                return
        raise RuntimeError(f"Unable to authenticate to UniFi controller {self.name}")

    def _set_csrf_header(self) -> None:
        token_cookie = self.session.cookies.get("TOKEN")
        if not token_cookie:
            return
        try:
            payload = token_cookie.split(".")[1]
            payload += "=" * (4 - len(payload) % 4)
            csrf = json.loads(base64.b64decode(payload)).get("csrfToken")
            if csrf:
                self.session.headers.update({"X-CSRF-Token": csrf})
        except Exception:
            logger.debug("Unable to decode UniFi CSRF token", exc_info=True)

    def get_json(self, endpoint: str, params: dict[str, Any] | None = None) -> Any:
        response = self.session.get(
            f"{self.base_url}{endpoint}",
            params=params,
            timeout=self.timeout,
            verify=self.verify_tls,
        )
        response.raise_for_status()
        data = response.json()
        if isinstance(data, dict) and data.get("meta", {}).get("rc") == "ok":
            return data.get("data", [])
        if isinstance(data, dict) and "data" in data:
            return data["data"]
        return data

    def sites(self) -> list[dict[str, Any]]:
        candidates = ["/proxy/network/api/self/sites", "/api/self/sites"]
        if self.api_key:
            candidates = ["/proxy/network/integration/v1/sites"]
        last_error: Exception | None = None
        for endpoint in candidates:
            try:
                if endpoint.endswith("/sites") and "integration" in endpoint:
                    return self._paginated_sites(endpoint)
                sites = self.get_json(endpoint)
                if isinstance(sites, list):
                    return sites
            except Exception as exc:
                last_error = exc
        if self.api_key:
            logger.warning("UniFi API key failed for %s; falling back to session login.", self.name)
            self.api_key = None
            self.session.headers.pop("X-API-KEY", None)
            self.login()
            return self.sites()
        raise RuntimeError(f"Unable to list UniFi sites for {self.name}: {last_error}")

    def _paginated_sites(self, endpoint: str) -> list[dict[str, Any]]:
        all_sites: list[dict[str, Any]] = []
        offset = 0
        while True:
            data = self.get_json(endpoint, params={"limit": 100, "offset": offset})
            if not isinstance(data, list):
                return all_sites
            all_sites.extend(data)
            if len(data) < 100:
                return all_sites
            offset += 100

    def devices(self, site: dict[str, Any]) -> list[dict[str, Any]]:
        for token in [site.get("name"), site.get("_id"), site.get("id")]:
            if not token:
                continue
            for endpoint in DEVICE_ENDPOINTS:
                try:
                    data = self.get_json(endpoint.format(site=token))
                    if isinstance(data, list):
                        return data
                except Exception:
                    logger.debug("Failed UniFi device lookup", exc_info=True)
        return []
