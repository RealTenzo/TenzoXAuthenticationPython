import hashlib
import json
import os
import platform
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Tuple

import requests

@dataclass
class UserData:
    username: str = ""
    subscription: str = ""
    expiry: str = ""


@dataclass
class ApiResponse:
    success: bool = False
    message: str = ""
    username: str = ""
    subscription: str = ""
    expiry: str = ""
    server_version: str = ""
    value: str = ""
    variables: Dict[str, str] = field(default_factory=dict)
class LoginResult:
    success: bool = False
    message: str = ""
    user: Optional[UserData] = None


@dataclass
class RegisterResult:
    success: bool = False
    message: str = ""


class TXA:
    PINNED_CERT_SHA256 = "DB:42:42:C4:90:3E:47:7D:F2:76:29:33:7C:68:EA:BA:B5:31:28:CA:2B:C4:EB:48:2B:40:79:00:C9:4D:95:ED"

    def __init__(self, name: str, secret: str, version: str):
        self.app_name = name
        self.secret = secret
        self.version = version
        self.api_url = "https://tenxoxauthentication.qzz.io"
        self.is_initialized = False
        self.is_logged_in = False
        self.user: Optional[UserData] = None
        self.response_message = ""
        self.variables: Dict[str, str] = {}
        self.is_application_active = False
        self.is_version_correct = False
        self.server_version = ""
        self.allowed_clock_skew_seconds = 120

    def __getitem__(self, name: str) -> str:
        return self.var(name)

    @property
    def response(self) -> str:
        return self.response_message

    def init(self):
        if not self.app_name or not self.secret or not self.version:
            self._show_error("TXA Auth Error", "AppName/Secret/Version missing")

        try:
            paused = self._check_if_paused()
            if paused:
                self._show_error("Application Paused", "Application is currently paused by administrator")

            self.is_application_active = not paused
            version_check = self._check_version_with_details()
            self.is_version_correct, self.server_version = version_check

            if not self.is_version_correct:
                self._show_error(
                    "Update Required",
                    f"Version mismatch!\n\nYour version: {self.version}\nServer version: {self.server_version}\n\nPlease update to the latest version."
                )

            self._load_application_variables()
            self.is_initialized = True
            self.response_message = "TXA SDK initialized with signed-response verification."
        except Exception as exc:
            self._show_error("Initialization Failed", str(exc) or "Initialization failed")

    def login(self, username: str, password: str) -> LoginResult:
        result = LoginResult()
        if not self.is_initialized:
            self.response_message = "Error: Call TXA.Init() first"
            result.message = self.response_message
            return result

        try:
            response = self._send_request("login", {
                "username": username,
                "password": password,
                "secret": self.secret,
                "appName": self.app_name,
                "appVersion": self.version,
                "hwid": self._get_hwid()
            })

            if not response.success:
                self.response_message = self._format_error_message(response.message, "login")
                result.message = self.response_message
                return result

            self.is_logged_in = True
            self.user = UserData(response.username, response.subscription, response.expiry)
            self.response_message = f"Login successful! Welcome, {self.user.username}"
            result.success = True
            result.message = self.response_message
            result.user = self.user
            return result
        except Exception as exc:
            self.response_message = str(exc) or "Login failed"
            result.message = self.response_message
            return result

    def register(self, username: str, password: str, license_key: str) -> RegisterResult:
        result = RegisterResult()
        if not self.is_initialized:
            self.response_message = "Error: Call TXA.Init() first"
            result.message = self.response_message
            return result

        try:
            response = self._send_request("register", {
                "username": username,
                "password": password,
                "licenseKey": license_key,
                "secret": self.secret,
                "appName": self.app_name,
                "appVersion": self.version,
                "hwid": self._get_hwid()
            })

            if not response.success:
                self.response_message = self._format_error_message(response.message, "register")
                result.message = self.response_message
                return result

            self.response_message = "Registration successful! You can login now"
            result.success = True
            result.message = self.response_message
            return result
        except Exception as exc:
            self.response_message = str(exc) or "Registration failed"
            result.message = self.response_message
            return result

    def var(self, var_name: str) -> str:
        return self.variables.get(var_name, "VARIABLE_NOT_FOUND")

    def get_variable(self, var_name: str) -> Optional[str]:
        if not self.is_initialized:
            self.response_message = "Error: Call TXA.Init() first"
            return None

        if var_name in self.variables:
            self.response_message = f"Variable '{var_name}' retrieved from cache"
            return self.variables[var_name]

        try:
            response = self._send_request("getvariable", {
                "secret": self.secret,
                "appName": self.app_name,
                "appVersion": self.version,
                "varName": var_name
            })

            if response.success and response.value:
                self.variables[var_name] = response.value
                self.response_message = f"Variable '{var_name}' retrieved successfully"
                return response.value

            self.response_message = f"Failed to get variable '{var_name}': {response.message}"
            return None
        except Exception as exc:
            self.response_message = str(exc) or "Variable request failed"
            return None

    def refresh_variables(self) -> bool:
        if not self.is_initialized:
            self.response_message = "Error: Call TXA.Init() first"
            return False

        try:
            if not self._load_application_variables():
                self.response_message = "No variables found or failed to load"
                return False

            self.response_message = f"Successfully refreshed {len(self.variables)} variables"
            return True
        except Exception as exc:
            self.response_message = str(exc) or "Variable refresh failed"
            return False

    def _check_if_paused(self) -> bool:
        response = self._send_request("isapplicationpaused", {
            "secret": self.secret,
            "appName": self.app_name
        })
        return response.success and response.message == "APPLICATION_PAUSED"

    def _check_version_with_details(self) -> Tuple[bool, str]:
        response = self._send_request("versioncheck", {
            "secret": self.secret,
            "appName": self.app_name,
            "appVersion": self.version
        })

        if response.success and response.message == "VERSION_OK":
            return True, self.version
        if response.message == "VERSION_MISMATCH":
            return False, response.server_version or "Unknown"
        raise RuntimeError(response.message or "Version check failed")

    def _load_application_variables(self) -> bool:
        response = self._send_request("getvariables", {
            "secret": self.secret,
            "appName": self.app_name
        })
        if response.success and response.message != "NO_VARIABLES":
            self.variables = dict(response.variables or {})
            return True
        return False

    def _send_request(self, endpoint: str, payload: Dict[str, Any]) -> ApiResponse:
        body = dict(payload)
        response = requests.post(
            f"{self.api_url}/{endpoint}",
            json=body,
            headers={"Content-Type": "application/json"},
            timeout=30,
            stream=True
        )

        try:
            self._verify_response_certificate(response)
            data = response.json()
            return ApiResponse(
                success=data.get("success", False),
                message=data.get("message", ""),
                username=data.get("username", ""),
                subscription=data.get("subscription", ""),
                expiry=data.get("expiry", ""),
                server_version=data.get("serverVersion", ""),
                value=data.get("value", ""),
                variables=data.get("variables", {}) or {}
            )
        finally:
            response.close()

    def _verify_response_certificate(self, response: requests.Response) -> None:
        cert_der = self._extract_peer_certificate(response)
        cert_der_hash = hashlib.sha256(cert_der).hexdigest().upper()
        fingerprint = ":".join(
            cert_der_hash[i:i + 2]
            for i in range(0, len(cert_der_hash), 2)
        )

        if fingerprint != self.PINNED_CERT_SHA256:
            raise RuntimeError("Tamper detected. Access blocked.")

    def _extract_peer_certificate(self, response: requests.Response) -> bytes:
        raw = response.raw
        connection = getattr(raw, "connection", None) or getattr(raw, "_connection", None)
        sock = getattr(connection, "sock", None)

        if sock is None:
            fp = getattr(raw, "_fp", None)
            if fp is not None:
                sock = getattr(getattr(getattr(fp, "fp", None), "raw", None), "_sock", None)

        if sock is None:
            raise RuntimeError("Tamper detected. Access blocked.")

        cert_der = sock.getpeercert(binary_form=True)
        if not cert_der:
            raise RuntimeError("Tamper detected. Access blocked.")

        return cert_der

    def _get_hwid(self) -> str:
        try:
            if platform.system() == "Windows":
                try:
                    output = subprocess.check_output(
                        ["whoami", "/user"],
                        stderr=subprocess.STDOUT,
                        text=True,
                        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)
                    )
                    for line in output.splitlines():
                        line = line.strip()
                        if line.startswith("S-1-"):
                            return line.split()[-1]
                except Exception:
                    pass
                try:
                    import winreg
                    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography")
                    value, _ = winreg.QueryValueEx(key, "MachineGuid")
                    return value
                except Exception:
                    pass
            elif platform.system() == "Linux":
                try:
                    with open("/etc/machine-id", "r", encoding="utf-8") as f:
                        return f.read().strip()
                except Exception:
                    pass
            elif platform.system() == "Darwin":
                try:
                    output = subprocess.check_output(["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"]).decode()
                    for line in output.split("\n"):
                        if "IOPlatformUUID" in line:
                            return line.split('"')[-2]
                except Exception:
                    pass
            return str(uuid.uuid5(uuid.NAMESPACE_DNS, platform.node()))
        except Exception:
            return "HWID_FAIL"

    def _format_error_message(self, error_message: str, operation: str) -> str:
        upper_msg = (error_message or "").upper()
        if operation == "login":
            if "INVALID_CREDENTIALS" in upper_msg:
                return "Invalid username or password"
            if "HWID_MISMATCH" in upper_msg:
                return "HWID mismatch. Please contact support to reset your HWID"
            if "BANNED" in upper_msg or "SUSPENDED" in upper_msg:
                return "Account has been banned or suspended"
            if "EXPIRED" in upper_msg:
                return "Subscription has expired"
        if operation == "register":
            if "INVALID_LICENSE" in upper_msg:
                return "Invalid license key"
            if "USERNAME_TAKEN" in upper_msg:
                return "Username is already taken"
            if "LICENSE_USED" in upper_msg:
                return "License key has already been used"
            if "LICENSE_EXPIRED" in upper_msg:
                return "License key has expired"
        return f"{operation} failed: {error_message}"

    def _show_error(self, title: str, message: str):
        os.system('cls' if os.name == 'nt' else 'clear')
        border = "=" * 70
        print(f"\n[{border}]")
        print(f"[ {title.ljust(69)} ]")
        print(f"[{border}]")
        for line in message.split("\n"):
            print(f"[ {line.ljust(69)} ]")
        print(f"[{border}]")
        print("\nPress any key to exit...")
        if os.name == 'nt':
            import msvcrt
            msvcrt.getch()
        else:
            input()
        sys.exit(0)
