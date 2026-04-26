import base64
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
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


EMBEDDED_PUBLIC_KEY_PEM = """-----BEGIN PUBLIC KEY-----
MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAh3fjJEqt8/GbGNkhn9ws
8v7cStTdgEv2712vsJUhyJXS/hhG6wLcTHCk/hY/+jICvAF7lsSAMmz4Nwntp62B
cPj+OP6eWcX4WSSciK0O+i1qiF0QxXEFchvQCcUa3GVxrDLKFPB5/44ct+INqUV5
dZZYhZl39zQcs+2zvY3kJGvOafopGhsuedMh7eLkPP09lUAXnX30yOyU4G71MXut
mKo1V8M3F4O7G91s6bZLhxONOU6NhgSuykCM2u3hzP34nXC4uJe0Lx/8ENftWNwZ
3Qf3cuXcXCZJsWSzEhfYSZX5waQOUoE5qqqslygoCt40lCP7qk1Z9drP9C9losxy
f1vHTTismKkTnVHSZJRXu1wtYC79J8F3f8oG97uwo3p+p1LA+CdF1X69xSY0nFZu
QF1qxkOV4NUrcOXra+blw8FaowKahBBzjJeAzjoTa02DxexQSk2kDVvPmUrOv68U
L/i6HsvOzaC62R7mNOKiqaDB9bircvGj/BknhX5Etf5RAgMBAAE=
-----END PUBLIC KEY-----"""

TAMPER_MESSAGE = "Tamper detected. Access blocked."


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
    request_nonce: str = ""
    server_timestamp: str = ""
    signature: str = ""


@dataclass
class LoginResult:
    success: bool = False
    message: str = ""
    user: Optional[UserData] = None


@dataclass
class RegisterResult:
    success: bool = False
    message: str = ""


class TXA:
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
        self.public_key = serialization.load_pem_public_key(EMBEDDED_PUBLIC_KEY_PEM.encode("utf-8"))

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
        except Exception:
            self._show_error("Security Alert", TAMPER_MESSAGE)

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
        except Exception:
            self.response_message = TAMPER_MESSAGE
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
        except Exception:
            self.response_message = TAMPER_MESSAGE
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
        except Exception:
            self.response_message = TAMPER_MESSAGE
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
        except Exception:
            self.response_message = TAMPER_MESSAGE
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
        raise RuntimeError(TAMPER_MESSAGE)

    def _load_application_variables(self) -> bool:
        response = self._send_request("getvariables", {
            "secret": self.secret,
            "appName": self.app_name
        })
        if response.success and response.message != "NO_VARIABLES":
            self.variables = dict(response.variables or {})
            return True
        return False

    def _make_request_body(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        body = dict(payload)
        body["clientNonce"] = uuid.uuid4().hex.upper()
        body["clientTimestamp"] = str(int(time.time()))
        return body

    def _send_request(self, endpoint: str, payload: Dict[str, Any]) -> ApiResponse:
        body = self._make_request_body(payload)
        response = requests.post(
            f"{self.api_url}/{endpoint}",
            json=body,
            headers={
                "Content-Type": "application/json",
                "X-TXA-Nonce": body["clientNonce"],
                "X-TXA-Timestamp": body["clientTimestamp"]
            },
            timeout=30
        )

        data = response.json()
        parsed = ApiResponse(
            success=data.get("success", False),
            message=data.get("message", ""),
            username=data.get("username", ""),
            subscription=data.get("subscription", ""),
            expiry=data.get("expiry", ""),
            server_version=data.get("serverVersion", ""),
            value=data.get("value", ""),
            variables=data.get("variables", {}) or {},
            request_nonce=data.get("requestNonce", ""),
            server_timestamp=data.get("serverTimestamp", ""),
            signature=data.get("signature", "")
        )

        self._verify_response_signature(endpoint, body["clientNonce"], parsed)
        return parsed

    def _verify_response_signature(self, endpoint: str, client_nonce: str, response: ApiResponse):
        if response.request_nonce != client_nonce:
            raise RuntimeError(TAMPER_MESSAGE)
        if not response.server_timestamp or not response.signature:
            raise RuntimeError(TAMPER_MESSAGE)

        now = int(time.time())
        server_time = int(response.server_timestamp)
        if abs(now - server_time) > self.allowed_clock_skew_seconds:
            raise RuntimeError(TAMPER_MESSAGE)

        variable_lines = "\n".join(
            f"{k}={response.variables[k]}" for k in sorted(response.variables.keys())
        )
        if variable_lines:
            variable_lines += "\n"

        payload = (
            f"endpoint={self._sha256_hex(endpoint)}\n"
            f"requestNonce={self._sha256_hex(client_nonce)}\n"
            f"serverTimestamp={self._sha256_hex(response.server_timestamp)}\n"
            f"success={'1' if response.success else '0'}\n"
            f"message={self._sha256_hex(response.message)}\n"
            f"username={self._sha256_hex(response.username)}\n"
            f"subscription={self._sha256_hex(response.subscription)}\n"
            f"expiry={self._sha256_hex(response.expiry)}\n"
            f"serverVersion={self._sha256_hex(response.server_version)}\n"
            f"value={self._sha256_hex(response.value)}\n"
            f"variables={self._sha256_hex(variable_lines)}\n"
        ).encode("utf-8")

        try:
            self.public_key.verify(
                base64.b64decode(response.signature),
                payload,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
        except InvalidSignature:
            raise RuntimeError(TAMPER_MESSAGE)

    def _sha256_hex(self, value: str) -> str:
        return hashlib.sha256((value or "").encode("utf-8")).hexdigest().upper()

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
