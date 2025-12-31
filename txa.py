import json
import uuid
import hashlib
import requests
import subprocess
import platform
import sys
import os
from typing import Dict, Optional, Tuple, Any

class TXA:
    class UserData:
        def __init__(self):
            self.username = ""
            self.subscription = ""
            self.expiry = ""

    class ApiResponse:
        def __init__(self):
            self.success = False
            self.message = ""
            self.username = ""
            self.subscription = ""
            self.expiry = ""
            self.server_version = ""
            self.value = ""
            self.variables = {}

    class LoginResult:
        def __init__(self):
            self.success = False
            self.message = ""
            self.user = None

    class RegisterResult:
        def __init__(self):
            self.success = False
            self.message = ""

    def __init__(self, name: str, secret: str, version: str):
        self.app_name = name
        self.secret = secret
        self.version = version
        self.api_url = "https://tenxoxauthentication.qzz.io"
        self.is_initialized = False
        self.is_logged_in = False
        self.user = None
        self.response_message = ""
        self.variables = {}
        self.is_application_active = False
        self.is_version_correct = False
        self.server_version = ""

    def __getitem__(self, name: str) -> str:
        return self.var(name)

    @property
    def response(self) -> str:
        return self.response_message

    def init(self):
        if not self.app_name or not self.secret or not self.version:
            self._show_error("TXA Auth Error", "AppName/Secret/Version missing")
            sys.exit(0)

        try:
            paused = self._check_if_paused()
            if paused:
                self._show_error("Application Paused", "Application is currently paused by administrator")
                sys.exit(0)

            self.is_application_active = not paused

            version_check = self._check_version_with_details()
            self.is_version_correct = version_check[0]
            self.server_version = version_check[1]

            if not self.is_version_correct:
                self._show_error(
                    "Update Required",
                    f"Version mismatch!\n\nYour version: {self.version}\nServer version: {self.server_version}\n\nPlease update to the latest version."
                )
                sys.exit(0)

            self._load_application_variables()

            self.is_initialized = True
            self.response_message = "TXA SDK Initialized successfully!"
            
        except Exception as ex:
            self._show_error("Init Error", f"Initialization failed: {ex}")
            sys.exit(0)

    def _show_error(self, title: str, message: str):
        os.system('cls' if os.name == 'nt' else 'clear')
        
        border = "═" * 70
        print(f"\n╔{border}╗")
        print(f"║ {title.ljust(69)} ║")
        print(f"╠{border}╣")
        
        lines = message.split('\n')
        for line in lines:
            print(f"║ {line.ljust(69)} ║")
        
        print(f"╚{border}╝")
        print("\nPress any key to exit...")
        
        if os.name == 'nt':
            import msvcrt
            msvcrt.getch()
        else:
            import termios, tty
            fd = sys.stdin.fileno()
            old_settings = termios.tcgetattr(fd)
            try:
                tty.setraw(sys.stdin.fileno())
                sys.stdin.read(1)
            finally:
                termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
        
        sys.exit(0)

    def login(self, username: str, password: str) -> LoginResult:
        self.response_message = ""
        login_result = self.LoginResult()

        if not self.is_initialized:
            self.response_message = "Error: Call TXA.Init() first"
            login_result.success = False
            login_result.message = self.response_message
            return login_result

        try:
            hwid = self._get_hwid()
            
            payload = {
                "username": username,
                "password": password,
                "secret": self.secret,
                "appName": self.app_name,
                "appVersion": self.version,
                "hwid": hwid
            }
            
            response = self._send_request("login", payload)
            
            if response.success:
                self.is_logged_in = True
                self.user = self.UserData()
                self.user.username = response.username
                self.user.subscription = response.subscription
                self.user.expiry = response.expiry
                
                self._load_user_variables()
                self.response_message = f"Login successful! Welcome, {self.user.username}"
                
                login_result.success = True
                login_result.message = self.response_message
                login_result.user = self.user
                return login_result
            else:
                self.response_message = self._format_error_message(response.message, "login")
                login_result.success = False
                login_result.message = self.response_message
                return login_result
                
        except Exception as ex:
            self.response_message = f"Connection error: {ex}"
            login_result.success = False
            login_result.message = self.response_message
            return login_result

    def register(self, username: str, password: str, license_key: str) -> RegisterResult:
        self.response_message = ""
        register_result = self.RegisterResult()

        if not self.is_initialized:
            self.response_message = "Error: Call TXA.Init() first"
            register_result.success = False
            register_result.message = self.response_message
            return register_result

        try:
            hwid = self._get_hwid()
            
            payload = {
                "username": username,
                "password": password,
                "licenseKey": license_key,
                "secret": self.secret,
                "appName": self.app_name,
                "appVersion": self.version,
                "hwid": hwid
            }
            
            response = self._send_request("register", payload)
            
            if response.success:
                self.response_message = "Registration successful! You can login now"
                register_result.success = True
                register_result.message = self.response_message
                return register_result
            else:
                self.response_message = self._format_error_message(response.message, "register")
                register_result.success = False
                register_result.message = self.response_message
                return register_result
                
        except Exception as ex:
            self.response_message = f"Connection error: {ex}"
            register_result.success = False
            register_result.message = self.response_message
            return register_result

    def var(self, var_name: str) -> str:
        return self.variables.get(var_name, "VARIABLE_NOT_FOUND")

    def get(self, var_name: str, default: Any = None) -> Any:
        value = self.var(var_name)
        if value == "VARIABLE_NOT_FOUND":
            return default
        
        try:
            if value.lower() == "true":
                return True
            elif value.lower() == "false":
                return False
            elif value.isdigit():
                return int(value)
            elif value.replace('.', '', 1).isdigit():
                return float(value)
            else:
                return value
        except:
            return default

    def get_variable(self, var_name: str) -> Optional[str]:
        self.response_message = ""

        if not self.is_initialized:
            self.response_message = "Error: Call TXA.Init() first"
            return None

        if var_name in self.variables:
            self.response_message = f"Variable '{var_name}' retrieved from cache"
            return self.variables[var_name]

        try:
            payload = {
                "secret": self.secret,
                "appName": self.app_name,
                "appVersion": self.version,
                "varName": var_name
            }
            
            response = self._send_request("getvariable", payload)
            
            if response.success and response.value:
                self.variables[var_name] = response.value
                self.response_message = f"Variable '{var_name}' retrieved successfully"
                return response.value
            else:
                if response.message == "VARIABLE_NOT_FOUND":
                    self.response_message = f"Variable '{var_name}' not found"
                else:
                    self.response_message = f"Failed to get variable '{var_name}': {response.message}"
                return None
                
        except Exception as ex:
            self.response_message = f"Connection error: {ex}"
            return None

    def refresh_variables(self) -> bool:
        self.response_message = ""

        if not self.is_initialized:
            self.response_message = "Error: Call TXA.Init() first"
            return False

        try:
            result = self._load_application_variables()
            if result:
                self.response_message = f"Successfully refreshed {len(self.variables)} variables"
                return True
            else:
                self.response_message = "No variables found or failed to load"
                return False
                
        except Exception as ex:
            self.response_message = f"Failed to refresh variables: {ex}"
            return False

    def _check_if_paused(self) -> bool:
        try:
            payload = {
                "secret": self.secret,
                "appName": self.app_name
            }
            
            response = requests.post(
                f"{self.api_url}/isapplicationpaused",
                json=payload,
                headers={'Content-Type': 'application/json'}
            )
            
            if response.status_code == 200:
                data = response.json()
                return data.get('success', False) and data.get('message') == "APPLICATION_PAUSED"
                
        except Exception:
            pass
        return False

    def _check_version_with_details(self) -> Tuple[bool, str]:
        try:
            payload = {
                "secret": self.secret,
                "appName": self.app_name,
                "appVersion": self.version
            }
            
            response = requests.post(
                f"{self.api_url}/versioncheck",
                json=payload,
                headers={'Content-Type': 'application/json'}
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('success') and data.get('message') == "VERSION_OK":
                    return True, self.version
                elif data.get('message') == "VERSION_MISMATCH":
                    return False, data.get('serverVersion', 'Unknown')
                    
        except Exception:
            pass
        return False, "Error"

    def _load_application_variables(self) -> bool:
        try:
            payload = {
                "secret": self.secret,
                "appName": self.app_name
            }
            
            response = requests.post(
                f"{self.api_url}/getvariables",
                json=payload,
                headers={'Content-Type': 'application/json'}
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('success') and data.get('message') != "NO_VARIABLES" and data.get('variables'):
                    self.variables.clear()
                    self.variables.update(data['variables'])
                    return len(self.variables) > 0
                    
        except Exception:
            pass
        return False

    def _load_user_variables(self):
        if self.is_logged_in and self.user:
            self.get_variable(f"user_{self.user.username}_settings")
            self.get_variable(f"permissions_{self.user.subscription}")

    def _get_hwid(self) -> str:
        try:
            if platform.system() == "Windows":
                try:
                    import winreg
                    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                                       r"SOFTWARE\Microsoft\Cryptography")
                    value, _ = winreg.QueryValueEx(key, "MachineGuid")
                    return value
                except:
                    pass
            elif platform.system() == "Linux":
                try:
                    with open("/etc/machine-id", "r") as f:
                        return f.read().strip()
                except:
                    pass
            elif platform.system() == "Darwin":
                try:
                    output = subprocess.check_output(
                        ["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"]
                    ).decode()
                    for line in output.split("\n"):
                        if "IOPlatformUUID" in line:
                            return line.split('"')[-2]
                except:
                    pass
            
            hostname = platform.node()
            return str(uuid.uuid5(uuid.NAMESPACE_DNS, hostname))
            
        except Exception:
            return "HWID_FAIL"

    def _send_request(self, endpoint: str, payload: Dict) -> ApiResponse:
        response_obj = self.ApiResponse()
        
        try:
            response = requests.post(
                f"{self.api_url}/{endpoint}",
                json=payload,
                headers={'Content-Type': 'application/json'},
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                response_obj.success = data.get('success', False)
                response_obj.message = data.get('message', '')
                response_obj.username = data.get('username', '')
                response_obj.subscription = data.get('subscription', '')
                response_obj.expiry = data.get('expiry', '')
                response_obj.server_version = data.get('serverVersion', '')
                response_obj.value = data.get('value', '')
                response_obj.variables = data.get('variables', {})
                
        except requests.exceptions.RequestException as ex:
            response_obj.success = False
            response_obj.message = f"Network error: {ex}"
        except Exception as ex:
            response_obj.success = False
            response_obj.message = f"Request failed: {ex}"
            
        return response_obj

    def _format_error_message(self, error_message: str, operation: str) -> str:
        if not error_message:
            return f"{operation} failed"
        
        upper_msg = error_message.upper()
        
        if operation == "login":
            if "INVALID_CREDENTIALS" in upper_msg or "INVALID USERNAME OR PASSWORD" in upper_msg:
                return "Invalid username or password"
            if "HWID_RESET" in upper_msg or "HWID_MISMATCH" in upper_msg:
                return "HWID mismatch. Please contact support to reset your HWID"
            if "BANNED" in upper_msg or "SUSPENDED" in upper_msg:
                return "Account has been banned or suspended"
            if "EXPIRED" in upper_msg:
                return "Subscription has expired"
            if "MAX_DEVICES" in upper_msg:
                return "Maximum number of devices reached"
                
        elif operation == "register":
            if "INVALID_LICENSE" in upper_msg:
                return "Invalid license key"
            if "USERNAME_TAKEN" in upper_msg:
                return "Username is already taken"
            if "LICENSE_USED" in upper_msg:
                return "License key has already been used"
            if "LICENSE_EXPIRED" in upper_msg:
                return "License key has expired"
            if "WEAK_PASSWORD" in upper_msg:
                return "Password is too weak. Please use a stronger password"
            if "INVALID_USERNAME" in upper_msg:
                return "Invalid username format"
        
        return f"{operation} failed: {error_message}"

    def debug_version_check(self) -> str:
        try:
            payload = {
                "secret": self.secret,
                "appName": self.app_name,
                "appVersion": self.version
            }
            
            response = requests.post(
                f"{self.api_url}/versioncheck",
                json=payload,
                headers={'Content-Type': 'application/json'}
            )
            
            return response.text
            
        except Exception as ex:
            return f"Error: {ex}"
