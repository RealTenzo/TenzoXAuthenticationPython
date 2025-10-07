import json
import subprocess
from datetime import datetime
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Disable SSL warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class Messages:
    AppOrSecretEmpty = "Application name or secret key cannot be empty."
    AppDataNotFound = "Application data not found."
    AppPaused = "Application is paused."
    VersionMismatch = "Version mismatch."
    ErrorParsingAppData = "Error parsing application data."
    NotLoggedIn = "Not logged in."
    AppNotFound = "Application not found."
    UserNotFound = "User not found."
    UserBanned = "User is banned."
    InvalidPassword = "Invalid password."
    SubscriptionExpired = "Subscription expired."
    HwidMismatch = "HWID mismatch."
    LoginSuccessful = "Login successful."
    MissingCredentials = "Missing credentials."
    UsernameExists = "Username already exists."
    InvalidLicense = "Invalid license {}"
    LicenseUsed = "License {} already used."
    LicenseExpired = "License {} expired."
    FailedCreateUser = "Failed to create user."
    FailedUpdateLicense = "Failed to update license {}."
    RegistrationSuccessful = "Registration successful."
    ErrorDuringRegistration = "Error during registration."
    InvalidExpiryFormat = "Invalid expiry date format."

class TenzoAuth:
    def __init__(self, version, app, secret):
        self.current_version = version
        self.default_app = app
        self.default_secret = secret
        self.current_hwid = self.get_hwid()
        self.current_username = None
        self.current_application = None
        self.current_secret = None
        self.last_status_message = None
        self.last_login_success = False
        self.api_base = self.get_api()
        if not app or not secret:
            self.last_status_message = Messages.AppOrSecretEmpty

    @staticmethod
    def get_api():
        key = b'tenzo'
        ebyte = (
            b'\x1c\x11\x1a\x0a\x1c\x4e\x4a\x41\x0a\x1d\x1b\x0f\x0b\x19\x1b'
            b'\x59\x07\x0a\x57\x59\x4d\x5d\x5e\x49\x42\x10\x00\x08\x1b\x1a'
            b'\x18\x11\x43\x08\x1b\x10\x07\x40\x1b\x1c\x1d\x04\x43\x09\x00'
            b'\x01\x11\x06\x1f\x0e\x07\x11\x5f\x54\x09\x1d\x17\x0b\x18\x0e'
            b'\x07\x00\x0a\x1b\x1b\x15\x07\x0f\x09\x0a\x5a\x04\x1e\x0a'
        )
        decrypted = bytes(e ^ key[i % len(key)] for i, e in enumerate(ebyte))
        return decrypted.decode('utf-8')

    @staticmethod
    def to_lower(s):
        return s.lower() if s else ''

    @staticmethod
    def get_hwid():
        try:
            result = subprocess.check_output(
                ['powershell', '-Command', '[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value'],
                shell=True,
                stderr=subprocess.DEVNULL
            )
            return result.decode('utf-8').strip()
        except:
            return "UNKNOWN"

    def http_get(self, url):
        try:
            response = requests.get(url, timeout=10, verify=False)
            return response.text if response.status_code == 200 else ''
        except:
            return ''

    def http_put(self, url, data):
        try:
            response = requests.put(url, json=data, timeout=10, verify=False)
            return response.status_code == 200
        except:
            return False

    def http_delete(self, url):
        try:
            response = requests.delete(url, timeout=10, verify=False)
            return response.status_code == 200
        except:
            return False

    def check_application_version(self, application, secret):
        if not application or not secret:
            self.last_status_message = Messages.AppOrSecretEmpty
            return False

        url = f"{self.api_base}/applications/{secret}/{application}.json"
        json_str = self.http_get(url)

        if not json_str or json_str == 'null':
            self.last_status_message = Messages.AppDataNotFound
            return False

        try:
            app_data = json.loads(json_str)
            if app_data.get('applicationPaused', False):
                self.last_status_message = Messages.AppPaused
                return False

            fetched_version = str(app_data.get('version', '')).strip()
            if fetched_version != self.current_version:
                self.last_status_message = Messages.VersionMismatch
                return False

            return True
        except:
            self.last_status_message = Messages.ErrorParsingAppData
            return False

    def is_date_expired(self, expiry):
        if expiry == "lifetime":
            return False

        try:
            if expiry.endswith("Z"):
                expiry = expiry[:-1]
            dot_pos = expiry.find('.')
            if dot_pos >= 0:
                expiry = expiry[:dot_pos]

            expiry_time = datetime.strptime(expiry, "%Y-%m-%dT%H:%M:%S")
            return expiry_time < datetime.utcnow()
        except:
            self.last_status_message = Messages.InvalidExpiryFormat
            return True

    def check_version(self, application=None, secret=None):
        app = application or self.default_app
        sec = secret or self.default_secret
        return self.check_application_version(app, sec)

    def get_expiry_date(self):
        if not self.is_logged_in():
            self.last_status_message = Messages.NotLoggedIn
            return ""

        username_lower = self.to_lower(self.current_username)
        url = f"{self.api_base}/applications/{self.current_secret}/{self.current_application}/users/{username_lower}/expiry.json"
        json_str = self.http_get(url)

        if not json_str or json_str == 'null':
            return "lifetime"

        try:
            expiry = json.loads(json_str)
            return "lifetime" if expiry is None else expiry
        except:
            return "lifetime"

    def _login(self, application, secret, username, password):
        self.last_login_success = False
        app_url = f"{self.api_base}/applications/{secret}/{application}.json"
        app_json = self.http_get(app_url)

        if not app_json or app_json == 'null':
            self.last_status_message = Messages.AppNotFound
            return False

        try:
            app_data = json.loads(app_json)
        except:
            app_data = {}

        if app_data.get('applicationPaused', False):
            self.last_status_message = Messages.AppPaused
            return False

        fetched_version = str(app_data.get('version', '')).strip()
        if fetched_version != self.current_version:
            self.last_status_message = Messages.VersionMismatch
            return False

        username_lower = self.to_lower(username)
        url = f"{self.api_base}/applications/{secret}/{application}/users/{username_lower}.json"
        json_str = self.http_get(url)

        if not json_str or json_str == 'null':
            self.last_status_message = Messages.UserNotFound
            return False

        try:
            user = json.loads(json_str)
        except:
            user = {}

        if user.get('isBanned', False):
            self.last_status_message = Messages.UserBanned
            return False

        if user.get('password') != password:
            self.last_status_message = Messages.InvalidPassword
            return False

        expiry = user.get('expiry', 'lifetime')
        if self.is_date_expired(expiry):
            self.last_status_message = Messages.SubscriptionExpired
            return False

        hwid_lock = user.get('hwidLock', False)
        sid = user.get('sid', '')

        if not hwid_lock or not sid or sid == self.current_hwid:
            if hwid_lock and not sid:
                update_data = {
                    'password': password,
                    'expiry': expiry,
                    'hwidLock': hwid_lock,
                    'sid': self.current_hwid
                }
                if 'oneTime' in user:
                    update_data['oneTime'] = user['oneTime']
                self.http_put(url, update_data)

            self.current_username = username
            self.current_application = application
            self.current_secret = secret
            self.last_status_message = Messages.LoginSuccessful
            self.last_login_success = True

            if user.get('oneTime', False):
                self.http_delete(url)

            return True

        self.last_status_message = Messages.HwidMismatch
        return False

    def login(self, username, password):  # Overload for default app/secret
        return self._login(self.default_app, self.default_secret, username, password)

    def register(self, username, password, license_key):
        self.last_login_success = False
        username_lower = self.to_lower(username)
        license_key = license_key.strip()

        if not all([username, password, license_key]):
            self.last_status_message = Messages.MissingCredentials
            return False

        if not self.check_version():
            return False

        user_url = f"{self.api_base}/applications/{self.default_secret}/{self.default_app}/users/{username_lower}.json"
        user_json = self.http_get(user_url)
        if user_json and user_json != 'null':
            self.last_status_message = Messages.UsernameExists
            return False

        license_url = f"{self.api_base}/applications/{self.default_secret}/{self.default_app}/licenses/{license_key}.json"
        license_json = self.http_get(license_url)
        if not license_json or license_json == 'null':
            self.last_status_message = Messages.InvalidLicense.format(license_key)
            return False

        try:
            license_data = json.loads(license_json)
        except:
            license_data = {}

        if license_data.get('used', False):
            self.last_status_message = Messages.LicenseUsed.format(license_key)
            return False

        expiry = license_data.get('expiry', 'lifetime')
        if self.is_date_expired(expiry):
            self.last_status_message = Messages.LicenseExpired.format(license_key)
            return False

        one_time_use = license_data.get('oneTime', False)

        user_data = {
            'password': password,
            'expiry': expiry,
            'hwidLock': True,
            'sid': self.current_hwid,
            'isBanned': False,
            'createdAt': datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S')
        }
        if one_time_use:
            user_data['oneTime'] = True

        if not self.http_put(user_url, user_data):
            self.last_status_message = Messages.FailedCreateUser
            return False

        license_update = {
            'used': True,
            'associatedUser': username_lower,
            'expiry': expiry
        }
        if 'displayName' in license_data:
            license_update['displayName'] = license_data['displayName']

        if not self.http_put(license_url, license_update):
            self.http_delete(user_url)
            self.last_status_message = Messages.FailedUpdateLicense.format(license_key)
            return False

        if one_time_use:
            self.http_delete(license_url)

        self.current_username = username
        self.current_application = self.default_app
        self.current_secret = self.default_secret
        self.last_status_message = Messages.RegistrationSuccessful
        self.last_login_success = True
        return True

    def get_last_status_message(self):
        return self.last_status_message

    def get_last_login_success(self):
        return self.last_login_success

    def get_current_username(self):
        return self.current_username

    def get_current_application(self):
        return self.current_application

    def is_logged_in(self):
        return bool(self.current_username and self.current_application)

    def get_current_version(self):
        return self.current_version
