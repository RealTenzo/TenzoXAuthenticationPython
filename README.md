# TenzoXAuthenticationPython

**TenzoXAuthenticationPython** is a simple Python library for adding **authentication and licensing** functionality to your applications. It provides **login, registration, license validation, and version checking** features with just a few lines of code. Ideal for developers who want to secure their Python apps easily.

**Website:** [https://txabeta.netlify.app/](https://txabeta.netlify.app/)

## Features

* Login with username and password
* Registration with license keys
* Version checking to prevent outdated app usage
* Expiry date and user info retrieval
* Simple and clean Python integration

## Requirements

* **Python 3.8+**
* **requests** library

```bash
pip install requests
```

## Installation

1. Clone the repository:

```bash
git clone https://github.com/yourusername/TenzoXAuthenticationPython.git
```

2. Include `tenzo_auth.py` in your project.
3. Ensure the `requests` library is installed.

## Usage Example

```python
from tenzo_auth import TenzoAuth

# Initialize auth
auth = TenzoAuth(version="1.0", app_name="AppName", secret_key="SecretKey")

# Login
if auth.login("username", "password"):
    print(f"Login successful!\nUser: {auth.get_current_username()}\nExpiry: {auth.get_expiry_date()}")
else:
    print("Login failed:", auth.get_last_status_message())

# Register
if auth.register("username", "password", "license"):
    print(f"Registration successful!\nUser: {auth.get_current_username()}\nExpiry: {auth.get_expiry_date()}")
else:
    print("Registration failed:", auth.get_last_status_message())
```

## Notes

* Ensure your app version matches the version expected by the library.
* License keys can be pre-generated or dynamically created by your system.
* Works with both **CLI tools** and **GUI applications**.

## Credits

* Uses **requests** for secure API communication
* Developed by **Tenzo**

## Contributing

Contributions are welcome! Feel free to open issues or submit pull requests for improvements and new features.

## License

This project is licensed under the **TenzoXAuthenticationPython License** – see the [LICENSE](LICENSE) file for details.
