app_name = "example"
secret = "example"
version = "1.0"

from tenzoxauth import TenzoAuth

def main():
    auth = TenzoAuth(version, app_name, secret)

    if not auth.check_version():
        print(f"Version mismatch or application paused: {auth.get_last_status_message()}")
        input("Press Enter to exit...")
        return

    print("Welcome to TenzoAuth")
    print("1. Login")
    print("2. Register")
    choice = input("Enter your choice (1 or 2): ")

    while choice not in ["1", "2"]:
        choice = input("Invalid choice. Please enter 1 for Login or 2 for Register: ")

    if choice == "1":
        print("\n--- Login ---")
        username = input("Username: ")
        password = input("Password: ")

        if auth.login(username, password):
            print("\nLogin successful!")
            print(f"Username: {auth.get_current_username()}")
            print(f"Application: {auth.get_current_application()}")
            print(f"Expiry date: {auth.get_expiry_date()}")
        else:
            print(f"\nLogin failed: {auth.get_last_status_message()}")
    else:
        print("\n--- Register ---")
        username = input("Username: ")
        password = input("Password: ")
        license = input("License Key: ")

        if auth.register(username, password, license):
            print("\nRegistration successful!")
            print(f"Username: {auth.get_current_username()}")
            print(f"Application: {auth.get_current_application()}")
            print(f"Expiry date: {auth.get_expiry_date()}")
        else:
            print(f"\nRegistration failed: {auth.get_last_status_message()}")

    input("\nPress Enter to exit...")

if __name__ == "__main__":

    main()
