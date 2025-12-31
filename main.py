from txa import TXA

def main():
    txa = TXA("tenzo", "6026bb04699ffdca3f4b8211c2c3d8d7", "1.0")
    
    txa.init()
    print(f"Initialization: {txa.response}")
    
    if txa.is_initialized:
        print(f"Variables loaded: {len(txa.variables)}")
        
        while True:
            print("\nTXA Authentication System")
            print("1. Login")
            print("2. Register")
            print("3. Get Variable")
            print("4. Refresh Variables")
            print("5. Check Status")
            print("6. Exit")
            
            choice = input("\nSelect option: ")
            
            if choice == "1":
                username = input("Username: ")
                password = input("Password: ")
                
                result = txa.login(username, password)
                if result.success:
                    print(f"Login successful! Welcome {result.user.username}")
                    print(f"Subscription: {result.user.subscription}")
                    print(f"Expiry: {result.user.expiry}")
                else:
                    print(f"Login failed: {result.message}")
                    
            elif choice == "2":
                username = input("Username: ")
                password = input("Password: ")
                license_key = input("License Key: ")
                
                result = txa.register(username, password, license_key)
                if result.success:
                    print("Registration successful!")
                else:
                    print(f"Registration failed: {result.message}")
                    
            elif choice == "3":
                var_name = input("Variable name: ")
                value = txa.get_variable(var_name)
                if value:
                    print(f"Value: {value}")
                else:
                    print(f"Failed: {txa.response}")
                    
            elif choice == "4":
                if txa.refresh_variables():
                    print("Variables refreshed successfully")
                else:
                    print(f"Failed: {txa.response}")
                    
            elif choice == "5":
                print(f"Initialized: {txa.is_initialized}")
                print(f"Logged in: {txa.is_logged_in}")
                print(f"App active: {txa.is_application_active}")
                print(f"Version correct: {txa.is_version_correct}")
                print(f"Server version: {txa.server_version}")
                if txa.is_logged_in and txa.user:
                    print(f"User: {txa.user.username}")
                    print(f"Subscription: {txa.user.subscription}")
                    
            elif choice == "6":
                print("Goodbye!")
                break
                
            else:
                print("Invalid choice")

if __name__ == "__main__":
    main()
