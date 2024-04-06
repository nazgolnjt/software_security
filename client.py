import re
import requests

current_user = None
BASE_URL = "http://127.0.0.1:5000"

# Account Functions  
def register():
    username = input("Enter username: ")
    password = input("Enter password: ")
    if check_password(password):
        response = requests.post(f'{BASE_URL}/register', json={"username": username, "password": password})
        if response.status_code == 200:
            print(response.json())
            customer_menu()
    else:
        print('Password must contain 3 lower-case, 3 upper-case, 3 digits and 3 symbols.')

def login():
    username = input("Enter username: ")
    password = input("Enter password: ")
    response = requests.post(f"{BASE_URL}/login", json={"username": username, "password": password})
    global current_user
    current_user = username
    response_json = response.json()
    if response_json['role'] == 'admin':
        print(response_json['message'])
        admin_menu()
    elif response_json['role'] == 'user':
        print(response_json['message'])
        user_menu()
    elif response_json['role'] == 'customer':
        print(response_json['message'])
        customer_menu()
    else:
        print(response_json['message'])

def check_password(password):
    lower_pattern = r'[a-z]'
    upper_pattern = r'[A-Z]'
    digit_pattern = r'\d'
    symbol_pattern = r'[!@#$%^&*()]'

    lower_count = len(re.findall(lower_pattern, password))
    upper_count = len(re.findall(upper_pattern, password))
    digit_count = len(re.findall(digit_pattern, password))
    symbol_count = len(re.findall(symbol_pattern, password))

    if lower_count >= 3 and upper_count >= 3 and digit_count >= 3 and symbol_count >= 3:
        return True
    else:
        return False

def change_password():
    global current_user
    username = current_user
    old_password = input("Enter old password: ")
    new_password = input("Enter new password: ")
    if check_password(new_password):
        response = requests.post(f"{BASE_URL}/change_password", json={"username": username, "old_password": old_password, "new_password": new_password})
        print(response.json())
    else:
        print('Password must contain 3 lower-case, 3 upper-case, 3 digits and 3 symbols.')

# Admin Functions
def add_user():
    username = input("Enter username: ")
    password = input("Enter password: ")
    if check_password(password):
        response = requests.post(f"{BASE_URL}/add_user", json={"username": username, "password": password})
        print(response.json())
    else:
        print('Password must contain 3 lower-case, 3 upper-case, 3 digits and 3 symbols.')


def view_feedbacks():
    response = requests.get(f"{BASE_URL}/view_feedbacks")
    if response.status_code == 200:
        feedbacks = response.json()
        if feedbacks:
            print("Feedbacks:")
            for fb in feedbacks:
                print(f"\nUsername: {fb['username']}\nContent: {fb['content']}")
        else:
            print("No feedback available.")
    else:
        print("Failed to retrieve feedback. Status Code:", response.status_code)

# Admin/User Functions
def add_product():
    name = input("Enter product name: ")
    price = input("Enter product price: ")
    quantity = input("Enter product quantity: ")
    response = requests.post(f"{BASE_URL}/add_product", json={"name": name, "price": price, "quantity": quantity})
    print(response.json())

# Customer Functions
def view_products():
    response = requests.get(f"{BASE_URL}/view_products")
    if response.status_code == 200:
        products = response.json()['products']
        if products:
            print("Available Products:")
            for product in products:
                print(f"ID: {product['id']}, Name: {product['name']}, Price: {product['price']}, Quantity: {product['quantity']}")
        else:
            print("No product available.")
    else:
        print("Failed to retrieve products. Status Code:", response.status_code)

def buy_product():
    product_id = input("Enter product ID: ")
    quantity = input("Enter quantity: ")
    response = requests.post(f"{BASE_URL}/buy_product", json={"product_id": product_id, "quantity": quantity})
    print(response.json())

def submit_feedback():
    global current_user
    username = current_user
    content = input("Enter feedback: ")
    response = requests.post(f"{BASE_URL}/submit_feedback", json={"username": username, "content": content})
    print(response.json())

# Menu Functions
def admin_menu():
    while True:
        print("\nAdmin Menu")
        print("1. Add User")
        print("2. Add Product")
        print("3. View Feedbacks")
        print("4. Change Password")
        print("5. Exit")
        choice = input("Choose an option: ")
        if choice == '1':
            add_user()
        elif choice == '2':
            add_product()
        elif choice == '3':
            view_feedbacks()
        elif choice == '4':
            change_password()
        elif choice == '5':
            print("Exiting the admin menu.")
            break
        else:
            print("Invalid choice, admin please try again.")

def user_menu():
    while True:
        print("\nUser Menu")
        print("1. Add Product")
        print("2. Change Password")
        print("3. Exit")
        choice = input("Choose an option: ")
        if choice == '1':
            add_product()
        elif choice == '2':
            change_password()
        elif choice == '3':
            print("Exiting the user menu.")
            break
        else:
            print("Invalid choice, user please try again.")

def customer_menu():
    while True:
        print("\nCustomer Menu")
        print("1. Buy Product")
        print("2. View Products")
        print("3. Submit Feedback")
        print("4. Change Password")
        print("5. Exit")
        choice = input("Choose an option: ")
        if choice == '1':
            buy_product()
        elif choice == '2':
            view_products()
        elif choice == '3':
            submit_feedback()
        elif choice == '4':
            change_password()
        elif choice == '5':
            print("Exiting the customer menu.")
            break
        else:
            print("Invalid choice, customer please try again.")

def main_menu():
    while True:
        print("\nMain Menu")
        print("1. Login")
        print("2. Register")
        print("3. Exit")
        choice = input("Choose an option: ")
        if choice == '1':
            login()
        elif choice == '2':
            register()
        elif choice == '3':
            print("Exiting the application.")
            break
        else:
            print("Invalid choice, please try again.")

# Main
if __name__ == "__main__":
    main_menu()
