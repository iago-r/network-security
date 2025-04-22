import os
import secrets
import string

import requests

from .settings import BASE_URL, HEADERS, HEADERS_FOR_IMPORT


def generate_password(length=12):
    chars = (
        string.ascii_letters
        + string.digits
        + "".join(c for c in string.punctuation if c not in ['"', "'", "\\", "/", ","])
    )
    while True:
        pwd = "".join(secrets.choice(chars) for _ in range(length))
        if all(
            (
                any(c.isupper() for c in pwd),
                any(c.islower() for c in pwd),
                any(c.isdigit() for c in pwd),
                any(c in string.punctuation for c in pwd),
            )
        ):
            return pwd


def post(endpoint, data, success_msg, error_msg):
    try:
        response = requests.post(f"{BASE_URL}{endpoint}/", json=data, headers=HEADERS)
        if response.status_code == 201:
            print(success_msg)
            return response.json()
        print(f"{error_msg} ({response.status_code}): {response.text}")
    except requests.exceptions.RequestException as e:
        print(f"Error sending POST request to {endpoint}: {e}")
    return None


def get_id(endpoint, param_name, param_value):
    try:
        response = requests.get(
            f"{BASE_URL}{endpoint}/?{param_name}={param_value}", headers=HEADERS
        )
        if response.status_code == 200:
            data = response.json()
            if data.get("count", 0) > 0:
                return data["results"][0]["id"]
    except requests.exceptions.RequestException as e:
        print(f"Error fetching {endpoint}: {e}")
    return None


def get_user_id(username):
    return get_id("users", "username", username)


def get_product_id(name):
    return get_id("products", "name", name)


def create_user(first_name, last_name, email, password):
    existing_user_id = get_user_id(email)
    if existing_user_id:
        print(f"User {email} already exists with ID {existing_user_id}")
        return existing_user_id

    data = {
        "username": email,
        "first_name": first_name,
        "last_name": last_name,
        "email": email,
        "password": password,
        "is_active": True,
        "is_superuser": False,
        "configuration_permissions": [],
    }
    res = post("users", data, f"User {email} created", "Error creating user")
    return res["id"] if res else None


def create_product(name):
    existing_product_id = get_product_id(name)
    if existing_product_id:
        print(f"Product {name} already exists with ID {existing_product_id}")
        return existing_product_id

    data = {"name": name, "description": name, "prod_type": 1, "sla_configuration": 1}
    res = post("products", data, f"Product {name} created", "Error creating product")
    return res["id"] if res else None


def associate_user_to_product(user_id, product_id, role=4):
    data = {"product": product_id, "user": user_id, "role": role}
    try:
        res = requests.post(f"{BASE_URL}product_members/", json=data, headers=HEADERS)
        if res.status_code == 201:
            print(f"User {user_id} associated to Product {product_id}")
        elif res.status_code == 400 and "user" in res.json():
            print(f"User {user_id} already associated to Product {product_id}")
        else:
            print(f"Error associating user to product ({res.status_code}): {res.text}")
    except requests.exceptions.RequestException as e:
        print(f"Error associating user to product: {e}")


def import_scan(product_name, finding_file):
    product_id = get_product_id(product_name)
    if not product_id:
        print(f"Error: Product '{product_name}' not found.")
        return

    finding_file = os.path.join("data/inputs", finding_file)
    with open(finding_file, "rb") as file:
        files = {"file": file}
        data = {
            "product_name": product_name,
            "auto_create_context": True,
            "engagement_name": "Engagement",
            "scan_type": "OpenVAS Parser",
        }
        response = requests.post(
            f"{BASE_URL}import-scan/",
            headers=HEADERS_FOR_IMPORT,
            data=data,
            files=files,
        )

    if response.status_code == 201:
        print(f"File '{finding_file}' successfully imported for '{product_name}'.")
    else:
        print(f"Import error: {response.status_code} - {response.text}")


def process_users_from_file(file_path):
    user_list = []
    try:
        with open(file_path) as file:
            for line in file:
                email, first, last, products = map(str.strip, line.split(",", 3))
                product_names = [p.strip() for p in products.split("|")]
                password = generate_password()
                user_id = create_user(first, last, email, password)
                if user_id:
                    for product_name in product_names:
                        product_id = create_product(product_name)
                        if product_id:
                            associate_user_to_product(user_id, product_id)
                        else:
                            print(
                                f"Invalid product ID for {product_name}, skipping association."
                            )
                    full_name = f"{first} {last}"
                    user_list.append(f"{full_name}, {email}, {password}")
                else:
                    print(
                        f"Failed to create user {email}, skipping product associations."
                    )
        with open("data/outputs/user_credentials.txt", "w") as f:
            f.write("\n".join(user_list))
        print("All users processed and credentials saved.")
    except FileNotFoundError:
        print(f"Error: File {file_path} not found.")


def process_findings_from_file(file_path):
    try:
        with open(file_path) as file:
            for line in file:
                product, finding_file = map(str.strip, line.split(","))
                print(finding_file)
                import_scan(product, finding_file)
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
