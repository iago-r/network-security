from selenium.common.exceptions import NoSuchElementException
from selenium.webdriver.common.by import By
import logging

logging.basicConfig(level=logging.INFO, format="%(message)s")


def find_element_by_attribute(driver, attribute, value):
    """

    Find an element on the website based on the specified attribute.

    """
    try:
        if attribute == "name":
            element = driver.find_element(By.NAME, value)
        elif attribute == "type":
            element = driver.find_element(By.CSS_SELECTOR, f"input[type='{value}']")
        elif attribute == "placeholder":
            element = driver.find_element(
                By.CSS_SELECTOR, f"input[placeholder='{value}']"
            )
        else:
            raise ValueError(f"Atributo inválido: {attribute}")
        logging.info(f"Element found successfully.")
        return element
    except NoSuchElementException:
        logging.info(f"Element not found based on attribute '{attribute}'.")
        return None


def validate_by_attribute(driver, attribute, value):
    """

    Validate if an element with the given attribute and value is displayed on the page.

    """
    try:
        if attribute == "name":
            if driver.find_element(By.NAME, value).is_displayed():
                pass
        elif attribute == "type":
            if driver.find_element(
                By.CSS_SELECTOR, f"input[type='{value}']"
            ).is_displayed():
                pass
        elif attribute == "placeholder":
            if driver.find_element(
                By.CSS_SELECTOR, f"input[placeholder='{value}']"
            ).is_displayed():
                pass
        logging.info("Failed to log in!")
        driver.refresh()
        return
    except:
        logging.info("Login successful!")


def check_credentials(request, credencial_login, credencial_passsword):
    """

    This function receives a string and two credentials and checks if both credentials are present in the request body string.
    The function can check if the credentials are the same by verifying the number of occurrences in the string.
    And it checks if both credentials are present in the string.

    """
    if credencial_login == credencial_passsword:
        return request.count(credencial_login) >= 2
    else:
        return credencial_login in request and credencial_passsword in request
