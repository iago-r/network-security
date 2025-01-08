import logging
import re
import time

from selenium import webdriver
from selenium.common.exceptions import NoSuchAttributeException
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys

from keywords.keywords import RegexSets


logging.basicConfig(level=logging.INFO, format="%(message)s")

DEFAULT_TIME = 1
regex_sets = RegexSets()
password_regex = regex_sets.valid_values_elements[0]
valid_values_elements = regex_sets.valid_values_elements


def find_password(element):
    return any(
        re.search(password_regex, str(value), re.IGNORECASE)
        for _, value in element.items()
    )


def filtered_dict(driver, evidence, struct_login):
    """

    The function will receive an instance of a page and an empty structure that will be filled.
    For each "evidence" (page with a potential authentication form), the function will extract all elements from the page and use regex to verify if the elements are indeed authentication fields.
    The function will filter the elements from the page and return a dictionary with the filtered elements.
    This function runs in a loop, meaning there can be multiple pages that are not candidates in the queue. Therefore, the page does not use the ZAP proxy. Because of this, the driver is closed as soon as the elements are extracted.

    """

    driver.get(evidence)
    time.sleep(DEFAULT_TIME)
    elements = driver.find_elements(By.XPATH, "//*")

    if not elements:
        elements_popup = driver.find_elements(By.XPATH, "//*")
        webdriver.ActionChains(driver).send_keys(Keys.ESCAPE).perform()
        elements = driver.find_elements(By.XPATH, "//*")
        elements.extend(elements_popup)

    array_elements = []

    for element in elements:
        element_info = {}
        try:
            attributes_to_gather = [
                ("name", element.get_attribute("name")),
                ("type", element.get_attribute("type")),
                ("placeholder", element.get_attribute("placeholder")),
                ("id", element.get_attribute("id")),
            ]
            element_info = {key: value for key, value in attributes_to_gather if value}
        except NoSuchAttributeException:
            pass

        if element_info:
            array_elements.append(element_info)
    logging.info(array_elements)

    filtered_dictionaries = []
    for einfo in array_elements:
        for _, value in einfo.items():
            for regex in valid_values_elements:
                if re.search(regex, value):
                    if einfo not in filtered_dictionaries:
                        filtered_dictionaries.append(einfo)
                    break

    logging.info(filtered_dictionaries)

    if filtered_dictionaries:

        if len(filtered_dictionaries) > 2:
            login = []
            for index, element in enumerate(filtered_dictionaries):
                if find_password(element):
                    if filtered_dictionaries[index - 1] in login:
                        pass
                    else:
                        login.append(filtered_dictionaries[index - 1])
                    if element in login:
                        pass
                    else:
                        login.append(element)
            filtered_dictionaries = login

        authentication_data = {
            "name": tuple(element.get("name", "") for element in filtered_dictionaries),
            "type": tuple(element.get("type", "") for element in filtered_dictionaries),
            "placeholder": tuple(
                element.get("placeholder", "") for element in filtered_dictionaries
            ),
        }

        dicionario_autenticado = {evidence: authentication_data}
        struct_login.append(dicionario_autenticado)

    driver.quit()
