import os
import logging
import re
import time
from pathlib import Path

from ruamel.yaml import YAML
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.keys import Keys
from zapv2 import ZAPv2

from autentication import autentication
from context.context import build_yaml, update_jobs
from keywords.elements import filtered_dict
from keywords.keywords import RegexSets, parameter_types_found
from params import params
from urls_login import urls_login
from user_data.user_data import Configuration

"""
The default time is used to wit while selenium or zap is working, this delay is a reng sefety to wait a frameowrk to finish the work. 
"""
DEFAULT_TIME = 3

logging.basicConfig(level=logging.INFO, format='%(message)s')


def main(file_path):

    file_path = Path(file_path)

    json_data = file_path.read_text()

    user = Configuration.model_validate_json(json_data)

    logging.info("User configuration loaded successfully.")

    regex_sets = RegexSets()

    invalid_values_urls = regex_sets.invalid_values_urls
    url_words = regex_sets.url_words

    FIREFOX = os.getenv("FIREFOX")
    ZAP_API_KEY = os.getenv("ZAP_API_KEY")
    if FIREFOX is None or ZAP_API_KEY is None:
        raise EnvironmentError("FIREFOX e ZAP_API_KEY devem estar definidos nas variáveis de ambiente.")

    ZAP_PROXY_ADDRESS = os.getenv("ZAP_PROXY_ADDRESS")
    ZAP_PROXY_PORT = int(os.getenv("ZAP_PROXY_PORT"))

    zap = ZAPv2(
        apikey=ZAP_API_KEY,
        proxies={
            "http": f"http://{ZAP_PROXY_ADDRESS}:{ZAP_PROXY_PORT}",
            "https": f"http://{ZAP_PROXY_ADDRESS}:{ZAP_PROXY_PORT}",
        },
    )
    proxy_server_url = f"{ZAP_PROXY_ADDRESS}:{ZAP_PROXY_PORT}"
    firefox_options = webdriver.FirefoxOptions()
    firefox_options.add_argument("--ignore-certificate-errors")
    firefox_options.add_argument(f"--proxy-server={proxy_server_url}")
    firefox_options.add_argument("--headless")

    s = Service(FIREFOX)
    firefox_profile = webdriver.FirefoxProfile()
    firefox_profile.set_preference("network.proxy.type", 1)
    firefox_profile.set_preference("network.proxy.http", ZAP_PROXY_ADDRESS)
    firefox_profile.set_preference("network.proxy.http_port", ZAP_PROXY_PORT)
    firefox_profile.set_preference("network.proxy.ssl", ZAP_PROXY_ADDRESS)
    firefox_profile.set_preference("network.proxy.ssl_port", ZAP_PROXY_PORT)
    firefox_profile.update_preferences()

    firefox_options.profile = firefox_profile

    if user.url_login == "":
        FLAG_LOGIN = 0
        logging.info("url de login não foi setada")
    else:
        FLAG_LOGIN = 1
        logging.info("url de login setada")

    zap.core.new_session(overwrite=True)

    struct_login = []

    driver = webdriver.Firefox(service=s, options=firefox_options)
    if FLAG_LOGIN:
        filtered_dict(driver, user.url_login, struct_login)
        time.sleep(DEFAULT_TIME)

    if FLAG_LOGIN == 0:
        struct_login = spider_scan(driver, zap, user, urls_login, url_words, invalid_values_urls, s, firefox_options, struct_login)
    
    logging.info("Struct login: %s", struct_login)

    zap.core.new_session(overwrite=True)

    driver = webdriver.Firefox(service=s, options=firefox_options)
    if len(struct_login) == 1:
        url_authentication = list(struct_login[0].keys())[0]
        driver.get(url_authentication)
    else:
        raise ValueError("Failed to create the list of URLs: struct_login does not contain exactly one element.")

    time.sleep(DEFAULT_TIME)

    for authentication_dictionary in struct_login:
        for _, elements in authentication_dictionary.items():
            for element_type, field in elements.items():
                login_element, password_element = field
                logging.info(login_element, password_element)
                username_field = autentication.find_element_by_attribute(
                    driver, element_type, login_element
                )
                if username_field is None:
                    continue  # Se não encontrou o campo de username, pula para o próximo elemento
                password_field = autentication.find_element_by_attribute(
                    driver, element_type, password_element
                )
                if password_field is None:
                    continue  # Se não encontrou o campo de password, pula para o próximo elemento

                username_field.send_keys(user.login)
                password_field.send_keys(user.password)

                time.sleep(DEFAULT_TIME)

                try:
                    password_field.send_keys(Keys.RETURN)

                    time.sleep(DEFAULT_TIME)
                    autentication.validate_by_attribute(driver, element_type, login_element)
                except Exception as e:
                    raise RuntimeError(f"Failed to submit the login form: {e}")

                time.sleep(DEFAULT_TIME)
                # there exists a list of element types to test, if we find the first one, we can break the loop and continue.
                break

    driver.quit()

    # Pegar todos os alertas da aplicação
    alerts = zap.alert.alerts()
    logging.info(f"Number of Alerts: {len(alerts)}")
    # se não retornar alerta, lançar assert informando a possibilidade do scan passivo ter parado de funcionar
    # Alertas no momento que o post foi passado, isso inclui as aplicações que foram passadas de forma errada
    # Lembrar que pegar o ultimo ainda é o mais sensato (evitar casos que manda a credencial que queremos, mas de uma forma errada) tem que testar.
    messageId = [alert["messageId"] for alert in alerts if alert["name"] == "Authentication Request Identified"]

    # verifica todos os alertas candidatos e filtra o que foi passado as credenciais de forma correta.
    for message in messageId:
        request_autenticated = zap.core.message(message)
        if autentication.check_credentials(
            request_autenticated["requestBody"],
            user.login,
            user.password,
        ):
            logging.info(
                f"The application's response during login: {request_autenticated["requestBody"]}"
            )
            break

    request_body = request_autenticated["requestBody"]

    # Verifica que o zap encontrou o gerenciamento de sessão
    alert_count = len(
        [
            alert
            for alert in alerts
            if alert["name"] == "Session Management Response Identified"
        ]
    )

    BASE_CONTEXT = "base_context/context_base.yaml"

    params.define_authentication_type(
        zap, parameter_types_found, url_authentication, request_body
    )

    yaml = YAML()

    with open(BASE_CONTEXT, "r") as file:
        context = yaml.load(file)

    build_yaml(
        context,
        alert_count,
        request_body,
        user.login,
        user.password,
        user.context,
        user.url,
        url_authentication,
    )

    new_context = user.context
    new_user = user.login
    new_url = url_authentication

    # Chama a função para atualizar os valores
    update_jobs(context["jobs"], new_context, new_user, new_url)

    OUTPUT = f"context_{user.context}"

    # Salvar em um novo arquivo YAML
    with open(f"../shared_data/{OUTPUT}.yaml", "w") as file:
        yaml.dump(context, file)

    logging.info("YAML file saved successfully!")

    output_yaml = f"../shared_data/{OUTPUT}.yaml"
    logging.info(f" Yaml path: ",output_yaml)



def wait_for_directory(directory_path):
    directory_path = Path(directory_path)

    if directory_path.exists():
        if any(directory_path.iterdir()):
            logging.info(f"Files found in directory: {directory_path}")
            return
        else:
            logging.info(f"Empty Directory: {directory_path}")
            return


def spider_scan(driver, zap, user, urls_login, url_words, invalid_values_urls, s, firefox_options, struct_login):
    # Primeira url será utilizada para realizar o crawler na página com o spider
    driver.get(user.url[0])

    time.sleep(DEFAULT_TIME)
    scanid = zap.spider.scan(user.url[0])

    while int(zap.spider.status(scanid)) < 100:
        # Loop until the spider has finished
        logging.info("Spider progress %: {}".format(zap.spider.status(scanid)))
        time.sleep(DEFAULT_TIME)

    logging.info("Spider completed")

    driver.quit()

    urls_found = zap.core.urls()

    logging.info(urls_found)
    general_results = urls_login.find_urls_login(urls_found, url_words)
    logging.info(general_results)
    evidences_urls_login = []
    for url in general_results:
        if not any(
            re.search(pattern, url) for pattern in invalid_values_urls
        ):  # match das palavras do array (regex group)
            evidences_urls_login.append(url)

    logging.info(evidences_urls_login)
    for evidence in evidences_urls_login:
        driver = webdriver.Firefox(service=s, options=firefox_options)
        filtered_dict(driver, evidence, struct_login)


if __name__ == "__main__":
    DIRECTORY_PATH = "/shared_data/input_config"
    wait_for_directory(DIRECTORY_PATH)
    arq_config = os.listdir(DIRECTORY_PATH)
    for arq in arq_config:
        arq = os.path.join(DIRECTORY_PATH, arq)
        try:
            main(arq)
        except Exception as e:
            logging.error(f"An error occurred while processing the file {arq}: {e}")
            raise RuntimeError(f"Failed to process the file {arq}") from e