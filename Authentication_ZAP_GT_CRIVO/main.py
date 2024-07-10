from libs import regex
from user_data import user_data
from urls_login import urls_login
from keywords import keywords
from autentication import autentication
from request_text import request_text
from params import params
import time
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.common.exceptions import NoSuchAttributeException
import os
from zapv2 import ZAPv2

import yaml
from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap

# --------------------------------------------------- BROWSER CONFIG ---------------------------------------------------  
FIREFOX = '/snap/bin/geckodriver'
ZAP_PROXY_ADDRESS = 'localhost'
ZAP_PROXY_PORT = 8080
ZAP_API_KEY = os.getenv("ZAP_API_KEY")
zap = ZAPv2(apikey=ZAP_API_KEY, proxies={'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'})
proxyServerUrl = f'{ZAP_PROXY_ADDRESS}:{ZAP_PROXY_PORT}'
firefox_options = webdriver.FirefoxOptions()
firefox_options.add_argument('--ignore-certificate-errors')
firefox_options.add_argument(f'--proxy-server={proxyServerUrl}')
s = Service(FIREFOX)
firefox_profile = webdriver.FirefoxProfile()
firefox_profile.set_preference('network.proxy.type', 1)
firefox_profile.set_preference('network.proxy.http', ZAP_PROXY_ADDRESS)
firefox_profile.set_preference('network.proxy.http_port', ZAP_PROXY_PORT)
firefox_profile.set_preference('network.proxy.ssl', ZAP_PROXY_ADDRESS)
firefox_profile.set_preference('network.proxy.ssl_port', ZAP_PROXY_PORT)
firefox_profile.update_preferences()

firefox_options.profile = firefox_profile

# --------------------------------------------------- BROWSER CONFIG --------------------------------------------------- 

DEFAULT_TIME = 3
BASE_CONTEXT = 'base_context/context_base.yaml'

yaml = YAML()

with open(BASE_CONTEXT, 'r') as file:
    context = yaml.load(file)

zap.core.new_session(overwrite=True)



driver = webdriver.Firefox(service=s, options=firefox_options)
driver.get(user_data.BASE_URL_LOGIN)

time.sleep(DEFAULT_TIME)

scanid  = zap.spider.scan(user_data.BASE_URL_LOGIN)

time.sleep(DEFAULT_TIME)
while (int(zap.spider.status(scanid)) < 100):
    # Loop until the spider has finished
    print('Spider progress %: {}'.format(zap.spider.status(scanid)))
    time.sleep(DEFAULT_TIME)

print ('Spider completed')

driver.quit()

urls_found = zap.core.urls()

general_results = urls_login.find_urls_login(urls_found, keywords.url_words)

evidences_urls_login = []
for result in general_results:
    if not any(invalid_value in result for invalid_value in keywords.invalid_values_urls):
        evidences_urls_login.append(result)


# Elementos da pagina
"-----------------------------------------------------------------------------------------------------------------------------------"

struct_login = []

for evidence in evidences_urls_login:
    driver = webdriver.Firefox(service=s, options=firefox_options)
    driver.get(evidence)
    # pegar os elementos 
    time.sleep(DEFAULT_TIME)
    elements = driver.find_elements(By.XPATH, "//*")

    # leve macro para burlar aplicações com uma janela de pop-up 
    if not elements:
        webdriver.ActionChains(driver).send_keys(Keys.ESCAPE).perform()
        elements = driver.find_elements(By.XPATH, "//*")

    array_elements = []

    for element in elements:
        element_info = {}
        try:
            attributes_to_gather = [
                ("name", element.get_attribute("name")),
                ("type", element.get_attribute("type")),
                ("placeholder", element.get_attribute("placeholder")),  
                ("id", element.get_attribute("id"))  
            ]
            element_info = {key: value for key, value in attributes_to_gather if value}
        except NoSuchAttributeException:
            pass  

        if element_info:
            array_elements.append(element_info)

    # Filtrando os dicionários
    filtered_dictionaries = []
    for dict in array_elements:
        for key, value in dict.items():
            if value in keywords.valid_values_elements:
                filtered_dictionaries.append(dict)
                break

    # Número de elementos para pegar acima
    '''
    for index, element in enumerate(filtered_dictionaries):
        if ('placeholder' in element and element['placeholder'] == 'Password') or ('name' in element and element['name'] == 'password') or ('type' in element and element['type'] == 'password'):
            if (filtered_dictionaries[index-1] in login):
                pass
            else:
                login.append(filtered_dictionaries[index-1])
            if (element in login):
                pass
            else:
                login.append(element)
    '''

    # Se após a filtragem o dicionario possuir elementos, criar as tuplas para usar na autenticação.
    if(filtered_dictionaries != []):

        authentication_data = {
        "name": tuple(element.get("name", "") for element in filtered_dictionaries),
        "type": tuple(element.get("type", "") for element in filtered_dictionaries),
        "placeholder": tuple(element.get("placeholder", "") for element in filtered_dictionaries),
        }

        dicionario_autenticado = {evidence : authentication_data}
        struct_login.append(dicionario_autenticado)

    driver.quit()


# Autenticação
"-----------------------------------------------------------------------------------------------------------------------------------"

zap.core.new_session(overwrite=True)

# Inicializar o driver do Selenium
# Essa urls tem que ser a que foi encontrada no spider
driver = webdriver.Firefox(service=s, options=firefox_options)
driver.get(user_data.BASE_URL_LOGIN)
time.sleep(DEFAULT_TIME)

for authentication_dictionary in struct_login:
    for _, elements in authentication_dictionary.items():
        for type, field in elements.items():
            login_element, password_element = field
            print(login_element, password_element)
            # Encontrar os campos de login e senha (mudar)
            username_field = autentication.find_element_by_attribute(driver, type, login_element)
            if username_field is None:
                continue  # Se não encontrou o campo de username, pula para o próximo elemento
            password_field = autentication.find_element_by_attribute(driver, type, password_element)
            if password_field is None:
                continue  # Se não encontrou o campo de password, pula para o próximo elemento

            username_auth = username_field
            password_auth = password_field
            # Preencher os campos de login e senha
        
            username_field.send_keys(user_data.CREDENTIAL_LOGIN)
            password_field.send_keys(user_data.CREDENTIAL_PASSWORD)

            time.sleep(DEFAULT_TIME)
            
            
            # Tentar enviar o formulário
            try:
                password_field.send_keys(Keys.RETURN)
            except Exception:
                pass
            

time.sleep(DEFAULT_TIME)
# Finalizar o driver
driver.quit()

"-----------------------------------------------------------------------------------------------------------------------------------"

# Pegar todos os alertas da aplicação
alerts = zap.alert.alerts()

# Alertas no momento que o post foi passado, isso inclui as aplicações que foram passadas de forma errada
# Lembrar que pegar o ultimo ainda é o mais sensato (evitar casos que manda a credencial que queremos, mas de uma forma errada) tem que testar.
alert_autentication = []
for alert in alerts:
        if alert["name"]  == "Authentication Request Identified":
            # alerta de autenticação
            alert_autentication.append(alert)

# Pegar os ids de todas as mensagens de autenticação, ou de possiveis autenticação
messageId = []
for alert in alert_autentication:
    messageId.append(alert["messageId"])

# verifica todos os alertas candidatos e filtra o que foi passado as credenciais de forma correta.
for id in messageId:
    request_autenticated = zap.core.message(id)
    if(autentication.check_credentials(request_autenticated["requestBody"], user_data.CREDENTIAL_LOGIN, user_data.CREDENTIAL_PASSWORD)):
        print(f' O response da aplicação no momento do login é:\n {request_autenticated["requestBody"]}')
        break


alert_count = len([alert for alert in alerts if alert["name"] == "Session Management Response Identified"])

if(alert_count > 0):
    # marcar contexto como auto detect.
    context['env']['contexts'][0]['sessionManagement']['method'] = "autodetect"
    print("Gerenciamento de sessão definido como auto detecção")

request_body = request_autenticated['requestBody']
request_text = request_text.replace_words(request_body, user_data.CREDENTIAL_LOGIN, user_data.CREDENTIAL_PASSWORD)
context['env']['contexts'][0]['authentication']['parameters']['loginRequestBody'] = request_text

# Validação de autenticação
context['env']['contexts'][0]['authentication']['verification']['method'] = "autodetect"

params.Define_type_authentication(zap, keywords.parameter_types_found, user_data.BASE_URL_LOGIN, request_body)


# Usuario
context['env']['contexts'][0]['users'][0]['name'] = "Test"
context['env']['contexts'][0]['users'][0]['credentials']['password'] = user_data.CREDENTIAL_PASSWORD
context['env']['contexts'][0]['users'][0]['credentials']['username'] = user_data.CREDENTIAL_LOGIN

context['env']['contexts'][0]['name'] = user_data.NAME_CONTEXT
context['env']['contexts'][0]['urls'] = user_data.BASE_URL
context['env']['contexts'][0]['includePaths'] = []
# autenticação
context['env']['contexts'][0]['authentication']['parameters']['loginPageUrl'] = user_data.BASE_URL_LOGIN
context['env']['contexts'][0]['authentication']['parameters']['loginRequestUrl'] = user_data.BASE_URL_LOGIN


# Criar novas entradas para a verificação logo abaixo de 'method'
verification_context = context['env']['contexts'][0]['authentication']['verification']
new_verification_entries = CommentedMap()
new_verification_entries['method'] = "autodetect"

if(keywords.parameter_types_found['form']):
    context['env']['contexts'][0]['authentication']['method'] = "form"

if(keywords.parameter_types_found['json']):

    new_verification_entries['method'] = "json"
    

# Atualizar os dados de verificação com a nova ordem
context['env']['contexts'][0]['authentication']['verification'] = new_verification_entries

OUTPUT = "context_output"
# Salvar em um novo arquivo YAML

with open(f'output_context/{OUTPUT}.yaml', 'w') as file:
    yaml.dump(context, file)

print("Arquivo YAML modificado e salvo com sucesso !")

time.sleep(DEFAULT_TIME)

output_yaml = os.path.join(regex.get_repo_path(), OUTPUT) 

zap.automation.run_plan(output_yaml, ZAP_API_KEY)
