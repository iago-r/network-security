import logging

from ruamel.yaml.comments import CommentedMap
from keywords import keywords


def replace_words(
    text,
    login,
    password,
    credential_login="{%username%}",
    credential_password="{%password%}",
):
    """

    This function is responsible for replacing the login and password keywords with the default credentials accepted by ZAP.
    The replace_words function has a case where it treats %40 as @, which was highlighted in some tests where the request with @ was returned by replacing it with the characters %40.

    """
    if login == password:
        new_request = text.replace(login, credential_login, 1).replace(
            password, credential_password, 1
        )
    else:
        if "%40" in text:
            login = login.replace("@", "%40")
        new_request = text.replace(login, credential_login, 1).replace(
            password, credential_password, 1
        )
    return new_request


def build_yaml(
    context,
    alert_count,
    request_body,
    credential_login,
    credential_password,
    context_name,
    base_url,
    base_url_login,
):
    """

    This function receives the context information as a parameter and constructs the YAML file responsible for the application's automation plan.

    """
    if alert_count > 0:
        # marcar contexto como auto detect.
        context["env"]["contexts"][0]["sessionManagement"]["method"] = "autodetect"
        logging.info("Session management set to auto-detection")

    request_text = replace_words(request_body, credential_login, credential_password)

    context["env"]["contexts"][0]["authentication"]["parameters"][
        "loginRequestBody"
    ] = request_text

    # Authentication validation
    context["env"]["contexts"][0]["authentication"]["verification"][
        "method"
    ] = "autodetect"

    # User crendetials
    context["env"]["contexts"][0]["users"][0]["name"] = credential_login
    context["env"]["contexts"][0]["users"][0]["credentials"][
        "password"
    ] = credential_password
    context["env"]["contexts"][0]["users"][0]["credentials"][
        "username"
    ] = credential_login

    context["env"]["contexts"][0]["name"] = context_name
    context["env"]["contexts"][0]["urls"] = base_url
    context["env"]["contexts"][0]["includePaths"] = []
    # Authentication
    context["env"]["contexts"][0]["authentication"]["parameters"][
        "loginPageUrl"
    ] = base_url_login
    context["env"]["contexts"][0]["authentication"]["parameters"][
        "loginRequestUrl"
    ] = base_url_login

    verification_context = context["env"]["contexts"][0]["authentication"][
        "verification"
    ]
    new_verification_entries = CommentedMap()
    new_verification_entries["method"] = "autodetect"

    if keywords.parameter_types_found["form"]:
        context["env"]["contexts"][0]["authentication"]["method"] = "form"

    if keywords.parameter_types_found["json"]:

        new_verification_entries["method"] = "json"

    # Atualizar os dados de verificação com a nova ordem
    context["env"]["contexts"][0]["authentication"][
        "verification"
    ] = new_verification_entries


def update_jobs(jobs, new_context, new_user, new_url):
    """

    Instantiates jobs defined by default in the application's automation plan file.

    """
    for job in jobs:
        if "parameters" in job:
            if "context" in job["parameters"]:
                job["parameters"]["context"] = new_context
            if "user" in job["parameters"]:
                job["parameters"]["user"] = new_user
            if "url" in job["parameters"]:
                job["parameters"]["url"] = new_url
