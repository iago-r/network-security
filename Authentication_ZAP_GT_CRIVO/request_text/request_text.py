def replace_words(text, login, password, credential_login="{%username%}", credential_password="{%password%}"):
    if login == password:
        new_request = text.replace(login, credential_login, 1).replace(password, credential_password, 1)
    else:
        if '%40' in text:
            login = login.replace('@', '%40')
        new_request = text.replace(login, credential_login, 1).replace(password, credential_password, 1)
    return new_request