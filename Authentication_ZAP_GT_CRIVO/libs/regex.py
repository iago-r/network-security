import os

def concatena_regex(string):
    new_regex = '\Q' + string + '\E'

    return new_regex

def get_repo_path():
    """Retorna o caminho do repositório."""
    return os.path.join(os.path.dirname(__file__), 'output_context/')


