import os


class RegexSets:
    """

    The class is responsible for loading the regex files that will be used to identify elements on the page.

    """

    def __init__(self):
        self.folder_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "regex_words/"
        )
        self.keywords = {}
        self.load_files()

    def load_files(self):
        # Obtém todos os arquivos .txt na pasta
        files = [f for f in os.listdir(self.folder_path) if f.endswith(".txt")]
        files = sorted(files)

        for file in files:
            key = file.split(".")[0]
            self.keywords[key] = self.read_files(file)

        self.invalid_values_urls = self.keywords.get("invalid_urls", [])
        self.type_elements = self.keywords.get("type_elements", [])
        self.valid_values_elements = self.keywords.get("valid_elements", [])
        self.url_words = self.keywords.get("valid_urls", [])

    def read_files(self, file):
        with open(f"{self.folder_path}{file}", "r") as f:
            return [line.strip() for line in f]


password_field_identifiers = ("password", "senha", "txtPassword")
parameters_types = ("form", "json")
parameter_types_found = {"form": 0, "json": 0, "script": 0}
