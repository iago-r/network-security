from pydantic import BaseModel
from typing import List, Optional
from pathlib import Path


class Configuration(BaseModel):
    """

    Class used to parse the JSON that the user must provide with the application data to perform the automation.

    """

    context: str
    url: List[str]
    url_login: Optional[str] = None
    exclude_urls: List[str] = []
    report_title: Optional[str] = "Report"
    login: str
    password: str
