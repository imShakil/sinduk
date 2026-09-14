import requests  # type: ignore
from .log import get_logger

logger = get_logger("sinduk.linklyhq")
__BASE_API_URL__ = "https://app.linklyhq.com/api/v1"


class LinklyHQ:
    def __init__(self, api_key, workspace_id):
        self.api_key = api_key
        self.wid = workspace_id
        self.base_url = __BASE_API_URL__

    def shorten(self, url, name=None):
        data = {"url": url, "workspace_id": self.wid, "api_key": self.api_key}
        if name:
            data["name"] = name
        try:
            response = requests.post(self.base_url + "/link", json=data, timeout=30)
            response.raise_for_status()
            logger.info(f"Shortened URL: {response.json()['full_url']}")
            return response.json()["full_url"]
        except requests.exceptions.RequestException as e:
            logger.error(f"Error shortening URL: {e}")
            return None
