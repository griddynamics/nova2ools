import httplib
import json
import sys
import os

from urlparse import urlparse

from exceptions import CommandError

class NovaApiClient(object):
    ARGUMENTS = [
        (("--host",), {"help": "Nova API Host (with port)"}),
        (("--username", "-u"), {"help": "OpenStack user name"}),
        (("--api-key", "-k"), {"help": "OpenStack API secret key"}),
        (("--project", "-p"), {"help": "OpenStack Project(Tenant) name"}),
    ]

    DEFAULTS = {
        "username": os.environ.get("NOVA_USERNAME"),
        "api_key": os.environ.get("NOVA_API_KEY"),
        "project": os.environ.get("NOVA_PROJECT_ID"),
    }

    __nova_url = os.environ.get("NOVA_URL")
    if __nova_url is not None:
        DEFAULTS["host"] = urlparse(__nova_url)[1]


    def __init__(self, options):
        if options.host is None:
            raise CommandError(1, "Nova API Host is not configured")
        if options.username is None:
            raise CommandError(1, "OpenStack user name is undefined")
        if options.api_key is None:
            raise CommandError(1, "OpenStack API secret key is undefined")
        if options.project is None:
            raise CommandError(1, "OpenStack Project(Tenant) name is undefined")
        self.__client = httplib.HTTPConnection(options.host)
        self.options = options
        if self.options.debug:
            self.__client.set_debuglevel(100)
        self.auth()

    def auth(self):
        auth_headers = {
            "X-Auth-User": self.options.username,
            "X-Auth-Key": self.options.api_key,
            "X-Auth-Project-Id": self.options.project
        }
        self.__client.request("GET", "/v1.1", headers=auth_headers)
        resp = self.__client.getresponse()
        self.__validate_response(resp)
        self.__token = resp.getheader("X-Auth-Token")
        self.__management_url = resp.getheader("X-Server-Management-Url")
        self.__management_path = urlparse(self.__management_url).path

    def request(self, method, url, body=None, headers=None):
        if headers is None:
            headers = {}
        self.__client.request(method, url, body, headers)
        resp = self.__client.getresponse()
        return self.__validate_response(resp)

    def get(self, path):
        return self.request("GET", self.__management_path + path, headers=self.__auth_headers())

    def post(self, path, body):
        headers = self.__auth_headers()
        if isinstance(body, dict):
            body = json.dumps(body)
            headers["Content-Type"] = "application/json"
        return self.request("POST", self.__management_path + path, body, headers)

    def put(self, path, body):
        return self.request("POST", self.__management_path + path, body, self.__auth_headers())

    def delete(self, path):
        return self.request("DELETE", self.__management_path + path, headers=self.__auth_headers())

    def __validate_response(self, response):
        response_content = response.read()
        if self.options.debug:
            sys.stderr.write("Response:\n")
            sys.stderr.write(response_content)
            sys.stderr.write("\n\n")
        if response.status == 200:
            json_response = json.loads(response_content)
            return json_response
        if response.status == 404:
            raise CommandError(1, response.reason)
        if response.status == 401:
            raise CommandError(1, response.reason)
        if response.status == 204: # No Content
            return None
        if response.status == 202: # Accepted
            try:
                json_response = json.loads(response_content)
            except ValueError:
                return response_content
            return json_response
        if response.status == 400: # Bad Request
            json_response = json.loads(response_content)
            raise CommandError(1, "Bad Request: {0}".format(json_response["badRequest"]["message"]))
        raise CommandError(1, "Unhandled response code: %s (%s)" % (response.status, response.reason))

    def __auth_headers(self):
        return {
            "X-Auth=Project-Id": self.options.project,
            "X-Auth-Token": self.__token
        }