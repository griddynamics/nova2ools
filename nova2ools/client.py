import httplib
import json
import sys

from urlparse import urlparse

from exceptions import CommandError

class Client(object):
    def __init__(self):
        self.__client = httplib.HTTPConnection("cc.c4gd.griddynamics.net", 8774)
        self.__debug = False

    def set_debug(self, value):
        self.__debug = value
        if value:
            self.__client.set_debuglevel(100)
        else:
            self.__client.set_debuglevel(0)

    def auth(self, user, access_key, project_id):
        self.__project_id = project_id
        auth_headers = {
            "X-Auth-User": user,
            "X-Auth-Key": access_key,
            "X-Auth-Project-Id": project_id
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
        if self.__debug:
            sys.stderr.write("Response:\n")
            sys.stderr.write(response_content)
            sys.stderr.write("\n\n")
        if response.status == 200:
            response = json.loads(response_content)
            return response
        if response.status == 404:
            raise CommandError(1, response.reason)
        if response.status == 401:
            raise CommandError(1, response.reason)
        if response.status == 204: # No Content
            return None
        if response.status == 202: # Accepted
            return None
        raise CommandError(1, "Unhandled response code: %s (%s)" % (response.status, response.reason))

    def __auth_headers(self):
        return {
            "X-Auth=Project-Id": self.__project_id,
            "X-Auth-Token": self.__token
        }