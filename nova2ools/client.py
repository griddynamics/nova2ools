import httplib
import json
from urlparse import urlparse

from exceptions import CommandError

class Client(object):
    def __init__(self):
        self.__client = httplib.HTTPConnection("cc.c4gd.griddynamics.net", 8774)

    def set_debug(self, value):
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

    def get(self, path):
        self.__client.request("GET", self.__management_path + path, headers=self.__auth_headers())
        resp = self.__client.getresponse()
        return self.__validate_response(resp)

    def post(self):
        pass

    def put(self):
        pass

    def delete(self):
        pass

    @staticmethod
    def __validate_response(response):
        if response.status == 200:
            response = json.load(response)
            return response
        response.read()
        if response.status == 404:
            raise CommandError(1, response.reason)
        if response.status == 401:
            raise CommandError(1, response.reason)
        if response.status == 204:
            return None
        raise CommandError(1, "Unhandled response code: %s (%s)" % (response.status, response.reason))

    def __auth_headers(self):
        return {
            "X-Auth=Project-Id": self.__project_id,
            "X-Auth-Token": self.__token
        }