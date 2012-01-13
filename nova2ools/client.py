import httplib
import json
import sys
import os

import logging

from urlparse import urlparse

from exceptions import CommandError


LOG = logging.getLogger("nova2ools.client")


class EndpointNotFound(Exception):
    """Could not find Service or Region in Service Catalog."""
    pass


class ServiceCatalog(object):
    """Helper methods for dealing with a Keystone Service Catalog."""

    def __init__(self, resource_dict):
        self.catalog = resource_dict

    def get_token(self):
        return self.catalog['access']['token']['id']

    def url_for(self, attr=None, filter_value=None,
                    service_type='compute', endpoint_type='publicURL'):
        """Fetch the public URL from the Compute service for
        a particular endpoint attribute. If none given, return
        the first. See tests for sample service catalog."""
        if 'endpoints' in self.catalog:
            # We have a bastardized service catalog. Treat it special. :/
            for endpoint in self.catalog['endpoints']:
                if not filter_value or endpoint[attr] == filter_value:
                    return endpoint[endpoint_type]
            raise EndpointNotFound()

        # We don't always get a service catalog back ...
        if not 'serviceCatalog' in self.catalog['access']:
            raise EndpointNotFound()

        # Full catalog ...
        catalog = self.catalog['access']['serviceCatalog']

        for service in catalog:
            if service['type'] != service_type:
                continue

            endpoints = service['endpoints']
            for endpoint in endpoints:
                if not filter_value or endpoint[attr] == filter_value:
                    return endpoint[endpoint_type]

        raise EndpointNotFound()

class NovaApiClient(object):
    ARGUMENTS = [
        (("--auth-url",), {"help": "Keystone or Nova URL for authentication"}),
        (("--username", "-u"), {"help": "OpenStack user name"}),
        (("--password", "-p"), {"help": "OpenStack API password"}),
        (("--tenant-id",), {"help": "OpenStack Project(Tenant) ID"}),
        (("--tenant-name", "--project", "-t"), {"help": "OpenStack Project(Tenant) name"}),
        (("--token",), {"help": "OpenStack token"}),
        (("--endpoint",), {"help": "OpenStack endpoint"}),
        (("--debug",), {"action": "store_true", "help": "Run in debug mode"}),
    ]

    DEFAULTS = {
        "auth_url": os.environ.get("OS_AUTH_URL", os.environ.get("NOVA_URL")),
        "username": os.environ.get("OS_USERNAME", os.environ.get("NOVA_USERNAME")),
        "password": os.environ.get("OS_PASSWORD", os.environ.get("NOVA_API_KEY")),
        "tenant_id": os.environ.get("OS_TENANT_ID"),
        "tenant_name": os.environ.get("OS_TENANT_NAME", os.environ.get("NOVA_PROJECT_ID")),
        "token": os.environ.get("OS_TOKEN"),
        "debug": os.environ.get("NOVA2OOLS_DEBUG", "") not in ["", "0", "f", "false", "no", "off"],
    }

    def __init__(self, options, service_type="compute"):
        self.options = options
        self.service_type = service_type
        self.service_catalog = ServiceCatalog({})
        self.auth()

    def auth(self):
        if self.options.token:
            self.__token = self.options.token
        self.__management_url = self.options.endpoint
        if not (self.options.token and self.options.endpoint):
            if not self.options.auth_url:
                raise CommandError(1, "Authentication URL is required")
            if urlparse(self.options.auth_url).path.startswith("/v1.1"):
                self.auth_nova()
            else:
                self.auth_keystone()
        else:
            self.__auth_headers = {
                "X-Auth-Token": self.__token,
            }

    def auth_nova(self):
        auth_headers = {
            "X-Auth-User": self.options.username,
            "X-Auth-Key": self.options.password,
            "X-Auth-Project-Id": self.options.tenant_name
        }
        resp = self.request(self.options.auth_url, "GET", headers=auth_headers)
        self.__token = resp.getheader("X-Auth-Token")
        if not self.__management_url:
            self.__management_url = resp.getheader("X-Server-Management-Url")
        self.__auth_headers = {
            "X-Auth-Project-Id": self.options.tenant_name,
            "X-Auth-Token": self.__token
        }

    def auth_keystone(self):
        token = self.options.token
        password = self.options.password
        username = self.options.username
        tenant_id = self.options.tenant_id
        tenant_name = self.options.tenant_name
        if token:
            params = {"auth": {"token": {"id": token}}}
        elif username and password:
            params = {"auth": {"passwordCredentials": {"username": username,
                                                       "password": password}}}
        else:
            raise CommandError(1, "A username and password or token is required")
        if tenant_id:
            params['auth']['tenantId'] = tenant_id
        elif tenant_name:
            params['auth']['tenantName'] = tenant_name
        access = self.request(
                self.options.auth_url + "/tokens",
                "POST",
                body=params,
                headers={"Content-Type": "application/json"})
        self.service_catalog = ServiceCatalog(access)
        if not self.__management_url and self.service_type:
            self.set_service_type(self.service_type)
        self.__auth_headers = {
            "X-Auth-Token": self.service_catalog.get_token()
        }
        if tenant_id:
            self.__auth_headers["X-Tenant"] = tenant_id
        if tenant_name:
            self.__auth_headers["X-Tenant-Name"] = tenant_name

    def set_service_type(self, service_type):
        try:
            self.__management_url = self.service_catalog.url_for(service_type=service_type)
        except EndpointNotFound:
            raise CommandError(1, "Could not find `%s' in service catalog" % service_type)
        self.service_type = service_type

    def http_log(self, args, kwargs, resp, body):
        if not self.options.debug:
            return

        string_parts = ['curl -i']
        for element in args:
            if element in ('GET', 'POST'):
                string_parts.append(' -X %s' % element)
            else:
                string_parts.append(' %s' % element)

        for element in kwargs['headers']:
            header = ' -H "%s: %s"' % (element, kwargs['headers'][element])
            string_parts.append(header)

        print "REQ: %s\n" % "".join(string_parts)
        if 'body' in kwargs:
            print "REQ BODY: %s\n" % (kwargs['body'])
        print "RESP: %s\nRESP BODY: %s\n" % (resp, body)

    def request(self, *args, **kwargs):
        kwargs.setdefault('headers', kwargs.get('headers', {}))
        if 'body' in kwargs:
            kwargs['headers']['Content-Type'] = 'application/json'
            kwargs['body'] = json.dumps(kwargs['body'])

        parsed = urlparse(args[0])
        client = httplib.HTTPConnection(parsed.netloc)
        client.request(args[1], parsed.path, **kwargs)
        resp = client.getresponse()
        body = resp.read()
        self.http_log(args, kwargs, resp, body)
        return self.__validate_response(resp, body)

    def get(self, path):
        return self.request(self.__management_url + path, "GET", headers=self.__auth_headers)

    def post(self, path, body):
        return self.request(self.__management_url + path, "POST", body=body, headers=self.__auth_headers)

    def put(self, path, body):
        return self.request(self.__management_url + path, "PUT", body=body, headers=self.__auth_headers)

    def delete(self, path):
        return self.request(self.__management_url + path, "DELETE", headers=self.__auth_headers)

    def __validate_response(self, response, response_content):
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
