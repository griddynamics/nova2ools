import httplib
import json
import os

import logging

from urlparse import urlparse

from exceptions import CommandError


LOG = logging.getLogger("nova2ools.client")


class EndpointNotFound(Exception):
    """Could not find Service or Region in Service Catalog."""
    pass


class TokenInfo(object):
    """Helper methods for dealing with a Keystone Token Info."""

    def __init__(self, resource_dict):
        self.token_info = resource_dict
        self.roles = None

    def get_token(self):
        return self.token_info['access']['token']['id']

    def get_roles(self):
        if self.roles is None:
            try:
                self.roles = set([role_ref["name"]
                    for role_ref in
                        self.token_info["access"]["user"]["roles"]])
            except KeyError:
                self.roles = set()
        return self.roles

    def url_for(self, attr=None, filter_value=None,
                    service_type='compute', endpoint_type='publicURL'):
        """Fetch the public URL from the Compute service for
        a particular endpoint attribute. If none given, return
        the first. See tests for sample service catalog."""
        if 'endpoints' in self.token_info:
            # We have a bastardized service catalog. Treat it special. :/
            for endpoint in self.token_info['endpoints']:
                if not filter_value or endpoint[attr] == filter_value:
                    return endpoint[endpoint_type]
            raise EndpointNotFound()

        # We don't always get a service catalog back ...
        if not 'serviceCatalog' in self.token_info['access']:
            raise EndpointNotFound()

        # Full catalog ...
        catalog = self.token_info['access']['serviceCatalog']

        for service in catalog:
            if service['type'] != service_type:
                continue

            endpoints = service['endpoints']
            for endpoint in endpoints:
                if not filter_value or endpoint[attr] == filter_value:
                    return endpoint[endpoint_type]

        raise EndpointNotFound()


class BaseClient(object):
    CHUNKSIZE = 65536

    ARGUMENTS = [
        (("--use-keystone",), {"action": "store_true", "help": "Keystone or Nova URL for authentication"}),
        (("--auth-url",), {"help": "Keystone or Nova URL for authentication"}),
        (("--glance-url",), {"help": "Glance managment url"}),
        (("--username", "-u"), {"help": "OpenStack user name"}),
        (("--password", "-p"), {"help": "OpenStack API password"}),
        (("--tenant-id",), {"help": "OpenStack Project(Tenant) ID"}),
        (("--tenant-name", "--project", "-t"), {"help": "OpenStack Project(Tenant) name"}),
        (("--token",), {"help": "OpenStack token"}),
        (("--endpoint",), {"help": "OpenStack endpoint"}),
        (("--debug",), {"action": "store_true", "help": "Run in debug mode"}),
    ]

    use_keystone = os.environ.get("USE_KEYSTONE", "False").lower() in ("1", "true", "yes")

    DEFAULTS = {
        "use_keystone": use_keystone,
        "auth_url": os.environ.get("OS_AUTH_URL", os.environ.get("NOVA_URL")),
        "glance_url":  os.environ.get("GLANCE_URL", "") if not use_keystone else "",
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
        self.token_info = None
        self.auth()

    def auth(self):
        if self.options.token:
            self.__token = self.options.token
        self.management_url = self.options.endpoint
        if not (self.options.token and self.options.endpoint):
            if not self.options.auth_url:
                raise CommandError(1, "Authentication URL is required")

            if self.options.use_keystone is None:
                raise CommandError(1, "You should select auth type (use_keystone parameter)")
            if self.options.use_keystone:
                self.auth_keystone()
            else:
                self.auth_nova()
        else:
            self.auth_headers = {
                "X-Auth-Token": self.__token,
            }

    def auth_nova(self):
        auth_headers = {
            "X-Auth-User": self.options.username,
            "X-Auth-Key": self.options.password,
            "X-Auth-Project-Id": self.options.tenant_name
        }
        resp, _ = self.request(self.options.auth_url, "GET", headers=auth_headers)
        self.__token = resp.getheader("X-Auth-Token")
        
        if not self.__token:
            raise CommandError(1, "You are not authorized")

        if not self.management_url:
            self.management_url = resp.getheader("X-Server-Management-Url")
        self.auth_headers = {
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
        _, access = self.request(
                self.options.auth_url + "/tokens",
                "POST",
                body=params,
                headers={"Content-Type": "application/json"})
        if access is None:
            raise CommandError(1, "You are not authenticated")
        self.token_info = TokenInfo(access)

        if not self.management_url and self.service_type:
            self.set_service_type(self.service_type)

        self.auth_headers = {
            "X-Auth-Token": self.token_info.get_token()
        }
        if not tenant_id:
            try:
                tenant_id = access['access']['token']['tenant']['id']
            except Exception:
                raise CommandError(1, "Response json object doesn't contain chain 'access->token->tenant->id'")
            self.options.tenant_id = tenant_id
        self.auth_headers["X-Tenant"] = tenant_id
        if tenant_name:
            self.auth_headers["X-Tenant-Name"] = tenant_name

    @property
    def auth_token(self):
        return self.auth_headers["X-Auth-Token"]

    @property
    def tenant_id(self):
        return self.options.tenant_id

    @property
    def username(self):
        return self.options.username

    def set_service_type(self, service_type, endpoint_type='publicURL'):
        self.management_url = self.url_for(
                    service_type=service_type, endpoint_type=endpoint_type)
        self.service_type = service_type

    def url_for(self, service_type, endpoint_type='publicURL'):
        try:
            return self.token_info.url_for(
            service_type=service_type, endpoint_type=endpoint_type)
        except EndpointNotFound:
            raise CommandError(1, "Could not find `%s' in service catalog" % service_type)

    def http_log(self, method, url, body, headers, resp, resp_body):
        if not self.options.debug:
            return

        string_parts = ["curl -i '%s' -X %s" % (url, method)]

        for element in headers:
            header = ' -H "%s: %s"' % (element, headers[element])
            string_parts.append(header)

        print "REQ: %s\n" % "".join(string_parts)
        if body:
            print "REQ BODY: %s\n" % body
        if resp:
            print "RESP: %s\n" % resp.status
        if resp_body:
            print "RESP BODY: %s\n" % resp_body

    def request(self, url, method, body=None, headers={}, read_body=True):
        if isinstance(body, (dict, list)):
            headers['Content-Type'] = 'application/json'
            body = json.dumps(body)

        resp, resp_body = None, None
        try:
            parsed = urlparse(url)
            client = httplib.HTTPConnection(parsed.netloc)
            request_uri = ("?".join([parsed.path, parsed.query])
                           if parsed.query
                           else parsed.path)
            # Do a simple request or a chunked request, depending
            # on whether the body param is a file-like object and
            # the method is PUT or POST
            if hasattr(body, 'read') and method.lower() in ('post', 'put'):
                # Chunk it, baby...
                client.putrequest(method, request_uri)
 
                for header, value in headers.items():
                    client.putheader(header, value)
                client.putheader('Transfer-Encoding', 'chunked')
                client.endheaders()
 
                chunk = body.read(self.CHUNKSIZE)
                while chunk:
                    client.send('%x\r\n%s\r\n' % (len(chunk), chunk))
                    chunk = body.read(self.CHUNKSIZE)
                client.send('0\r\n\r\n')
            else:
                # Simple request...
                client.request(method, request_uri, body, headers)

            resp = client.getresponse()
            if read_body:
                resp_body = resp.read()
        finally:
            self.http_log(method, url, body, headers, resp, resp_body)
        self.__validate_response(resp)
        try:
            resp_body = json.loads(resp_body)
        except TypeError, ValueError:
            pass
        return (resp, resp_body)

    def get(self, path):
        return self.request(self.management_url + path, "GET", headers=self.auth_headers)[1]

    def post(self, path, body):
        return self.request(self.management_url + path, "POST", body=body, headers=self.auth_headers)[1]

    def action(self, path):
        return self.request(self.management_url + path, "POST", headers=self.auth_headers)[1]

    def put(self, path, body):
        return self.request(self.management_url + path, "PUT", body=body, headers=self.auth_headers)[1]

    def delete(self, path):
        return self.request(self.management_url + path, "DELETE", headers=self.auth_headers)[1]

    def __validate_response(self, response):
        if response.status / 100 == 2:
            return
        if response.status == 400: # Bad Request
            json_response = json.loads(response.read())
            raise CommandError(1, "Bad Request: {0}".format(json_response["badRequest"]["message"]))
        if response.status / 100 == 4:
            raise CommandError(1, response.reason)
        raise CommandError(1, "Unhandled response code: %s (%s)" % (response.status, response.reason))
