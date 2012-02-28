import json
import errno
import os
from nova2ools.exceptions import CommandError
from nova2ools.glance.utils import image_meta_to_http_headers, get_image_meta_from_headers

__author__ = 'pshkitin'

import httplib
import logging
import socket
import urllib
import urlparse

LOG = logging.getLogger("nova2ools.glance.client")


class ImageBodyIterator(object):

    """
    A class that acts as an iterator over an image file's
    chunks of data.  This is returned as part of the result
    tuple from `glance.client.Client.get_image`
    """

    CHUNKSIZE = 65536

    def __init__(self, response):
        """
        Constructs the object from an HTTPResponse object
        """
        self.response = response

    def __iter__(self):
        """
        Exposes an iterator over the chunks of data in the
        image file.
        """
        while True:
            chunk = self.response.read(ImageBodyIterator.CHUNKSIZE)
            if chunk:
                yield chunk
            else:
                break


class BaseClient(object):

    """A base client class"""

    CHUNKSIZE = 65536
    DEFAULT_PORT = 80
    DEFAULT_DOC_ROOT = None

    def __init__(self, host, port=None, use_ssl=False,
                 doc_root=None, auth_token=None, username=None, tenant_id=None, use_keystone=False):
        """
        Creates a new client to some service.

        :param host: The host where service resides
        :param port: The port where service resides
        :param use_ssl: Should we use HTTPS?
        :param doc_root: Prefix for all URLs we request from host
        :param auth_token: The auth token to pass to the server
        :param username: The name of current user
        :param tenant_id: Requests will be apply to this tenant
        :param use_keystone: Use or not keystone
        """
        self.host = host
        self.port = port or self.DEFAULT_PORT
        self.use_ssl = use_ssl
        self.connection = None
        self.doc_root = self.DEFAULT_DOC_ROOT if doc_root is None else doc_root
        self.auth_token = auth_token
        self.username = username
        self.tenant_id = tenant_id
        self.use_keystone = use_keystone

    def get_connection_type(self):
        """
        Returns the proper connection type
        """
        if self.use_ssl:
            return httplib.HTTPSConnection
        else:
            return httplib.HTTPConnection

    def do_request(self, method, action, body=None, headers=None,
                   params=None):
        headers = headers or {}

        return self._do_request(
                method, action, body=body, headers=headers, params=params)

    def _do_request(self, method, action, body=None, headers=None,
                    params=None):
        """
        Connects to the server and issues a request.

        :param method: HTTP method ("GET", "POST", "PUT", etc...)
        :param action: part of URL after root netloc
        :param body: string of data to send, or None (default)
        :param headers: mapping of key/value pairs to add as headers
        :param params: dictionary of key/value pairs to add to append
                             to action

        :note

        If the body param has a read attribute, and method is either
        POST or PUT, this method will automatically conduct a chunked-transfer
        encoding and use the body as a file object, transferring chunks
        of data using the connection's send() method. This allows large
        objects to be transferred efficiently without buffering the entire
        body in memory.
        """
        if type(params) is dict:

            # remove any params that are None
            for (key, value) in params.items():
                if value is None:
                    del params[key]

            action += '?' + urllib.urlencode(params)

        try:
            connection_type = self.get_connection_type()
            headers = headers or {}

            if self.use_keystone:
                if 'X-Auth-Token' not in headers and self.auth_token:
                    headers['X-Auth-Token'] = self.auth_token

                if 'X-User' not in headers and self.username:
                    headers['X-User'] = self.username

                if 'X-Tenant' not in headers and self.tenant_id:
                    headers['X-Tenant'] = self.tenant_id

            c = connection_type(self.host, self.port)

            if self.doc_root:
                action = '/'.join([self.doc_root, action.lstrip('/')])

            # Do a simple request or a chunked request, depending
            # on whether the body param is a file-like object and
            # the method is PUT or POST
            if hasattr(body, 'read') and method.lower() in ('post', 'put'):
                # Chunk it, baby...
                c.putrequest(method, action)

                for header, value in headers.items():
                    c.putheader(header, value)
                c.putheader('Transfer-Encoding', 'chunked')
                c.endheaders()

                chunk = body.read(self.CHUNKSIZE)
                while chunk:
                    c.send('%x\r\n%s\r\n' % (len(chunk), chunk))
                    chunk = body.read(self.CHUNKSIZE)
                c.send('0\r\n\r\n')
            else:
                # Simple request...
                c.request(method, action, body, headers)
            res = c.getresponse()
            status_code = self.get_status_code(res)
            if status_code in (httplib.OK,
                               httplib.CREATED,
                               httplib.ACCEPTED,
                               httplib.NO_CONTENT):
                return res
            else:
                LOG.info("Not normal request result: %s" % res.read())
                if status_code == httplib.UNAUTHORIZED:
                    raise CommandError(1, "User not authorized")
                elif status_code == httplib.FORBIDDEN:
                    raise CommandError(1, "User not authorized")
                elif status_code == httplib.NOT_FOUND:
                    raise CommandError(1, "Not found")
                elif status_code == httplib.CONFLICT:
                    raise CommandError(1, "Bad request. Duplicate data")
                elif status_code == httplib.BAD_REQUEST:
                    raise CommandError(1, "Bad request")
                elif status_code == httplib.MULTIPLE_CHOICES:
                    raise CommandError(1, "Multiple choices")
                elif status_code == httplib.INTERNAL_SERVER_ERROR:
                    raise CommandError(1, "Internal Server error")
                else:
                    raise CommandError(1, "Unknown error occurred")

        except (socket.error, IOError), e:
            LOG.info("Unable to connect to server. Got error: %s" % e)
            raise CommandError(1, "Unable to connect to server")

    def get_status_code(self, response):
        """
        Returns the integer status code from the response, which
        can be either a Webob.Response (used in testing) or httplib.Response
        """
        if hasattr(response, 'status_int'):
            return response.status_int
        else:
            return response.status

    def _extract_params(self, actual_params, allowed_params):
        """
        Extract a subset of keys from a dictionary. The filters key
        will also be extracted, and each of its values will be returned
        as an individual param.

        :param actual_params: dict of keys to filter
        :param allowed_params: list of keys that 'actual_params' will be
                               reduced to
        :retval subset of 'params' dict
        """
        try:
            # expect 'filters' param to be a dict here
            result = dict(actual_params.get('filters'))
        except TypeError:
            result = {}

        for allowed_param in allowed_params:
            if allowed_param in actual_params:
                result[allowed_param] = actual_params[allowed_param]

        return result


class GlanceClient(BaseClient):

    """Main client class for accessing Glance resources"""

    DEFAULT_PORT = 9292
    DEFAULT_DOC_ROOT = "/v1"
    SUPPORTED_PARAMS = ('limit', 'marker', 'sort_key', 'sort_dir')

    def get_images(self, **kwargs):
        """
        Returns a list of image id/name mappings from Registry

        :param filters: dictionary of attributes by which the resulting
                        collection of images should be filtered
        :param marker: id after which to start the page of images
        :param limit: maximum number of items to return
        :param sort_key: results will be ordered by this image attribute
        :param sort_dir: direction in which to to order results (asc, desc)
        """
        params = self._extract_params(kwargs, self.SUPPORTED_PARAMS)
        res = self.do_request("GET", "/images", params=params)
        data = json.loads(res.read())['images']
        return data

    def get_images_detailed(self, **kwargs):
        """
        Returns a list of detailed image data mappings from Registry

        :param filters: dictionary of attributes by which the resulting
                        collection of images should be filtered
        :param marker: id after which to start the page of images
        :param limit: maximum number of items to return
        :param sort_key: results will be ordered by this image attribute
        :param sort_dir: direction in which to order results (asc, desc)
        """
        params = self._extract_params(kwargs, self.SUPPORTED_PARAMS)
        res = self.do_request("GET", "/images/detail", params=params)
        data = json.loads(res.read())['images']
        return data

    def get_image(self, image_id):
        """
        Returns a tuple with the image's metadata and the raw disk image as
        a mime-encoded blob stream for the supplied opaque image identifier.

        :param image_id: The opaque image identifier

        :retval Tuple containing (image_meta, image_blob)
        :raises exception.NotFound if image is not found
        """
        res = self.do_request("GET", "/images/%s" % image_id)

        image = get_image_meta_from_headers(res)
        return image, ImageBodyIterator(res)

    def get_image_meta(self, image_id):
        """
        Returns a mapping of image metadata from Registry

        :raises exception.NotFound if image is not in registry
        """
        res = self.do_request("HEAD", "/images/%s" % image_id)

        image = get_image_meta_from_headers(res)
        return image

    def add_image(self, image_meta=None, image_data=None):
        """
        Tells Glance about an image's metadata as well
        as optionally the image_data itself

        :param image_meta: Optional Mapping of information about the
                           image
        :param image_data: Optional string of raw image data
                           or file-like object that can be
                           used to read the image data

        :retval The newly-stored image's metadata.
        """
        headers = image_meta_to_http_headers(image_meta or {})

        if image_data:
            body = image_data
            headers['content-type'] = 'application/octet-stream'
            # For large images, we need to supply the size of the
            # image file. See LP Bug #827660.
            if hasattr(image_data, 'seek') and hasattr(image_data, 'tell'):
                try:
                    image_data.seek(0, os.SEEK_END)
                    image_size = image_data.tell()
                    image_data.seek(0)
                    headers['x-image-meta-size'] = image_size
                    headers['content-length'] = image_size
                except IOError, e:
                    if e.errno == errno.ESPIPE:
                        # Illegal seek. This means the user is trying
                        # to pipe image data to the client, e.g.
                        # echo testdata | bin/glance add blah..., or
                        # that stdin is empty
                        pass
                    else:
                        raise
        else:
            body = None

        res = self.do_request("POST", "/images", body, headers)
        data = json.loads(res.read())
        return data['image']