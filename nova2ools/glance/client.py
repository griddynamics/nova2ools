import json
import errno
import os

import logging
import urllib

from nova2ools.glance.utils import image_meta_to_http_headers, get_image_meta_from_headers
from nova2ools.client import BaseClient


LOG = logging.getLogger(__name__)


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


class GlanceClient(BaseClient):

    """Main client class for accessing Glance resources"""

    DEFAULT_PORT = 9292
    DEFAULT_DOC_ROOT = "/v1"
    SUPPORTED_PARAMS = ('limit', 'marker', 'sort_key', 'sort_dir')

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
        data = self.do_request("GET", "/images", params=params)["images"]
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
        data = self.do_request("GET", "/images/detail", params=params)["images"]
        return data

    def get_image(self, image_id):
        """
        Returns a tuple with the image's metadata and the raw disk image as
        a mime-encoded blob stream for the supplied opaque image identifier.

        :param image_id: The opaque image identifier

        :retval Tuple containing (image_meta, image_blob)
        :raises exception.NotFound if image is not found
        """
        res = self.do_request("GET", "/images/%s" % image_id, read_body=False)

        image = get_image_meta_from_headers(res)
        return image, ImageBodyIterator(res)

    def get_image_meta(self, image_id):
        """
        Returns a mapping of image metadata from Registry

        :raises exception.NotFound if image is not in registry
        """
        res = self.do_request("HEAD", "/images/%s" % image_id, read_body=False)

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

        data = self.do_request("POST", "/images", body, headers)["image"]
        return data

    def do_request(self, method, action, body=None, headers={},
                   params=None, read_body=True):
        if isinstance(params, dict):
            params = [pair for pair in params.iteritems() if pair[1]]
            if params:
                action = "%s?%s" % (action, urllib.urlencode(params))
        headers = headers.copy()
        headers.update(self.auth_headers)
        (resp, resp_body) = self.request(self.management_url + action, method,
                            body=body, headers=headers, read_body=read_body)
        return resp_body if read_body else resp
