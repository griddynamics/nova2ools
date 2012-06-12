import datetime

__author__ = 'pshkitin'

def convert_timestamps_to_datetimes(image_meta):
    """Returns image with timestamp fields converted to datetime objects."""
    for attr in ['created_at', 'updated_at', 'deleted_at']:
        if image_meta.get(attr):
            image_meta[attr] = _parse_glance_iso8601_timestamp(
                image_meta[attr])
    return image_meta


def _parse_glance_iso8601_timestamp(timestamp):
    """Parse a subset of iso8601 timestamps into datetime objects."""
    iso_formats = ['%Y-%m-%dT%H:%M:%S.%f', '%Y-%m-%dT%H:%M:%S']

    for iso_format in iso_formats:
        try:
            return datetime.datetime.strptime(timestamp, iso_format)
        except ValueError:
            pass

    raise ValueError(_('%(timestamp)s does not follow any of the '
                       'signatures: %(iso_formats)s') % locals())

def image_meta_to_http_headers(image_meta):
    """
    Returns a set of image metadata into a dict
    of HTTP headers that can be fed to either a Webob
    Request object or an httplib.HTTP(S)Connection object

    :param image_meta: Mapping of image metadata
    """
    headers = {}
    for k, v in image_meta.items():
        if v is None:
            v = ''
        if k == 'properties':
            for pk, pv in v.items():
                if pv is None:
                    pv = ''
                headers["x-image-meta-property-%s"
                % pk.lower()] = unicode(pv)
        else:
            headers["x-image-meta-%s" % k.lower()] = unicode(v)
    return headers

def get_image_meta_from_headers(response):
    """
    Processes HTTP headers from a supplied response that
    match the x-image-meta and x-image-meta-property and
    returns a mapping of image metadata and properties

    :param response: Response to process
    """
    result = {}
    properties = {}

    if hasattr(response, 'getheaders'):  # httplib.HTTPResponse
        headers = response.getheaders()
    else:  # webob.Response
        headers = response.headers.items()

    for key, value in headers:
        key = str(key.lower())
        if key.startswith('x-image-meta-property-'):
            field_name = key[len('x-image-meta-property-'):].replace('-', '_')
            properties[field_name] = value or None
        elif key.startswith('x-image-meta-'):
            field_name = key[len('x-image-meta-'):].replace('-', '_')
            result[field_name] = value or None
    result['properties'] = properties
    if 'size' in result:
        result['size'] = int(result['size'])
    if 'is_public' in result:
        result['is_public'] = bool_from_header_value(result['is_public'])
    if 'deleted' in result:
        result['deleted'] = bool_from_header_value(result['deleted'])
    return result

def bool_from_header_value(value):
    """
    Returns True if value is a boolean True or the
    string 'true', case-insensitive, False otherwise
    """
    if isinstance(value, bool):
        return value
    elif isinstance(value, (basestring, unicode)):
        if str(value).lower() == 'true':
            return True
    return False