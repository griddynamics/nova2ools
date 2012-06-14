from datetime import datetime
import base64
import urlparse
import os
import sys
import urllib
from nova2ools import utils

from argparse import ArgumentParser
from inspect import ismethod
from itertools import ifilter
import re

from client import BaseClient
from exceptions import CommandError
from exceptions import handle_command_error
from nova2ools import VERSION
from nova2ools.glance.client import GlanceClient
from nova2ools.glance.utils import convert_timestamps_to_datetimes
from nova2ools.utils import generate_password


__all__ = []


def export(function):
    global __all__
    __all__.append(function.__name__)
    return function


def CliCommandMetaclass(name, bases, dict):
    global __all__
    __all__.append(name)
    return type(name, bases, dict)


__all__.append("CliCommand")


class ArgumentException(Exception):
    def __init__(self, message):
        self.message = message


class NovaArgumentParser(ArgumentParser):

    def __init__(self, *args, **kwargs):
        self.default_param = kwargs.pop("default_param", "list")
        super(NovaArgumentParser, self).__init__(*args, **kwargs)

    def error(self, message):
        raise ArgumentException(message)

    def parse_args(self, args=None, namespace=None):
        try:
            return super(NovaArgumentParser, self).parse_args(args, namespace)
        except ArgumentException as e:
            if "too few arguments" not in e.message:
                super(NovaArgumentParser, self).error(e.message)
            try:
                if args is None:
                    args = sys.argv[1:]
                args.append(self.default_param)
                return super(NovaArgumentParser, self).parse_args(args, namespace)
            except ArgumentException as e:
                super(NovaArgumentParser, self).error(e.message)


class CliCommand(object):
    __common_args = [
        (
            ("--version", "-v"),
            {
                "action": "version",
                "version": "Nova2ools Version: {0}".format(VERSION),
                "help": "Show version",
            },
        )
    ]
    __common_defaults = {}

    DEFAULT_COMMAND = 'list'

    @handle_command_error
    def __init__(self, help, client_class=BaseClient, **kwargs):
        self.__help = help
        self.__parser = self.__generate_options_parser(client_class)
        self.parse_args()
        self.client = client_class(self.options, **kwargs)
        self.tenant_by_id = None

    @handle_command_error
    def run(self):
        self.options.subcommand()

    def get(self, path=""):
        return self.client.get(getattr(self, "RESOURCE", "") + path)

    def post(self, path, body=None):
        return self.client.post(getattr(self, "RESOURCE", "") + path, body)

    def put(self, path, body):
        return self.client.put(getattr(self, "RESOURCE", "") + path, body)

    def delete(self, path):
        return self.client.delete(getattr(self, "RESOURCE", "") + path)

    def parse_args(self):
        self.options = self.__parser.parse_args()

    def __generate_options_parser(self, client):
        parser = NovaArgumentParser(description=self.__help, default_param=self.DEFAULT_COMMAND)
        for i in self.__common_args:
            parser.add_argument(*i[0], **i[1])
        for i in client.ARGUMENTS:
            parser.add_argument(*i[0], **i[1])
        parser.set_defaults(**self.__common_defaults)
        parser.set_defaults(**client.DEFAULTS)
        subparsers = None
        for attr in (getattr(self, i) for i in dir(self) if not i.startswith("_")):
            if not ismethod(attr) or not getattr(attr, "subcommand", False):
                continue
            if subparsers is None:
                subparsers = parser.add_subparsers()
            subparser = subparsers.add_parser(attr.subcommand_name, help=attr.subcommand_help)
            for arg in getattr(attr, "subcommand_args", ()):
                subparser.add_argument(*arg[0], **arg[1])
            subparser.set_defaults(subcommand=attr)
        return parser

    def is_valid_id(self, id):
        if id.isdigit() or re.match(r'[a-z0-9]{8}-([a-z0-9]{4}-){3}[a-z0-9]{12}', id):
            return True
        return False

    def get_server(self, identifier):
        if self.is_valid_id(identifier):
            return self.get_server_by_id(identifier)
        return self.get_server_by_name(identifier)

    def get_server_by_name(self, name):
        servers = self.client.get("/servers/detail?name={0}".format(name))["servers"]
        filtered_servers = [server for server in servers if server["name"] == name]
        if len(filtered_servers) < 1:
            raise CommandError(1, "VM `{0}` is not found".format(name))
        if len(filtered_servers) > 1:
            msg = "More then one({0}) server with `{1}` name (use `id` instead of name)".format(len(servers), name)
            raise CommandError(1, msg)
        return filtered_servers[0]

    def get_server_by_id(self, id):
        server = self.client.get("/servers/{0}".format(id))["server"]
        if len(server) < 1:
            raise CommandError(1, "VM `{0}` is not found".format(id))
        return server

    def get_flavor(self, identifier):
        if not identifier.isdigit():
            return self.get_flavor_by_name(identifier)
        return self.get_flavor_by_id(identifier)

    def get_flavor_by_name(self, name):
        flavors = self.client.get("/flavors/detail")["flavors"]
        res = filter(lambda flavor: flavor.get('name') == name, flavors)
        if len(res) < 1:
            raise CommandError(1, "Flavor `{0}` is not found".format(name))
        if len(res) > 1:
            msg = "More then one({0}) flavor with `{1}` name (use `id` instead of name)".format(len(flavors), name)
            raise CommandError(1, msg)
        return res[0]

    def get_flavor_by_id(self, id):
        flavor = self.client.get("/flavors/{0}".format(id))["flavor"]
        if not flavor:
            raise CommandError(1, "Flavor `{0}` is not found".format(id))
        return flavor

    def get_image(self, identifier):
        if not self.is_valid_id(identifier):
            return self.get_image_by_name(identifier)
        return self.get_image_by_id(identifier)

    def get_image_by_name(self, name):
        images = self.client.get("/images/detail?name={0}".format(name))["images"]
        filtered_images = [image for image in images if image["name"] == name]
        if len(filtered_images) < 1:
            raise CommandError(1, "Image `{0}` is not found".format(name))
        if len(filtered_images) > 1:
            msg = "More then one({0}) image with `{1}` name (use `id` instead of name)".format(len(images), name)
            raise CommandError(1, msg)
        return filtered_images[0]

    def get_image_by_id(self, id):
        image = self.client.get("/images/{0}".format(id))["image"]
        return image

    def get_security_group_by_name(self, name):
        sgroups = self.client.get("/os-security-groups")["security_groups"]
        for sg in sgroups:
            if sg["name"] == name:
                return sg
        raise CommandError(1, "Security Group `{0}` is not found".format(name))

    def get_tenant_name_by_id(self, tenant_id):
        if not self.client.token_info:
            return tenant_id
        if self.tenant_by_id is None:
            client = self.client
            service_type = client.service_type
            self.tenant_by_id = {}
            try:
                client.set_service_type(
                        "identity",
                        "adminURL"
                        if "Admin" in
                        client.token_info.get_roles()
                        else "publicURL")
                self.tenant_by_id = dict(
                    [
                        (tenant["id"], tenant["name"])
                        for tenant in client.get("/tenants?limit=10000")["tenants"]
                    ]
                )
            except CommandError:
                pass
            client.set_service_type(service_type)
        return self.tenant_by_id.get(tenant_id, "#{0}".format(tenant_id))

    def save_list(self, name, collection):
        home = os.environ.get("HOME", "")
        with open("%s/.nova2ools" % home, "a+") as datafile:
            lines = ["%s='%s'\n" %(name, ' '.join(collection))]

            for line in datafile:
                if not line.isspace() and not line.startswith(name):
                    lines.append(line)

            datafile.seek(0)
            datafile.truncate()
            datafile.write("".join(lines) + "\n")


@export
def subcommand(help, name=None):
    def decorator(method):
        method.subcommand = True
        method.subcommand_help = help
        method.subcommand_name = name or method.__name__
        return method

    return decorator


@export
def add_argument(*args, **kwargs):
    def decorator(method):
        if not hasattr(method, "subcommand_args"):
            method.subcommand_args = []
        method.subcommand_args.insert(0, (args, kwargs))
        return method

    return decorator


################################################################################


class FlavorsCommand(CliCommand):
    __metaclass__ = CliCommandMetaclass

    RESOURCE = "/flavors"

    def __init__(self):
        CliCommand.__init__(self, "Show available flavors for the project")

    @subcommand("List available flavors")
    def list(self):
        flavors = self.get("/detail")
        for flv in flavors["flavors"]:
            sys.stdout.write("{id}: {name} ram:{ram} vcpus:{vcpus} swap:{swap} disc:{disk}\n".format(**flv))
        namelist = [flv["name"] for flv in flavors["flavors"]]
        self.save_list("FLAVORS", namelist)


class ImagesCommand(CliCommand):
    __metaclass__ = CliCommandMetaclass

    RESOURCE = "/images"

    @handle_command_error
    def __init__(self):
        super(ImagesCommand, self).__init__(
            "Manage images available for the project",
            GlanceClient, service_type="image")

    @subcommand("List available images")
    @add_argument(
        "-f", "--format",
        default="{name:20} {id} {type} {status:10}",
        help="Set output format. The format syntax is the same as for Python `str.format` method. " +
             "Available variables: `id`, `name`, `created_at`, `updated_at`, `type`, `status`, " \
             "`size`, `checksum`, `is_public`, `metadata`. Default format: " +
             "\"{name:20} {id} {type} {status:10}\""
    )
    @add_argument("-m", "--metadata", action="store_true", default=False, help="Include metadata information to output")
    @add_argument("--limit", type=int, default=20, help="Maximum number of items to return")
    @add_argument("--marker", type=int, help="id after which to start the page of images")
    @add_argument("--sort-key",
        choices=['id', 'name', 'created_at', 'updated_at', 'status', 'size'],
        help="Results will be ordered by this image attribute")
    @add_argument("--sort-dir", metavar="<asc|desc>", choices=['asc', 'desc'], default="asc",
        help="Direction in which to order results (asc, desc)")
    def list(self):
        limit = self.options.limit
        marker = self.options.marker
        sort_key = self.options.sort_key
        sort_dir = self.options.sort_dir

        params = {"limit": limit,
                  "marker": marker,
                  "sort_key": sort_key,
                  "sort_dir": sort_dir}

        images = self.client.get_images_detailed(**params)
        format = self.options.format
        for img in ifilter(self.__filter_images, images):
            img = convert_timestamps_to_datetimes(img)
            self.__print_image_format(format, img)
            if self.options.metadata and len(img["properties"]) > 0:
                first = True
                for key, value in img["properties"].items():
                    if first:
                        sys.stdout.write("Metadata: {0:5} -> {1}\n".format(key, value))
                        first = False
                    else:
                        sys.stdout.write("          {0:14} -> {1}\n".format(key, value))

        namelist = [image["name"] for image in images]
        self.save_list("IMAGES", namelist)

    @subcommand("Register all images to glance", name="register-all")
    @add_argument('--image', metavar='<image>', help='Path to image')
    @add_argument('--kernel', metavar='<kernel>', help='Path to kernel')
    @add_argument('--ramdisk', metavar='<ramdisk>', help='Path to RAM disk')
    @add_argument('--name', metavar='<name>', help='Image name')
    @add_argument('--public', action="store_true", default=False,
        help='Allow use image from other tenants')
    @add_argument('--arch', metavar='<arch>', default='x86_64', help='Architecture')
    def register_all(self):
        """Uploads an image, kernel, and ramdisk into the image_service"""
        image_path = self.options.image
        kernel_path = self.options.kernel
        ramdisk_path = self.options.ramdisk
        name = self.options.name
        public = self.options.public
        architecture = self.options.arch
        owner = self.client.username

        kernel_id = self._register('aki', 'aki', kernel_path, owner,
            public=public, architecture=architecture)

        ramdisk_id = self._register('ari', 'ari', ramdisk_path, owner,
            public=public, architecture=architecture)

        self._register( 'ami', 'ami', image_path, owner, name, public,
            architecture, kernel_id, ramdisk_id)


    @subcommand("Register image to glance", name="register")
    @add_argument('--path', metavar='<path>', required=True, help='Image path')
    @add_argument('--name', metavar='<name>', help='Image name')
    @add_argument('--public', action="store_true", default=False,
        help='Allow use image from other tenants')
    @add_argument('--arch', metavar='<arch>', default='x86_64',
        help='Architecture')
    @add_argument('--cont-format', dest='container_format', default='bare',
        metavar='<container format>',
        help='Container format(default bare)')
    @add_argument('--disk-format', metavar='<disk format>', default='raw',
        help='Disk format(default: raw)')
    @add_argument('--kernel', dest='kernel_id', metavar='<kernel>', help='Kernel id')
    @add_argument('--ramdisk', dest='ramdisk_id', metavar='<ramdisk>', help='RAM disk id')
    def image_register(self):
        """Uploads an image into the image_service"""

        path = self.options.path
        owner = self.client.username
        name = self.options.name
        public = self.options.public
        architecture = self.options.arch
        container_format = self.options.container_format
        disk_format = self.options.disk_format
        kernel_id = self.options.kernel_id
        ramdisk_id = self.options.ramdisk_id

        return self._register(container_format, disk_format, path,
            owner, name, public, architecture,
            kernel_id, ramdisk_id)

    @subcommand("Register kernel image to glance", name="register-kernel")
    @add_argument('--path', metavar='<path>', required=True, help='Image path')
    @add_argument('--name', metavar='<name>', help='Image name')
    @add_argument('--public', action="store_true", default=False,
        help='Allow use image from other tenants')
    @add_argument('--arch', metavar='<arch>', default='x86_64',
        help='Architecture')
    def kernel_register(self):
        """Uploads a kernel into the image_service"""
        path = self.options.path
        owner = self.client.username
        name = self.options.name
        public = self.options.public
        architecture = self.options.arch

        return self._register('aki', 'aki', path, owner, name,
            public, architecture)

    @subcommand("Register ramdisk image to glance", name="register-ramdisk")
    @add_argument('--path', metavar='<path>', required=True, help='Image path')
    @add_argument('--name', metavar='<name>', help='Image name')
    @add_argument('--public', action="store_true", default=False,
        help='Allow use image from other tenants')
    @add_argument('--arch', metavar='<arch>', default='x86_64',
        help='Architecture')
    def ramdisk_register(self):
        """Uploads a ramdisk into the image_service"""
        path = self.options.path
        owner = self.client.username
        name = self.options.name
        public = self.options.public
        architecture = self.options.arch

        return self._register('ari', 'ari', path, owner, name,
            public, architecture)

    def _register(self, container_format, disk_format,
                  path, owner, name=None, public=False,
                  architecture='x86_64', kernel_id=None, ramdisk_id=None):
        meta = {'is_public': public,
                'name': name,
                'container_format': container_format,
                'disk_format': disk_format,
                'properties': {'image_state': 'available',
                               'project_id': owner,
                               'architecture': architecture,
                               'image_location': 'local'}}
        if kernel_id:
            meta['properties']['kernel_id'] = kernel_id
        if ramdisk_id:
            meta['properties']['ramdisk_id'] = ramdisk_id
        try:
            with open(path) as ifile:
                image = self.client.add_image(meta, ifile)
            new = image['id']
            print "Image registered to %(new)." % locals()
            return new
        except Exception as exc:
            print "Failed to register %(path)s: %(exc)s" % locals()


    @staticmethod
    def __filter_images(img):
        return (
            img["name"] is not None
            and img["status"] == "active"
            )

    def __print_image_format(self, format, image):
        id          = image["id"]
        name        = image["name"]
        created_at  = image["created_at"]
        updated_at  = image["updated_at"]
        status      = image["status"]
        type        = image['container_format']
        size        = str(image['size']) + 'b'
        checksum    = image['checksum']
        is_public   = image['is_public']

        metadata = ", ".join(
            (
                "{0}={1}".format(k, v)
                for k, v in image["properties"].items()
            )
        )
        info = dict(locals())
        del info["self"]
        del info["image"]
        del info["format"]
        sys.stdout.write(format.format(**info))
        sys.stdout.write("\n")


class SshKeysCommand(CliCommand):
    __metaclass__ = CliCommandMetaclass

    RESOURCE = "/os-keypairs"

    def __init__(self):
        super(SshKeysCommand, self).__init__("Manage SSH Key Pairs")

    @subcommand("Register existing key")
    @add_argument("keyname", help="Key registration name")
    @add_argument("public_key", type=file, help="SSH Public Key file")
    def register(self):
        request = {
            "keypair": {
                "name": self.options.keyname,
                "public_key": self.options.public_key.read()
            }
        }
        self.post("", request)

    @subcommand("Generate a new SSH Key Pair (Private key will be printed to standard output)")
    @add_argument("key", help="A new key name")
    def generate(self):
        request = {
            "keypair": {
                "name": self.options.key
            }
        }
        keypair = self.post("", request)
        sys.stdout.write(keypair["keypair"]["private_key"])

    @subcommand("Remove SSH Key from OpenStack")
    @add_argument("key", help="Existing key name")
    def remove(self):
        self.delete("/{0}".format(self.options.key))

    @subcommand("List existing keys")
    def list(self):
        keys = self.get()
        for key in keys["keypairs"]:
            sys.stdout.write("{keypair[name]}: {keypair[fingerprint]}\n".format(**key))
        namelist = [key["keypair"]["name"] for key in keys["keypairs"]]
        self.save_list("SSH_KEYS", namelist)

    @subcommand("Print public key to standard output", "print-public")
    @add_argument("key", help="Existing key name")
    def print_public(self):
        keys = self.get()
        for key in keys["keypairs"]:
            if key["keypair"]["name"] == self.options.key:
                sys.stdout.write(key["keypair"]["public_key"])
                return
        raise CommandError(1, "key not found")


class VmsCommand(CliCommand):
    __metaclass__ = CliCommandMetaclass

    RESOURCE = "/servers"

    def __init__(self):
        super(VmsCommand, self).__init__("Manage Virtual Machines")
        self.__images = {}
        self.__flavors = {}

    @subcommand("Remove Virtual Machine")
    @add_argument("vm", help="VM id or name")
    def remove(self):
        srv = self.get_server(self.options.vm)
        self.delete("/{0}".format(srv["id"]))
        print "Instance {0} successfully removed".format(srv["id"])

    @subcommand("Show information about VM")
    @add_argument("vm", help="VM id or name")
    @add_argument("-H", "--show-host", default=False, action="store_true", help="Show host for image (admin only)")
    def show(self):
        srv = self.get_server(self.options.vm)

        self.__print_vm_detail(srv)

    @subcommand("Spawn a new VM")
    @add_argument("-n", "--name", required=True, help="VM name")
    @add_argument("-i", "--image", required=True, help="Image to use (id or name)")
    @add_argument("-f", "--flavor", required=True, help="Flavor to use")
    @add_argument("-p", "--admin-password", help="Administrator Password")
    @add_argument("-m", "--metadata", nargs="*", help="Server Metadata")
    @add_argument("-k", "--keyname", help="Registered SSH Key Name")
    @add_argument("-j", "--inject", nargs="*", help="Inject file to image (personality)")
    @add_argument("-s", "--security-groups", nargs="*", help="Apply security groups to a new VM")
    def spawn(self):
        img = self.get_image(self.options.image)
        flv = self.get_flavor(self.options.flavor)
        srvDesc = {
            "name": self.options.name,
            "imageRef": img["links"][0]["href"],
            "flavorRef": flv["id"],
            "adminPass": self.options.admin_password or generate_password(16)
        }

        if self.options.metadata is not None:
            srvDesc["metadata"] = self.__generate_metadata_dict(self.options.metadata)
        if self.options.keyname is not None:
            srvDesc["key_name"] = self.options.keyname
        if self.options.inject is not None:
            srvDesc["personality"] = self.__generate_personality(self.options.inject)
        if self.options.security_groups is not None:
            srvDesc["security_groups"] = [{"name": i} for i in self.options.security_groups]
        srv = self.post("", {"server": srvDesc})["server"]
        srv_details = self.get_server(srv["id"])
        self.__print_vm_detail(srv_details)

    @subcommand("List spawned VMs")
    @add_argument(
        "-f", "--format",
        default="{name:20} {id} {user_id:15} {tenant_name:10} {status:10} {key_name:15}",
        help="Set output format. The format syntax is the same as for Python `str.format` method. " +
        "Available variables: `id`, `name`, `created`, `updated`, `user_id`, `status`, `tenant_id`, `tenant_name`, " +
        "`fixed_addresses`, `float_addresses`, `image_id`. Default format: " +
        "\"{name:20} {id} {user_id:15} {tenant_name:10} {status:10} {key_name:15}\""
    )
    @add_argument("-d", "--details", default=False, action="store_true", help="Print detailed information about VM")
    def list(self):
        response = self.get("/detail")
        servers = response["servers"]
        for srv in servers:
            if self.options.details:
                self.__print_vm_detail(srv)
            else:
                self.__print_vm_format(self.options.format, srv)
        namelist = [srv["name"] for srv in servers]
        self.save_list("VMS", namelist)

    @subcommand("Migrate VM")
    @add_argument("vm", help="VM id or name")
    @add_argument("--no-block-migration", action="store_true", default=False, help="Disable block migration " \
                                                                                   "in case of live migration")
    @add_argument("--live-migration", action="store_true", default=False, help="Perform live migration")
    @add_argument("-d", "--destination", help="Migration destination hostname")
    def migrate(self):
        srv = self.get_server(self.options.vm)
        if not self.options.live_migration:
            url ="/%s/migrate" % srv['id']
            return self.post(url)
        else:
            url = "/%s/action" % srv['id']
            if not self.options.destination:
                CommandError(1, "You must specify --destination <host> along with --live-migration")
            return self.post(url, {"live_migrate": {
                "block_migration": not self.options.no_block_migration,
                "destination": self.options.destination
            }})

    @subcommand("Get security groups")
    @add_argument("vm", help="VM id or name")
    def get_security_groups(self):
        srv = self.get_server(self.options.vm)
        url = "/%s/list_security_groups" % srv['id']
        res = self.get(url)
        print "VM %s is in next security groups:" % srv['id']
        for group in res['result']:
            print group

    def get_image_detail(self, id):
        return self.__get_detail_cached(id, "/images", self.__images)["image"]

    def get_flavor_detail(self, id):
        return self.__get_detail_cached(id, "/flavors", self.__flavors)["flavor"]

    def __get_detail_cached(self, id, prefix, cache):
        if id not in cache:
            cache[id] = self.client.get("{0}/{1}".format(prefix, id))
        return cache[id]

    def __print_vm_format(self, format, vm):
        id = vm["id"]
        name = vm["name"]
        created = vm["created"]
        updated = vm["updated"]
        user_id = vm["user_id"]
        status = vm["status"]
        tenant_id = vm["tenant_id"]
        tenant_name = self.get_tenant_name_by_id(vm["tenant_id"])
        image_id = vm["image"]["id"]
        key_name = vm["key_name"]
        info = dict(locals())
        del info["self"]
        del info["vm"]
        del info["format"]
        sys.stdout.write(format.format(**info))
        sys.stdout.write("\n")

    def __print_vm_detail(self, srv):
        try:
            img = self.get_image_detail(srv["image"]["id"])
        except CommandError as e:
            pass
        flv = self.get_flavor_detail(srv["flavor"]["id"])
        sys.stdout.write(
            "{name}({id}): user:{user_id} project:{tenant_name} key:{key_name} {status}\n"
            .format(
                tenant_name=self.get_tenant_name_by_id(srv["tenant_id"]),
                **srv
            )
        )
        if "adminPass" in srv:
            print "  Admin Password: {0}".format(srv["adminPass"])
        first = True
        for net_id, addrs in srv["addresses"].items():
            for addr in addrs:
                type = "float"
                if addr.get("fixed", None):
                    type = "fixed"
                if first:
                    prefix = "       Addresses:"
                    first = False
                else:
                    prefix = "                 "
                print "{prefix} {addr[addr]}(v{addr[version]}) net:{net_id} {type}".format(**locals())
        if self.options.show_host:
            print "            Host: ", srv.get("OS-EXT-SRV-ATTR:host")
        if img:
            print "           Image: ", img["name"],
        try:
            print "({metadata[architecture]})".format(**img)
        except KeyError:
            print ""
        print "          Flavor: {name} ram:{ram} vcpus:{vcpus} disk:{disk} swap:{swap}".format(**flv)

        if len(srv["metadata"]) > 0:
            first = True
            for key, value in srv["metadata"].items():
                if first:
                    print "        Metadata: {0}={1}".format(key, value)
                    first = False
                else:
                    print "                  {0}={1}".format(key, value)

    @staticmethod
    def __generate_metadata_dict(metadata):
        def split(value):
            eq_index = value.index("=")
            return value[:eq_index], value[eq_index + 1:]

        return dict((split(i) for i in metadata))

    @staticmethod
    def __generate_personality(inject):
        def split(value):
            eq_index = value.index("=")
            path = value[eq_index + 1:]
            path = os.path.abspath(os.path.expanduser(path))
            return {
                "path": value[:eq_index],
                "contents": base64.b64encode(str(open(path).read()))
            }

        return [split(i) for i in inject]


class SecGroupsCommand(CliCommand):
    __metaclass__ = CliCommandMetaclass

    RESOURCE = "/os-security-groups"

    def __init__(self):
        super(SecGroupsCommand, self).__init__("Manage Security Groups (Firewall)")

    @subcommand("Create Security Group")
    @add_argument("name", help="Security Group Name")
    @add_argument("description", help="Security Group Description")
    def create(self):
        request = {
            "security_group": {
                "name": self.options.name,
                "description": self.options.description
            }
        }
        self.post("", request)

    @subcommand("List Security Groups")
    def list(self):
        sg_names = []
        for sg in self.get()["security_groups"]:
            sys.stdout.write(self.__format(sg))
            sg_names.append(sg["name"])
        self.save_list("SGROUPS", sg_names)

    @subcommand("Show Security Group Details")
    @add_argument("name", help="Security Group Name")
    def show(self):
        sg = self.get_security_group_by_name(self.options.name)
        sys.stdout.write(self.__format(sg))

    @subcommand("Delete Security Group")
    @add_argument("name", help="Security Group Name")
    def remove(self):
        sg = self.get_security_group_by_name(self.options.name)
        self.delete("/{id}".format(**sg))

    @subcommand("Add Rule to Security Group", "add-rule")
    @add_argument("group", help="Security Group to add a new Rule")
    @add_argument("--port", help="Single IP Port or Range in FROM:TO format (ignored for `ICMP` protocol)")
    @add_argument("-p", "--protocol", required=True, help="IP Protocol (`TCP`, `UDP` or `ICMP`)")
    @add_argument("-a", "--from-address", help="IP Subnet in CIRD notation (IP/MASK) to allow access from")
    def add_rule(self):
        group = self.get_security_group_by_name(self.options.group)
        if self.options.port is not None:
            if ":" in self.options.port:
                from_port, to_port = self.options.port.split(":")
            else:
                from_port = to_port = self.options.port
        else:
            from_port = -1
            to_port = -1
        rule = {
            "parent_group_id": group["id"],
            "from_port": from_port,
            "to_port": to_port,
            "ip_protocol": self.options.protocol,
            "cidr": self.options.from_address
        }
        self.client.post("/os-security-group-rules", {"security_group_rule": rule})

    @subcommand("Allow connections from VMs of different Security Group", "allow-group")
    @add_argument("group", help="Security Group where a Rule will be created")
    @add_argument("allow_group", metavar="allow-group", help="Security Group where a Rule will be created")
    def allow_group(self):
        group = self.get_security_group_by_name(self.options.group)
        rule = {
            "parent_group_id": group["id"]
        }
        allow_group = self.get_security_group_by_name(self.options.allow_group)
        rule["group_id"] = allow_group["id"]
        self.client.post("/os-security-group-rules", {"security_group_rule": rule})

    @subcommand("Remove rule from Security Group by ID", "remove-rule")
    @add_argument("id", help="Rule ID")
    def remove_rule(self):
        self.client.delete("/os-security-group-rules/{0}".format(self.options.id))

    @subcommand("Remove all rules from Security Group", "clean-group")
    @add_argument("name", help="Security Group Name")
    def clean_group(self):
        sg = self.get_security_group_by_name(self.options.name)
        for rule in sg["rules"]:
            self.client.delete("/os-security-group-rules/{id}".format(**rule))

    @subcommand("Remove all Security Groups except `default` and all rules in `deafult` Security Group")
    def clean(self):
        groups = self.get()["security_groups"]
        for sg in groups:
            if sg["name"] == "default":
                continue
            self.delete("/{id}".format(**sg))
        sg = self.get_security_group_by_name("default")
        for rule in sg["rules"]:
            self.client.delete("/os-security-group-rules/{id}".format(**rule))

    def __format(self, sg):
        result = []
        tenant_name=self.get_tenant_name_by_id(sg["tenant_id"])
        put = result.append
        put("{name}({tenant_name}): {description}\n".format(tenant_name=tenant_name, **sg))
        for rule in sg["rules"]:
            if len(rule["group"]) > 0:
                fmt = "    {id}: GROUP({group[name]})\n"
            elif rule["ip_protocol"] == "ICMP":
                fmt = "    {id}: ICMP\n"
            elif rule["from_port"] == rule["to_port"]:
                fmt = "    {id}: {ip_protocol}({to_port})\n"
            else:
                fmt = "    {id}: {ip_protocol}({from_port}:{to_port})\n"
            put(fmt.format(**rule))
        return "".join(result)


class ExtensionsCommand(CliCommand):
    __metaclass__ = CliCommandMetaclass

    RESOURCE = "/extensions"

    def __init__(self):
        super(ExtensionsCommand, self).__init__("List all available extensions")

    @handle_command_error
    def run(self):
        for ext in self.get()["extensions"]:
            sys.stdout.write("{name}({alias}): {description}\n".format(**ext))


class BillingCommand(CliCommand):
    __metaclass__ = CliCommandMetaclass

    DEFAULT_COMMAND = 'bill'

    @staticmethod
    def url_escape(s):
        return urllib.quote(s)

    def __init__(self):
        super(BillingCommand, self).__init__("Manage billing subsystem", service_type="nova-billing")

    @staticmethod
    def get_resource_tree(resources):
        res_by_id = dict(((res["id"], res) for res in resources))
        for res in resources:
            try:
                parent = res_by_id[res["parent_id"]]
            except KeyError:
                pass
            else:
                parent.setdefault("children", []).append(res)
        return filter(
            lambda res: res["parent_id"] not in res_by_id,
            resources)

    @staticmethod
    def build_resource_tree(bill):

        def calc_cost(res):
            cost = res.get("cost", 0.0)
            for child in res.get("children", ()):
                calc_cost(child)
                cost += child["cost"]
            res["cost"] = cost

        for acc in bill:
            subtree = BillingCommand.get_resource_tree(
                acc["resources"])
            acc_cost = 0.0
            for res in subtree:
                calc_cost(res)
                acc_cost = res["cost"]
            acc["cost"] = acc_cost
            acc["resources"] = subtree

    def print_result(self, resp):
        print "Statistics for {0} - {1}".format(resp["period_start"], resp["period_end"])
        bill = resp["accounts"]
        self.build_resource_tree(bill)

        def print_res(res, depth):
            print "{0}{1}{2}: {3}\t{4} - {5}".format(
                "    " * depth,
                res["name"] and (res["name"] + " ") or "",
                res["rtype"],
                res["cost"],
                res["created_at"],
                res["destroyed_at"] or "now")
            depth += 1
            for child in res.get("children", ()):
                print_res(child, depth)

        for acc in bill:
            print "Account {0} (#{1}): total {2}".format(
                self.get_tenant_name_by_id(acc["name"]),
                acc["name"], acc["cost"])
            for res in acc["resources"]:
                print_res(res, 1)

    @handle_command_error
    @subcommand("Get the bill")
    @add_argument("--account", required=False, help="Select an account")
    @add_argument("--time-period", required=False, help="Set time period")
    @add_argument("--period-start", required=False, help="Set time period start")
    @add_argument("--period-end", required=False, help="Set time period end")
    def bill(self):
        if self.options.account:
            params = ["account={0}".format(self.url_escape(self.options.account))]
        else:
            params = []

        for opt in ["time_period", "period_start", "period_end"]:
            if getattr(self.options, opt):
                params.append("{0}={1}".format(
                    opt, self.url_escape(getattr(self.options, opt))))
        req = "/report"
        if params:
            req = "{0}?{1}".format(req, "&".join(params))
        self.print_result(self.get(req))

    @handle_command_error
    @subcommand("Get or set the tariffs")
    @add_argument("--no-migrate", default=False, action="store_true",
                  help="do not migrate to the new tariffs")
    @add_argument("tariffs", nargs="*", help="tariff-1 value-1 tariff-2 value-2 ...")
    def tariff(self):
        tariffs = self.options.tariffs
        if len(tariffs):
            body = {
                "datetime": "%sZ" % datetime.utcnow().isoformat(),
                "migrate": not self.options.no_migrate,
                "values": dict(zip(tariffs[::2],
                                   (float(i) for i in tariffs[1::2]))),
            }
            resp = self.post("/tariff", body)
        else:
            resp = self.get("/tariff")
        for key, value in resp.iteritems():
            print "{0}: {1}".format(key, value)

    @handle_command_error
    @subcommand("Get accounts")
    def account(self):
        for acc in self.get("/account"):
            print "#{id}: {name} ({ext})".format(
                ext=self.get_tenant_name_by_id(acc["name"]),
                **acc)

    @handle_command_error
    @subcommand("Get resources")
    @add_argument("--account-id", required=False, help="Resources' account id")
    @add_argument("--name", required=False, help="Resources' name")
    @add_argument("--rtype", required=False, help="Resources' type")
    @add_argument("--id", required=False, help="Resources' id")
    @add_argument("--parent-id", required=False, help="Resources' parent id")
    def resource(self):
        params = []
        for fld in ("account_id", "name", "id", "rtype", "parent_id"):
            value = getattr(self.options, fld)
            if value:
                params.append(
                    "{0}={1}".format(fld, self.url_escape(value)))
        req = "/resource"
        if params:
            req = "{0}?{1}".format(req, "&".join(params))

        def print_res(res, depth):
            print  "{0}#{1}: {2}{3} {4}".format(
                "    " * depth,
                res["id"],
                res["name"] and (res["name"] + " ") or "",
                res["rtype"],
                "; ".join(("{0}={1}".format(key, value)
                           for key, value in res["attrs"].iteritems())))
            depth += 1
            for child in res.get("children", ()):
                print_res(child, depth)

        for res in self.get_resource_tree(self.get(req)):
            print_res(res, 0)


class LocalVolumesCommand(CliCommand):

    __metaclass__ = CliCommandMetaclass

    def __init__(self):
        super(LocalVolumesCommand, self).__init__("Manages Volumes system")

    @handle_command_error
    @subcommand('Create local volume', 'create')
    @add_argument("--vm", required=True, help="Instance name or id attach volume to")
    @add_argument("--snapshot", required=False, help="Snapshot id create volume from")
    @add_argument("--device", required=True, help="Device name in guest OS. Example: /dev/vdb")
    @add_argument("--size", required=False, help="Size of new volume. Measures in bytes by default\n" \
                                                 "Examples:\n" \
                                                 "100, 100b, 100K ,100M , 100G")
    def create_volume(self):
        id = self.get_server(self.options.vm).get('id', None)
        body = {
                'volume': {
                    'instance_id': id,
                    'snapshot_id': self.options.snapshot,
                    'device': self.options.device,
                    'size': self.options.size,
                    }
        }
        response = self.post('/gd-local-volumes', body)
        vol = response['volume']
        utils.print_item((
            ('id', vol['id']),
            ('status', vol['status']),
            ('size', vol['size']),
            ('instance_id', vol['instance_id']),
            ('device', vol['device'])
        ))

    @handle_command_error
    @subcommand("Delete local volume", "delete")
    @add_argument("--id", required=True, help="Local Volume id")
    def delete_volume(self):
        self.delete('/gd-local-volumes/' + self.options.id)

    @handle_command_error
    @subcommand("Resize local volume", "resize")
    @add_argument("--id", required=True, help="Local volume id")
    @add_argument("--size", required=True, help="New size of local volume. Measures in bytes by default.\n" \
                                                     "Examples:\n" \
                                                     "100, 100b, 100K ,100M , 100G")
    def resize_volume(self):
        body = {
            'volume': {
                'size': self.options.size
            }
        }
        self.put('/gd-local-volumes/%s' % self.options.id, body)

    @handle_command_error
    @subcommand("Snapshot local volume", "snapshot")
    @add_argument("--id", required=True, help="Local volume id")
    @add_argument("--name", required=True, help="Name of newly created snapshot")
    def snapshot_volume(self):
        body = {
            'volume_id': self.options.id,
            'name': self.options.name
        }

        self.post('/gd-local-volumes-snapshotting', body)

    @handle_command_error
    @subcommand("List of local volumes", "list")
    @add_argument(
        "-f", "--format",
        default="{id:6} {instance_id:10} {status:10} {size:20} {device:20}",
        help="Set output format. The format syntax is the same as for Python `str.format` method. " +
        "Available variables: `id`, `instance_id`, `status`, `size`, `device`. " \
        "Default format: " +
        "\"{id:6} {instance_id:10} {status:10} {size:20} {device:20}\""
    )
    def list_volumes(self):
        response = self.get("/gd-local-volumes")
        utils.print_table(response['volumes'], self.options.format)


class FloatingIpCommand(CliCommand):
    __metaclass__ = CliCommandMetaclass

    def __init__(self):
        super(FloatingIpCommand, self).__init__("Working with floating ips")

    @handle_command_error
    @subcommand("Get floating ips")
    @add_argument(
        "-f", "--format",
        default="{id} {ip:20} {fixed_ip} {instance_id:<10}",
        help="Set output format. The format syntax is the same as for Python `str.format` method. " +
             "Available variables: `ip`, `instance_id`, `fixed_ip`, `id`. Default format: " +
             "\"{id} {ip:20} {fixed_ip} {instance_id:<10}\""
    )
    def list(self):
        """List floating ips for this tenant."""
        res = self.get("/os-floating-ips")
        ips = res.get('floating_ips')
        if not ips:
            sys.stdout.write("There are no floating ips available")
        for ip in ips:
            self.__print_floating_ip(self.options.format, ip)

    @handle_command_error
    @subcommand("Allocate floating ip")
    @add_argument(
        "-f", "--format",
        default="Id: {id}\nIp: {ip:20}",
        help="Set output format. The format syntax is the same as for Python `str.format` method. " +
             "Available variables: `ip`, `instance_id`, `fixed_ip`, `id`. Default format: " +
             "\"{id} {ip:20}\""
    )
    def allocate(self):
        """Allocate a floating IP for the current tenant."""
        try:
            res = self.post("/os-floating-ips", body=None)
        except Exception:
            raise CommandError(1, 'No more floating ips available')
        floating_ip = res.get('floating_ip')
        self.__print_floating_ip(self.options.format, floating_ip)

    @handle_command_error
    @subcommand("De-allocate floating ip")
    @add_argument('ip', metavar='<ip>', help='IP of Floating Ip.')
    def deallocate(self):
        """De-allocate a floating IP."""
        floating_ip = self.get_floating_ip(self.options.ip)
        return self.delete("/os-floating-ips/%s" % floating_ip['id'])

    @handle_command_error
    @subcommand("Attach floating ip to server")
    @add_argument("vm", help="VM id or name")
    @add_argument('ip', help='IP Address.')
    def attach(self):
        """Attach a floating IP address to a server."""
        srv = self.get_server(self.options.vm)
        floating_ip = self.get_floating_ip(self.options.ip)

        srv_id = srv['id']
        ip = floating_ip['ip']

        url = '/servers/%s/action' % srv_id
        return self.post(url, {'addFloatingIp': {'address': ip}})

    @handle_command_error
    @subcommand("Detach floating ip from server")
    @add_argument("vm", help="VM id or name")
    @add_argument('ip', help='IP Address.')
    def detach(self):
        """Detach a floating IP address from a server."""
        srv = self.get_server(self.options.vm)
        floating_ip = self.get_floating_ip(self.options.ip)

        srv_id = srv['id']
        ip = floating_ip['ip']

        url = '/servers/%s/action' % srv_id
        return self.post(url, {'removeFloatingIp': {'address': ip}})

    def get_floating_ip(self, identifier):
        if identifier.isdigit():
            return self.get_floating_ip_by_id(identifier)
        else:
            return self.get_floating_ip_by_ip(identifier)

    def get_floating_ip_by_ip(self, ip):
        res = self.get("/os-floating-ips")
        floating_ips = res.get('floating_ips')
        if not floating_ips:
            raise CommandError(1, "There are no floating ips available")
        for floating_ip in floating_ips:
            if floating_ip['ip'] == ip:
                return floating_ip
        raise CommandError(1, "Floating ip %s not found" % ip)

    def get_floating_ip_by_id(self, id):
        id = str(id)
        res = self.get("/os-floating-ips")
        floating_ips = res.get('floating_ips')
        if not floating_ips:
            raise CommandError(1, "There are no floating ips available")
        for floating_ip in floating_ips:
            if str(floating_ip['id']) == id:
                return floating_ip
        raise CommandError(1, "Floating ip with id %s not found" % id)

    def __print_floating_ip(self, format, floating_ip):
        id = floating_ip["id"]
        instance_id = floating_ip["instance_id"]
        fixed_ip = floating_ip["fixed_ip"]
        ip = floating_ip["ip"]
        info = dict(locals())
        del info["self"]
        del info["floating_ip"]
        del info["format"]
        sys.stdout.write(format.format(**info))
        sys.stdout.write("\n")

class DNSCommand(CliCommand):
    __metaclass__ = CliCommandMetaclass

    def __init__(self):
        super(DNSCommand, self).__init__("Manage dns subsystem", service_type="nova_dns")

    @handle_command_error
    def run(self):
        self.options.subcommand()

    @handle_command_error
    @subcommand("Get zones list")
    def zonelist(self):
        for zone in self.request('GET', '/zone/'):
            print "\t{0}".format(zone)

    @handle_command_error
    @subcommand("Add zone")
    @add_argument("zone", help="Zone name to add")
    @add_argument("--primary", required=False, help="Name server that will respond authoritatively for the domain")
    @add_argument("--hostmaster", required=False, help="Email address of the person responsible for this zone")
    @add_argument("--refresh", required=False, help="The time when the slave will try to refresh the zone from the master")
    @add_argument("--retry", required=False, help="time between retries if the slave fails to contact the master")
    @add_argument("--expire", required=False, help="Indicates when the zone data is no longer authoritative")
    @add_argument("--ttl", required=False, help="Default record ttl")
    def zoneadd(self):
        args = ('primary', 'hostmaster', 'refresh', 'retry', 'expire', 'ttl')
        print self.request('PUT', '/zone/', [self.options.zone], args)

    @handle_command_error
    @subcommand("Drop zone")
    @add_argument("zone", help="Zone name to delete")
    @add_argument("--force", required=False, help="Delete all subdomains")
    def zonedrop(self):
        print self.request('DELETE', '/zone/', [self.options.zone],  ('force',))

    @handle_command_error
    @subcommand("List records in zone")
    @add_argument("zone", nargs='?', help="Zone name")
    @add_argument("--name", required=False, help="Record name")
    @add_argument("--type", required=False, help="Record type")
    @add_argument("-f", "--format", required=False,
        default="{name:20} {type:5} {ttl:10} {content}",
        help="Set output format. The format syntax is the same as for Python `str.format` method. " +
        "Available variables: `name`, `type`, `content`, `ttl`, `priority`. " \
        "Default format: " +
        "\"{id:6} {instance_id:10} {status:10} {size:20} {device:20}\""
    )
    def list(self):
        if not self.options.zone:
            return self.zonelist()
        print self.options.format
        for rec in  self.request('GET', '/record/', [self.options.zone], ('name','type')):
            print self.options.format.format(**rec)

    @handle_command_error
    @subcommand("Add record to zone")
    @add_argument("zone", help="Zone name")
    @add_argument("name", help="Record name")
    @add_argument("type", help="Record type")
    @add_argument("content", help="Record content")
    @add_argument("--ttl", required=False, help="Record ttl")
    @add_argument("--priority", required=False, help="Record priority")
    def add(self):
        name = self.options.name if self.options.name else '@'
        print self.request('PUT', '/record/', 
            [self.options.zone, name, self.options.type, self.options.content],
            ('ttl', 'priority'))

    @handle_command_error
    @subcommand("Edit record in zone")
    @add_argument("zone", help="Zone name")
    @add_argument("name", help="Record name")
    @add_argument("type", help="Record type")
    @add_argument("--content", help="Record content")
    @add_argument("--ttl", required=False, help="Record ttl")
    @add_argument("--priority", required=False, help="Record priority")
    def edit(self):
        name = self.options.name if self.options.name else '@'
        print self.request('POST', '/record/', 
            [self.options.zone, name, self.options.type],
            ('ttl', 'priority', 'content'))

    @handle_command_error
    @subcommand("Delete record from zone")
    @add_argument("zone", help="Zone name")
    @add_argument("name", help="Record name")
    @add_argument("type", help="Record type")
    def drop(self):
        name = self.options.name if self.options.name else '@'
        print self.request('DELETE', '/record/', 
            [self.options.zone, name, self.options.type])


    def request(self, method, path, addtopath=None, args=None):
        #FIXME urlencode addtopath ?
        req = path + '/'.join(addtopath) if addtopath else path
        if args:
            params = {}
            for o, v in vars(self.options).iteritems():
                if o not in args or v is None: 
                    continue
                params[o] = v
            if params:
                req = "%s?%s" % (req, urllib.urlencode(params))
        resp = {}
        #FIXME probably change NovaClient to remove this ?? 
        if method == 'GET':
            resp = self.get(req)
        elif method == 'POST':
            resp = self.post(req, None)
        elif method == 'PUT':
            resp = self.put(req, None)
        elif method == 'DELETE':
            resp = self.delete(req)
        else:
            raise CommandError(1, 'Unknown method %s' % method)
        if resp['error']:
            raise CommandError(1, resp['error'])
        return resp['result']
