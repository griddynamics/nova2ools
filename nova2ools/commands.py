import base64
import os
import sys

from argparse import ArgumentParser
from inspect import ismethod
from itertools import ifilter

from client import Client
from exceptions import CommandError
from exceptions import handle_command_error


__all__ = []


def export(function):
    global __all__
    __all__.append(function.__name__)
    return function


def CliCommandMetaclass(name, bases, dict):
    global __all__
    __all__.append(name)

    for i in ("get", "put", "post", "delete"):
        def gen_method(original_method, path_part):
            def method(self, path, *args, **kwargs):
                return original_method(self.client, path_part + path, *args, **kwargs)

            method.__name__ = original_method.__name__
            method.__doc__ = getattr(original_method, "__doc__")
            return method

        dict[i] = gen_method(getattr(Client, i), dict["RESOURCE"])
    return type(name, bases, dict)


__all__.append("CliCommand")

class CliCommand(object):
    __common_args = [
        (("--username", "-u"), {"help": "OpenStack user name"}),
        (("--api-key", "-k"), {"help": "OpenStack API secret key"}),
        (("--project", "-p"), {"help": "OpenStack Project(Tenant) name"}),
        (("--debug",), {"action": "store_true", "help": "Run in debug mode"})
    ]
    __common_defaults = {
        "username": os.environ.get("NOVA_USERNAME"),
        "api_key": os.environ.get("NOVA_API_KEY"),
        "project": os.environ.get("NOVA_PROJECT_ID"),
        "debug": False
    }

    def __init__(self, help):
        self.__help = help
        self.__parser = self.__generate_options_parser()
        self.parse_args()
        self.client = Client()
        self.client.set_debug(self.options.debug)
        self.auth()

    def parse_args(self):
        self.options = self.__parser.parse_args()

    def auth(self):
        opts = self.options
        if opts.username is None:
            raise CommandError(1, "OpenStack user name is undefined")
        if opts.api_key is None:
            raise CommandError(1, "OpenStack API secret key is undefined")
        if opts.project is None:
            raise CommandError(1, "OpenStack Project(Tenant) name is undefined")
        self.client.auth(opts.username, opts.api_key, opts.project)

    def __generate_options_parser(self):
        parser = ArgumentParser(description=self.__help)
        for i in self.__common_args:
            parser.add_argument(*i[0], **i[1])
        parser.set_defaults(**self.__common_defaults)
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

    def get_server_by_name(self, name):
        servers = self.client.get("/servers/detail?name={0}".format(name))["servers"]
        if len(servers) < 1:
            raise CommandError(1, "VM `{0}` is not found".format(name))
        if len(servers) > 1:
            sys.stderr.write("Warning: more then one({0}) server with `{1}` name\n".format(len(servers), name))
        return servers[0]

    def get_flavor_by_name(self, name):
        flavors = self.client.get("/flavors/detail")["flavors"]
        for flv in flavors:
            if flv["name"] == name:
                return flv
        raise CommandError(1, "Flavor `{0}` is not found".format(name))

    def get_image_by_name(self, name):
        images = self.client.get("/images/detail?name={0}".format(name))["images"]
        if len(images) < 1:
            raise CommandError(1, "VM `{0}` is not found".format(name))
        if len(images) > 1:
            sys.stderr.write("Warning: more then one({0}) image with `{1}` name\n".format(len(images), name))
        return images[0]


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

    @handle_command_error
    def run(self):
        #noinspection PyUnresolvedReferences
        flavors = self.get("/detail")
        for flv in flavors["flavors"]:
            sys.stdout.write("{id}: {name} ram:{ram} vcpus:{vcpus} swap:{swap} disc:{disk}\n".format(**flv))


class ImagesCommand(CliCommand):
    __metaclass__ = CliCommandMetaclass

    RESOURCE = "/images"

    def __init__(self):
        super(ImagesCommand, self).__init__("List images available for the project")

    @handle_command_error
    def run(self):
        #noinspection PyUnresolvedReferences
        images = self.get("/detail")
        for img in ifilter(self.__filter_images, images["images"]):
            sys.stdout.write("{id}: {name} {metadata[architecture]}\n".format(**img))

    @staticmethod
    def __filter_images(img):
        return (
            img["name"] is not None
            and img["status"] == "ACTIVE"
            )


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
        #noinspection PyUnresolvedReferences
        self.post("", request)

    @subcommand("Generate a new SSH Key Pair (Private key will be printed to standard output)")
    @add_argument("key", help="A new key name")
    def generate(self):
        request = {
            "keypair": {
                "name": self.options.key
            }
        }
        #noinspection PyUnresolvedReferences
        keypair = self.post("", request)
        sys.stdout.write(keypair["keypair"]["private_key"])

    @subcommand("Remove SSH Key from OpenStack")
    @add_argument("key", help="Existing key name")
    def remove(self):
        #noinspection PyUnresolvedReferences
        self.delete("/{0}".format(self.options.key))

    @subcommand("List existing keys")
    def list(self):
        #noinspection PyUnresolvedReferences
        keys = self.get("")
        for key in keys["keypairs"]:
            sys.stdout.write("{keypair[name]}: {keypair[fingerprint]}\n".format(**key))

    @subcommand("Print public key to standard output", "print-public")
    @add_argument("key", help="Existing key name")
    def print_public(self):
        #noinspection PyUnresolvedReferences
        keys = self.get("")
        for key in keys["keypairs"]:
            if key["keypair"]["name"] == self.options.key:
                sys.stdout.write(key["keypair"]["public_key"])
                return
        raise CommandError(1, "key not found")

    @handle_command_error
    def run(self):
        self.parse_args()
        self.auth()
        self.options.subcommand()


class VmsCommand(CliCommand):
    __metaclass__ = CliCommandMetaclass

    RESOURCE = "/servers"

    def __init__(self):
        super(VmsCommand, self).__init__("Manage Virtual Machines")
        self.__images = {}
        self.__flavors = {}

    @subcommand("Remove Virtual Machine")
    @add_argument("vm", help="VM name")
    def remove(self):
        srv = self.get_server_by_name(self.options.vm)
        #noinspection PyUnresolvedReferences
        self.delete("/{0}".format(srv["id"]))

    @subcommand("Show information about VM")
    @add_argument("vm", help="VM name")
    def show(self):
        srv = self.get_server_by_name(self.options.vm)
        self.__print_srv_details(srv)

    @subcommand("Spawn a new VM")
    @add_argument("-n", "--name", help="VM name")
    @add_argument("-i", "--image", required=True, help="Image to use")
    @add_argument("-f", "--flavor", required=True, help="Flavor to use")
    @add_argument("-p", "--password", help="Administrator Password")
    @add_argument("-m", "--metadata", nargs="*", help="Server Metadata")
    @add_argument("-k", "--keyname", help="Registered SSH Key Name")
    @add_argument("-j", "--inject", nargs="*", help="Inject file to image (personality)")
    @add_argument("-s", "--security-groups", nargs="*", help="Inject file to image (personality)")
    def spawn(self):
        img = self.get_image_by_name(self.options.image)
        flv = self.get_flavor_by_name(self.options.flavor)
        srvDesc = {
            "name": self.options.name,
            "imageRef": img["links"][0]["href"],
            "flavorRef": flv["id"]
        }
        if self.options.password is not None:
            srvDesc["adminPass"] = self.options.password
        if self.options.metadata is not None:
            srvDesc["metadata"] = self.__generate_metadata_dict(self.options.metadata)
        if self.options.keyname is not None:
            srvDesc["key_name"] = self.options.keyname
        if self.options.inject is not None:
            srvDesc["personality"] = self.__generate_personality(self.options.inject)
        if self.options.security_groups is not None:
            srvDesc["security_groups"] = dict(({"name": i} for i in self.options.security_groups))
        #noinspection PyUnresolvedReferences
        srv = self.post("", {"server": srvDesc})["server"]
        self.__print_srv_details(srv)

    @subcommand("List spawned VMs")
    def list(self):
        #noinspection PyUnresolvedReferences
        response = self.get("/detail")
        servers = response["servers"]
        for srv in servers:
            self.__print_srv_details(srv)

    @handle_command_error
    def run(self):
        self.parse_args()
        self.auth()
        self.options.subcommand()

    def get_image_detail(self, id):
        return self.__get_detail_cached(id, "/images", self.__images)["image"]

    def get_flavor_detail(self, id):
        return self.__get_detail_cached(id, "/flavors", self.__flavors)["flavor"]

    def __get_detail_cached(self, id, prefix, cache):
        if id not in cache:
            cache[id] = self.client.get("{0}/{1}".format(prefix, id))
        return cache[id]

    def __print_srv_details(self, srv):
        print srv
        img = self.get_image_detail(srv["image"]["id"])
        flv = self.get_flavor_detail(srv["flavor"]["id"])
        print "{name}: user:{user_id} project:{tenant_id} key:{key_name} {status}".format(**srv)
        if "adminPass" in srv:
            print "  Admin Password: {0}".format(srv["adminPass"])
        first = True
        for net_id, addrs in srv["addresses"].items():
            for addr in addrs:
                type = "float"
                if addr["fixed"]:
                    type = "fixed"
                if first:
                    prefix = "       Addresses:"
                    first = False
                else:
                    prefix = "                 "
                print "{prefix} {addr[addr]}(v{addr[version]}) net:{net_id} {type}".format(**locals())
        print "           Image: {name}({metadata[architecture]})".format(**img)
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
