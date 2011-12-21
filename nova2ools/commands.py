import base64
import os
import sys

from argparse import ArgumentParser
from inspect import ismethod
from itertools import ifilter

from client import NovaApiClient
from exceptions import CommandError
from exceptions import handle_command_error
from nova2ools import VERSION


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

class CliCommand(object):
    __common_args = [
        (("--debug",), {"default": False, "action": "store_true", "help": "Run in debug mode"}),
        (
            ("--version", "-v"),
            {
                "action": "version",
                "version": "Nova2ools Version: {0}".format(VERSION),
                "help": "Show version"
            }
        )
    ]
    __common_defaults = {}

    @handle_command_error
    def __init__(self, help, client_class=NovaApiClient):
        self.__help = help
        self.__parser = self.__generate_options_parser(NovaApiClient)
        self.parse_args()
        self.client = client_class(self.options)

    def get(self, path=""):
        return self.client.get(getattr(self, "RESOURCE", "") + path)

    def post(self, path, body):
        return self.client.post(getattr(self, "RESOURCE", "") + path, body)

    def put(self, path, body):
        return self.client.put(getattr(self, "RESOURCE", "") + path, body)

    def delete(self, path):
        return self.client.delete(getattr(self, "RESOURCE", "") + path)

    def parse_args(self):
        self.options = self.__parser.parse_args()

    def __generate_options_parser(self, client):
        parser = ArgumentParser(description=self.__help)
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

    def get_security_group_by_name(self, name):
        sgroups = self.client.get("/os-security-groups")["security_groups"]
        for sg in sgroups:
            if sg["name"] == name:
                return sg
        raise CommandError(1, "Security Group `{0}` is not found".format(name))


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

    @subcommand("Print public key to standard output", "print-public")
    @add_argument("key", help="Existing key name")
    def print_public(self):
        keys = self.get()
        for key in keys["keypairs"]:
            if key["keypair"]["name"] == self.options.key:
                sys.stdout.write(key["keypair"]["public_key"])
                return
        raise CommandError(1, "key not found")

    @handle_command_error
    def run(self):
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
        self.delete("/{0}".format(srv["id"]))

    @subcommand("Show information about VM")
    @add_argument("vm", help="VM name")
    def show(self):
        srv = self.get_server_by_name(self.options.vm)
        self.__print_srv_details(srv)

    @subcommand("Spawn a new VM")
    @add_argument("-n", "--name", required=True, help="VM name")
    @add_argument("-i", "--image", required=True, help="Image to use")
    @add_argument("-f", "--flavor", required=True, help="Flavor to use")
    @add_argument("-p", "--password", help="Administrator Password")
    @add_argument("-m", "--metadata", nargs="*", help="Server Metadata")
    @add_argument("-k", "--keyname", help="Registered SSH Key Name")
    @add_argument("-j", "--inject", nargs="*", help="Inject file to image (personality)")
    @add_argument("-s", "--security-groups", nargs="*", help="Apply security groups to a new VM")
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
            srvDesc["security_groups"] = [{"name": i} for i in self.options.security_groups]
        srv = self.post("", {"server": srvDesc})["server"]
        self.__print_srv_details(srv)

    @subcommand("List spawned VMs")
    def list(self):
        response = self.get("/detail")
        servers = response["servers"]
        for srv in servers:
            self.__print_srv_details(srv)

    @handle_command_error
    def run(self):
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
        img = self.get_image_detail(srv["image"]["id"])
        flv = self.get_flavor_detail(srv["flavor"]["id"])
        print "{name}({id}, 0x{id:x}): user:{user_id} project:{tenant_id} key:{key_name} {status}".format(**srv)
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
        for sg in self.get()["security_groups"]:
            sys.stdout.write(self.__format(sg))

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
            "parent_group_id": group["id"],
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

    @handle_command_error
    def run(self):
        self.options.subcommand()

    @classmethod
    def __format(cls, sg):
        result = []
        put = result.append
        put("{name}({tenant_id}): {description}\n".format(**sg))
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
