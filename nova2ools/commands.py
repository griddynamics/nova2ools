import base64
import os
import sys
import urllib

from argparse import ArgumentParser
from inspect import ismethod
from itertools import ifilter
import re

from client import NovaApiClient
from exceptions import CommandError
from exceptions import handle_command_error
from nova2ools import VERSION
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

    @handle_command_error
    def __init__(self, help, client_class=NovaApiClient, **kwargs):
        self.__help = help
        self.__parser = self.__generate_options_parser(client_class)
        self.parse_args()
        self.client = client_class(self.options, **kwargs)
        self.tenant_by_id = None

    def get(self, path=""):
        return self.client.get(getattr(self, "RESOURCE", "") + path)

    def post(self, path, body=None):
        return self.client.post(getattr(self, "RESOURCE", "") + path, body)

    def action(self, path):
        return self.client.action(getattr(self, "RESOURCE", "") + path)

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
            msg = "More then one({0}) server with `{1}` name (use `id` instead of name)".format(len(servers), name)
            raise CommandError(1, msg)
        return servers[0]

    def get_server_by_id(self, id):
        server = self.client.get("/servers/{0}".format(id))["server"]
        if len(server) < 1:
            raise CommandError(1, "VM `{0}` is not found".format(id))
        return server

    def get_flavor_by_name(self, name):
        flavors = self.client.get("/flavors/detail")["flavors"]
        for flv in flavors:
            if flv["name"] == name:
                return flv
        raise CommandError(1, "Flavor `{0}` is not found".format(name))

    def get_image_by_name(self, name):
        images = self.client.get("/images/detail?name={0}".format(name))["images"]
        if len(images) < 1:
            raise CommandError(1, "Image `{0}` is not found".format(name))
        if len(images) > 1:
            msg = "More then one({0}) image with `{1}` name (use `id` instead of name)".format(len(images), name)
            raise CommandError(1, msg)
        return images[0]

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
                        for tenant in client.get("/tenants?limit=10000")["tenants"]["values"]
                    ]
                )
            except CommandError:
                pass
            client.set_service_type(service_type)
        return self.tenant_by_id.get(tenant_id, "#{0}".format(tenant_id))


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

    @handle_command_error
    def run(self):
        self.options.subcommand()


class ImagesCommand(CliCommand):
    __metaclass__ = CliCommandMetaclass

    RESOURCE = "/images"

    def __init__(self):
        super(ImagesCommand, self).__init__("List images available for the project")

    @subcommand("List available images")
    @add_argument(
        "-f", "--format",
        default="{name:20} 0x{id:08x},{id:<5} {status:10}",
        help="Set output format. The format syntax is the same as for Python `str.format` method. " +
             "Available variables: `id`, `name`, `created`, `updated`, `status`, `progress`, `metadata`. Default format: " +
             "\"{name:20} 0x{id:08x},{id:<5} {status:10}\""
    )
    @add_argument("-m", "--metadata", action="store_true", default=False, help="Include metadata information to output")
    def list(self):
        images = self.get("/detail")
        format = self.options.format
        for img in ifilter(self.__filter_images, images["images"]):
            self.__print_image_format(format, img)
            if self.options.metadata and len(img["metadata"]) > 0:
                first = True
                for key, value in img["metadata"].items():
                    if first:
                        sys.stdout.write("Metadata: {0:5} -> {1}\n".format(key, value))
                        first = False
                    else:
                        sys.stdout.write("          {0:14} -> {1}\n".format(key, value))

    @handle_command_error
    def run(self):
        self.options.subcommand()

    @staticmethod
    def __filter_images(img):
        return (
            img["name"] is not None
            and img["status"] == "ACTIVE"
            )

    def __print_image_format(self, format, image):
        id = int(image["id"])
        name = image["name"]
        created = image["created"]
        updated = image["updated"]
        status = image["status"]
        progress = image["progress"]
        metadata = ", ".join(
            (
                "{0}={1}".format(k, v)
                for k, v in image["metadata"].items()
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
    @add_argument("vm", help="VM id or name")
    def remove(self):
        if not (self.options.vm.isdigit()):
            srv = self.get_server_by_name(self.options.vm)
            self.delete("/{0}".format(srv["id"]))
        else:
            self.delete("/{0}".format(self.options.vm))

    @subcommand("Show information about VM")
    @add_argument("vm", help="VM id or name")
    def show(self):
        if not (self.options.vm.isdigit()):
            srv = self.get_server_by_name(self.options.vm)
        else:
            srv = self.get_server_by_id(self.options.vm)
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
        if not (self.options.image.isdigit()):
            img = self.get_image_by_name(self.options.image)
        else:
            img = self.get_image_by_id(self.options.image)
        flv = self.get_flavor_by_name(self.options.flavor)
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
        self.__print_vm_detail(srv)

    @subcommand("List spawned VMs")
    @add_argument(
        "-f", "--format",
        default="{name:20} 0x{id:08x},{id:<5} {user_id:15} {tenant_name:10} {status:10} {fixed_addresses}",
        help="Set output format. The format syntax is the same as for Python `str.format` method. " +
        "Available variables: `id`, `name`, `created`, `updated`, `user_id`, `status`, `tenant_id`, `tenant_name`, " +
        "`fixed_addresses`, `float_addresses`, `image_id`. Default format: " +
        "\"{name:20} 0x{id:08x},{id:<5} {user_id:15} {tenant_name:10} {status:10} {fixed_addresses}\""
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

    @subcommand("Migrate VM")
    @add_argument("vm", help="VM id or name")
    def migrate(self):
        if not (self.options.vm.isdigit()):
            srv = self.get_server_by_name(self.options.vm)
        else:
            srv = self.get_server_by_id(self.options.vm)
        url ="/%s/migrate" % srv['id']
        return self.post(url)

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

    def __print_vm_format(self, format, vm):
        id = vm["id"]
        name = vm["name"]
        created = vm["created"]
        updated = vm["updated"]
        user_id = vm["user_id"]
        status = vm["status"]
        tenant_id = vm["tenant_id"]
        tenant_name = self.get_tenant_name_by_id(vm["tenant_id"])
        fixed_addresses = ",".join(
            (
            i["addr"]
            for j in vm["addresses"].values()
            for i in j
            if i["fixed"]
            )
        )
        float_addresses = ",".join(
            (
            i["addr"]
            for j in vm["addresses"].values()
            for i in j
            if not i["fixed"]
            )
        )
        image_id = vm["image"]["id"]
        info = dict(locals())
        del info["self"]
        del info["vm"]
        del info["format"]
        sys.stdout.write(format.format(**info))
        sys.stdout.write("\n")

    def __print_vm_detail(self, srv):
        img = self.get_image_detail(srv["image"]["id"])
        flv = self.get_flavor_detail(srv["flavor"]["id"])
        sys.stdout.write(
            "{name}({id}, 0x{id:x}): user:{user_id} project:{tenant_name} key:{key_name} {status}\n"
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
                if addr["fixed"]:
                    type = "fixed"
                if first:
                    prefix = "       Addresses:"
                    first = False
                else:
                    prefix = "                 "
                print "{prefix} {addr[addr]}(v{addr[version]}) net:{net_id} {type}".format(**locals())
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

    @handle_command_error
    def run(self):
        self.options.subcommand()

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
    RESOURCE = "/projects"

    def __init__(self):
        super(BillingCommand, self).__init__("Manage billing subsystem", service_type="nova_billing")

    @handle_command_error
    def run(self):
        self.options.subcommand()

    @handle_command_error
    @subcommand("Get statistics")
    @add_argument("--billing-project", required=False, help="Select project to show statistics")
    @add_argument("--time-period", required=False, help="Set time period")
    @add_argument("--period-start", required=False, help="Set time period start")
    @add_argument("--period-end", required=False, help="Set time period end")
    @add_argument("--instances", required=False, help="Set time period end", action="store_true", default=False)
    @add_argument("--images", required=False, help="Set time period end", action="store_true", default=False)
    @add_argument("--long", required=False, help="Set time period end", action="store_true", default=False)
    def list(self):
        include = []
        if self.options.instances:
            include.append("instances")
        if self.options.images:
            include.append("images")
        if self.options.long:
            include = ([opt + "-long" for opt in include]
                       if include else ["instances-long"])
        params = ["include=" + ",".join(include)] if include else []
        self.ask(params)

    def ask(self, params):
        def url_escape(s):
            return urllib.quote(s)

        if self.options.billing_project:
            req = "/{0}".format(url_escape(self.options.billing_project))
        else:
            req = ""

        for opt in ["time_period", "period_start", "period_end"]:
            if getattr(self.options, opt):
                params.append("{0}={1}".format(opt, url_escape(getattr(self.options, opt))))
        if params:
            req = "{0}?{1}".format(req, "&".join(params))
        self.print_result(self.get(req))

    @staticmethod
    def format_usage(usage):
        if "vcpus_h" in usage or "memory_mb_h" in usage:
            return "{0:.4f} GB*h\t{1:.4f} MB*h\t{2:.4f} CPU*h".format(
                usage.get("local_gb_h", 0),
                usage.get("memory_mb_h", 0),
                usage.get("vcpus_h", 0)
            )
        return "{0:.4f} GB*h".format(usage.get("local_gb_h", 0))

    def print_result(self, resp):
        print "Statistics for {0} - {1}".format(resp["period_start"], resp["period_end"])
        for project in resp["projects"]:
            print "Project {0}".format(self.get_tenant_name_by_id(project["id"]))
            for statistics_key in "instances", "images":
                if statistics_key not in project:
                    continue
                statistics_value = project[statistics_key]
                print "{0}: {1} items".format(statistics_key, statistics_value["count"])
                if "items" in statistics_value:
                    for object_item in statistics_value["items"]:
                        item_descr = "\t{0}: {1}\t{2} - {3}".format(
                            object_item["id"],
                            object_item["name"] or "",
                            object_item["created_at"],
                            object_item["destroyed_at"] or "now")
                        print item_descr
                        print "\t\t{0}".format(self.format_usage(object_item["usage"]))
                print "total:\t\t{0}".format(self.format_usage(statistics_value["usage"]))


class FloatingIpCommand(CliCommand):
    __metaclass__ = CliCommandMetaclass

    def __init__(self):
        super(FloatingIpCommand, self).__init__("Working with floating ips")

    @handle_command_error
    def run(self):
        self.options.subcommand()

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
        if not (self.options.vm.isdigit()):
            srv = self.get_server_by_name(self.options.vm)
        else:
            srv = self.get_server_by_id(self.options.vm)
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
        if not (self.options.vm.isdigit()):
            srv = self.get_server_by_name(self.options.vm)
        else:
            srv = self.get_server_by_id(self.options.vm)
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
        id = int(id)
        res = self.get("/os-floating-ips")
        floating_ips = res.get('floating_ips')
        if not floating_ips:
            raise CommandError(1, "There are no floating ips available")
        for floating_ip in floating_ips:
            if floating_ip['id'] == id:
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