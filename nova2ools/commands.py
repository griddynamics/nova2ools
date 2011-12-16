import os
import sys

from argparse import ArgumentParser
from inspect import ismethod
from itertools import ifilter

from client import Client
from exceptions import CommandError
from exceptions import handle_command_error

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
        self.__client = Client()
        self.__parser = self.__generate_options_parser()
        self.parse_args()
        self.auth()

    def parse_args(self):
        self._options = self.__parser.parse_args()
        self.__client.set_debug(self._options.debug)

    for i in ("get", "put", "post", "delete"):
        def gen_method(original_method):
            def method(self, *args, **kwargs):
                return original_method(self.__client, *args, **kwargs)
            method.__name__ = original_method.__name__
            method.__doc__ = getattr(original_method, "__doc__")
            return method
        #noinspection PyArgumentList
        vars()[i] = gen_method(getattr(Client, i))

    def auth(self):
        opts = self._options
        if opts.username is None:
            raise CommandError(1, "OpenStack user name is undefined")
        if opts.api_key is None:
            raise CommandError(1, "OpenStack API secret key is undefined")
        if opts.project is None:
            raise CommandError(1, "OpenStack Project(Tenant) name is undefined")
        self.__client.auth(opts.username, opts.api_key, opts.project)

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


def subcommand(help, name=None):
    def decorator(method):
        method.subcommand = True
        method.subcommand_help = help
        method.subcommand_name = name or method.__name__
        return method

    return decorator


def add_argument(*args, **kwargs):
    def decorator(method):
        if not hasattr(method, "subcommand_args"):
            method.subcommand_args = []
        method.subcommand_args.append((args, kwargs))
        return method
    return decorator


################################################################################


class FlavorsCommand(CliCommand):
    def __init__(self):
        CliCommand.__init__(self, "Show available flavors for the project")

    @handle_command_error
    def run(self):
        flavors = self.get("/flavors/detail")
        for flv in flavors["flavors"]:
            sys.stdout.write("{id}: {name} ram:{ram} vcpus:{vcpus} swap:{swap} disc:{disk}\n".format(**flv))


class ImagesCommand(CliCommand):
    def __init__(self):
        super(ImagesCommand, self).__init__("List images available for the project")

    @handle_command_error
    def run(self):
        images = self.get("/images/detail")
        for img in ifilter(self.__filter_images, images["images"]):
            sys.stdout.write("{id}: {name} {metadata[architecture]}\n".format(**img))

    @staticmethod
    def __filter_images(img):
        return (
            img["name"] is not None
            and img["status"] == "ACTIVE"
            )


__all__ = [
    "CliCommand",
    "subcommand",
    "add_argument",
    "FlavorsCommand",
    "ImagesCommand"
]