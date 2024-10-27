#!/usr/bin/env python3

import dataclasses
import datetime
import enum
import logging
import pathlib
import time

import radix

import api
import ip2as
from delegations import Delegations
from asnames import ASNamesDB


@dataclasses.dataclass
class IPDBConfig:
    name: str
    callback: api.TaskCompletionCallback
    storage: pathlib.Path
    bgp_update_period: float = 3600.0


class IPDatabase:
    class Source(enum.IntFlag):
        BGP = enum.auto()
        IRR = enum.auto()

    def __init__(self, config: api.Config) -> None:
        assert isinstance(config, IPDBConfig)
        assert config.storage.is_absolute()
        self.config: IPDBConfig = config

        # Managed by update_bgp_pfx2as
        self.bgp_last_update_time: float = 0.0
        self.bgp_database: pathlib.Path = self.config.storage / "uninitialized"
        self.update_bgp_database()
        self.bgp_pfx2as = ip2as.IP2ASRadix.from_caida_prefix2as(self.bgp_database)

        # Managed by update_bgp_pfx2as
        self.rir_date = datetime.date.fromtimestamp(time.time() - 2*86400)
        fp = Delegations.download_rir_delegations(
            self.rir_date, self.config.storage
        )
        assert fp is not None
        self.rir_indexfp: pathlib.Path = fp
        self.delegations = Delegations(self.rir_indexfp)

        self.asnamesdb = ASNamesDB(self.config.storage / "autnums.html")

    def get_ip_blocks_radix(self, ips: list[str]) -> radix.Radix:
        blocks = radix.Radix()
        for ip in ips:
            prefix = self.bgp_pfx2as.get_prefix(ip)
            if prefix is None:
                continue
            node = blocks.add(prefix)
            node.data["source"] = IPDatabase.Source.BGP
            asn = self.bgp_pfx2as.get(ip)
            node.data["origin"] = asn
            node.data["origin_shortname"] = self.asnamesdb.short(asn)
            node.data.setdefault("ips", 0)
            node.data["ips"] += 1

        for ip in ips:
            orginfo_prefix = self.delegations.get_ip(ip)
            if orginfo_prefix is None:
                continue
            orginfo, prefix = orginfo_prefix
            node = blocks.add(str(prefix))
            node.data.setdefault("source", IPDatabase.Source.IRR)
            node.data["source"] |= IPDatabase.Source.IRR
            node.data["rir"] = orginfo.rir
            node.data["cc"] = orginfo.cc
            node.data["org_asns"] = list(orginfo.asn_iter())

        return blocks

    def get_ip_blocks_jsondict(self, ips: list[str]):  #  -> dict[IPNetwork, BlockInfo]:
        blocks = self.get_ip_blocks_radix(ips)
        jsondict = {}
        for node in blocks.nodes():
            prefix = node.prefix
            data = {"sources": []}
            if node.data["source"] & IPDatabase.Source.BGP:
                data["sources"].append("bgp")
                data["origin"] = node.data["origin"]
                data["origin_shortname"] = node.data["origin_shortname"]
                data["ips"] = node.data["ips"]
            if node.data["source"] & IPDatabase.Source.IRR:
                data["sources"].append("rir")
                data.update(
                    {
                        "rir": node.data["rir"],
                        "cc": node.data["cc"],
                        "org_asns": node.data["org_asns"],
                    }
                )
            jsondict[prefix] = data
        return jsondict

    def update_bgp_database(self) -> bool:
        now = time.time()
        age = now - self.bgp_last_update_time
        if age < self.config.bgp_update_period:
            logging.debug("Too early to check BGP prefix-to-AS index (age=%.3fs)", age)
            return False
        self.bgp_last_update_time = now

        fp = ip2as.IP2ASRadix.download_latest_caida_pfx2as(self.config.storage)
        if fp == self.bgp_database:
            logging.debug("Current prefix-to-AS database is up-to-date (%s)", fp)
            return False

        logging.info(
            "Downloaded new prefix-to-AS mapping (%s -> %s)", self.bgp_database, fp
        )
        self.bgp_database = fp
        return True
