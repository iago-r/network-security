#!/usr/bin/env python3

import logging
import json
from collections import Counter
from pathlib import Path

from ipdb import IPDBConfig, IPDatabase


OI_ASNS = [8167, 7738, 14571]
CLOUD_ASNS = [14618, 16509, # Amazon
              396982, 15169, # Google
              16397, 26592, # EQUINIX
              8075, # Microsoft
              13878, 19089, # UOL
              54113, # Fastly
]


def main():
    logging.basicConfig(level=logging.DEBUG)

    storage = Path("~/git/kiron/data/blocks").expanduser()
    config = IPDBConfig("ipdb", None, storage)

    ipdb = IPDatabase(config)


    asn2count_global = Counter()
    for file in ["ips-oi-com-br.txt", "ips-oi-net-br.txt"]:
        fp = storage / file
        with open(fp, encoding="utf8") as fd:
            ips = list(line.strip() for line in fd)

        dirname = file.replace("ips-", "")
        dirname = dirname.replace(".txt", "")
        outdir = storage / dirname
        outdir.mkdir(parents=True, exist_ok=True)

        jsondict = ipdb.get_ip_blocks_jsondict(ips)
        with open(outdir/"blocks-full.json", "wt", encoding="utf8") as fd:
            json.dump(jsondict, fd)

        with open(outdir/"blocks-bgp.json", "wt", encoding="utf8") as fd:
            filtered = {k: v for k, v in jsondict.items() if "bgp" in v["sources"]}
            json.dump(filtered, fd)

        with open(outdir/"blocks-bgp-5plus.json", "wt", encoding="utf8") as fd:
            filtered = {k: v for k, v in jsondict.items() if "bgp" in v["sources"] and v["ips"] >= 5}
            json.dump(filtered, fd)

        asn2count = Counter()
        for _prefix, info in jsondict.items():
            if "bgp" not in info["sources"]:
                continue
            asn2count[info["origin"]] += info["ips"]
            asn2count_global[info["origin"]] += info["ips"]
        asn2info = {asn: {"count": cnt, "name": ipdb.asnamesdb.short(asn)} for asn,cnt in asn2count.items()}

        with open(outdir/"asnpop.json", "wt", encoding="utf8") as fd:
            json.dump(asn2info, fd)
        with open(outdir/"asnpop.csv", "wt", encoding="utf8") as fd:
            fd.write("asn,ips,shortname\n")
            for asn, info in asn2info.items():
                fd.write(f"{asn},{info['count']},{info['name']}\n")

        oi_blocks = set()
        cloud_ips = set()
        for ip in ips:
            mapping = ipdb.bgp_pfx2as.get(ip)
            if mapping is None:
                continue
            if mapping in OI_ASNS:
                oi_blocks.add(ipdb.bgp_pfx2as.get_prefix(ip))
            elif mapping in CLOUD_ASNS:
                cloud_ips.add(ip)

        with open(outdir/"oi-blocks.txt", "wt", encoding="utf8") as fd:
            for prefix in oi_blocks:
                fd.write(f"{prefix}\n")
        with open(outdir/"cloud-ips.txt", "wt", encoding="utf8") as fd:
            for ip in cloud_ips:
                fd.write(f"{ip}\n")

    asn2info_global = {asn: {"count": cnt, "name": ipdb.asnamesdb.short(asn)} for asn,cnt in asn2count_global.items()}

    with open(storage/"asnpop.json", "wt", encoding="utf8") as fd:
        json.dump(asn2info_global, fd)
    with open(storage/"asnpop.csv", "wt", encoding="utf8") as fd:
        fd.write("asn,ips,shortname\n")
        for asn, info in asn2info_global.items():
            fd.write(f"{asn},{info['count']},{info['name']}\n")


if __name__ == "__main__":
    main()
