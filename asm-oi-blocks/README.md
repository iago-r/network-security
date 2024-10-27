# IP Database Module

This module is in charge of aggregating information about IP addresses.

## BGP blocks

This module uses [CAIDA's prefix-to-AS mapping service][caida-pfx2as] to load a prefix trie in memory of publicly announced BGP feeds.

[caida-pfx2as]: https://publicdata.caida.org/datasets/routing/routeviews-prefix2as/

## IRR delegations
