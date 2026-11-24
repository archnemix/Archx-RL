"""Resolve client IP only from an explicitly trusted, sanitizing reverse proxy."""
import ipaddress

from replay import canonical_ip


def trusted_networks(values):
    if not isinstance(values, (list, tuple)) or len(values) > 64:
        raise ValueError('Invalid trusted proxy list')
    networks = []
    for value in values:
        network = ipaddress.ip_network(value, strict=True)
        if network.prefixlen == 0:
            raise ValueError('A trusted proxy network cannot match every address')
        networks.append(network)
    return networks


def client_ip(peer, forwarded_values, networks):
    peer = canonical_ip(peer)
    address = ipaddress.ip_address(peer)
    if not any(address.version == network.version and address in network for network in networks):
        return peer
    # The trusted proxy must OVERWRITE this header with exactly one address.
    # Accepting a chain or duplicate headers would make this contract ambiguous.
    if len(forwarded_values) != 1 or not isinstance(forwarded_values[0], str):
        raise ValueError('Missing or duplicate trusted proxy header')
    forwarded = forwarded_values[0].strip()
    if not forwarded or ',' in forwarded or '%' in forwarded:
        raise ValueError('Invalid trusted proxy header')
    return canonical_ip(forwarded)
