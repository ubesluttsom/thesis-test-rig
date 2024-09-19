two_sender_context = {
    "networks": {
        "net1": {
            "bridge_name": "virbr1",
            "ip_address": "10.0.1.1",
            "netmask": "255.255.255.0",
            "dhcp_range_start": "10.0.1.100",
            "dhcp_range_end": "10.0.1.200",
            "devices": ["router1", "vm1"],
        },
        "net2": {
            "bridge_name": "virbr2",
            "ip_address": "10.0.2.1",
            "netmask": "255.255.255.0",
            "dhcp_range_start": "10.0.2.100",
            "dhcp_range_end": "10.0.2.200",
            "devices": ["router1", "vm2"],
        },
        "net3": {
            "bridge_name": "virbr3",
            "ip_address": "10.0.3.1",
            "netmask": "255.255.255.0",
            "dhcp_range_start": "10.0.3.100",
            "dhcp_range_end": "10.0.3.200",
            "devices": ["router1", "vm3"],
        },
    },
    "devices": {
        "router1": {
            "macs": {
                "net1": "52:54:00:01:00:01",
                "net2": "52:54:00:01:00:02",
                "net3": "52:54:00:01:00:03",
            },
            "ips": {
                "net1": "10.0.1.100",
                "net2": "10.0.2.100",
                "net3": "10.0.3.100",
            },
            "routes": {
                "10.0.1.0/24": "10.0.1.101",
                "10.0.2.0/24": "10.0.2.101",
                "10.0.3.0/24": "10.0.3.101",
            },
        },
        "vm1": {
            "macs": {"net1": "52:54:00:00:01:01"},
            "ips": {"net1": "10.0.1.101"},
            "default_gateway": "10.0.1.100",
        },
        "vm2": {
            "macs": {"net2": "52:54:00:00:02:01"},
            "ips": {"net2": "10.0.2.101"},
            "default_gateway": "10.0.2.100",
        },
        "vm3": {
            "macs": {"net3": "52:54:00:00:03:01"},
            "ips": {"net3": "10.0.3.101"},
            "default_gateway": "10.0.3.100",
        },
    },
}

context = {
    "networks": {
        "net1": {
            "bridge_name": "virbr1",
            "ip_address": "10.0.1.1",
            "netmask": "255.255.255.0",
            "dhcp_range_start": "10.0.1.100",
            "dhcp_range_end": "10.0.1.200",
            "devices": ["router1", "vm1"],
        },
        "net2": {
            "bridge_name": "virbr2",
            "ip_address": "10.0.2.1",
            "netmask": "255.255.255.0",
            "dhcp_range_start": "10.0.2.100",
            "dhcp_range_end": "10.0.2.200",
            "devices": ["router1", "vm2"],
        },
    },
    "devices": {
        "router1": {
            "macs": {
                "net1": "52:54:00:01:00:01",
                "net2": "52:54:00:01:00:02",
            },
            "ips": {
                "net1": "10.0.1.100",
                "net2": "10.0.2.100",
            },
            "routes": {
                "10.0.1.0/24": "10.0.1.101",
                "10.0.2.0/24": "10.0.2.101",
            },
        },
        "vm1": {
            "macs": {"net1": "52:54:00:00:01:01"},
            "ips": {"net1": "10.0.1.101"},
            "default_gateway": "10.0.1.100",
        },
        "vm2": {
            "macs": {"net2": "52:54:00:00:02:01"},
            "ips": {"net2": "10.0.2.101"},
            "default_gateway": "10.0.2.100",
        },
    },
}

star_topology_context = {
    "networks": {
        "net1": {
            "bridge_name": "virbr1",
            "ip_address": "10.0.1.1",
            "netmask": "255.255.255.0",
            "dhcp_range_start": "10.0.1.100",
            "dhcp_range_end": "10.0.1.200",
            "devices": ["router1", "vm1"],
        },
        "net2": {
            "bridge_name": "virbr2",
            "ip_address": "10.0.2.1",
            "netmask": "255.255.255.0",
            "dhcp_range_start": "10.0.2.100",
            "dhcp_range_end": "10.0.2.200",
            "devices": ["router1", "vm2"],
        },
        "net3": {
            "bridge_name": "virbr3",
            "ip_address": "10.0.3.1",
            "netmask": "255.255.255.0",
            "dhcp_range_start": "10.0.3.100",
            "dhcp_range_end": "10.0.3.200",
            "devices": ["router1", "vm3"],
        },
        "net4": {
            "bridge_name": "virbr4",
            "ip_address": "10.0.4.1",
            "netmask": "255.255.255.0",
            "dhcp_range_start": "10.0.4.100",
            "dhcp_range_end": "10.0.4.200",
            "devices": ["router1", "vm4"],
        },
    },
    "devices": {
        "router1": {
            "macs": {
                "net1": "52:54:00:01:00:01",
                "net2": "52:54:00:01:00:02",
                "net3": "52:54:00:01:00:03",
                "net4": "52:54:00:01:00:04",
            },
            "ips": {
                "net1": "10.0.1.100",
                "net2": "10.0.2.100",
                "net3": "10.0.3.100",
                "net4": "10.0.4.100",
            },
            "routes": {
                "10.0.1.0/24": "10.0.1.101",
                "10.0.2.0/24": "10.0.2.101",
                "10.0.3.0/24": "10.0.3.101",
                "10.0.4.0/24": "10.0.4.101",
            },
        },
        "vm1": {
            "macs": {"net1": "52:54:00:00:01:01"},
            "ips": {"net1": "10.0.1.101"},
            "default_gateway": "10.0.1.100",
        },
        "vm2": {
            "macs": {"net2": "52:54:00:00:02:01"},
            "ips": {"net2": "10.0.2.101"},
            "default_gateway": "10.0.2.100",
        },
        "vm3": {
            "macs": {"net3": "52:54:00:00:03:01"},
            "ips": {"net3": "10.0.3.101"},
            "default_gateway": "10.0.3.100",
        },
        "vm4": {
            "macs": {"net4": "52:54:00:00:04:01"},
            "ips": {"net4": "10.0.4.101"},
            "default_gateway": "10.0.4.100",
        },
    },
}

parking_lot_context = {
    "networks": {
        "net1": {
            "bridge_name": "virbr1",
            "ip_address": "10.0.1.1",
            "netmask": "255.255.255.0",
            "dhcp_range_start": "10.0.1.100",
            "dhcp_range_end": "10.0.1.200",
            "bandwidth": 12500,
            "devices": ["router1", "vm1"],
        },
        "net2": {
            "bridge_name": "virbr2",
            "ip_address": "10.0.2.1",
            "netmask": "255.255.255.0",
            "dhcp_range_start": "10.0.2.100",
            "dhcp_range_end": "10.0.2.200",
            "bandwidth": 12500,
            "devices": ["router2", "vm2"],
        },
        "net3": {
            "bridge_name": "virbr3",
            "ip_address": "10.0.3.1",
            "netmask": "255.255.255.0",
            "dhcp_range_start": "10.0.3.100",
            "dhcp_range_end": "10.0.3.200",
            "bandwidth": 12500,
            "devices": ["router3", "vm3"],
        },
        "net12": {
            "bridge_name": "virbr12",
            "ip_address": "10.0.12.1",
            "netmask": "255.255.255.0",
            "dhcp_range_start": "10.0.12.100",
            "dhcp_range_end": "10.0.12.200",
            "bandwidth": 12500,
            "devices": ["router1", "router2"],
        },
        "net23": {
            "bridge_name": "virbr23",
            "ip_address": "10.0.23.1",
            "netmask": "255.255.255.0",
            "dhcp_range_start": "10.0.23.100",
            "dhcp_range_end": "10.0.23.200",
            "bandwidth": 12500,
            "devices": ["router2", "router3"],
        },
    },
    "devices": {
        "router1": {
            "macs": {"net1": "52:54:00:01:00:01", "net12": "52:54:00:01:00:02"},
            "ips": {"net1": "10.0.1.100", "net12": "10.0.12.100"},
            "routes": {
                "10.0.2.0/24": "10.0.12.101",
                "10.0.3.0/24": "10.0.12.101",
            },
        },
        "vm1": {
            "macs": {"net1": "52:54:00:00:01:01"},
            "ips": {"net1": "10.0.1.101"},
            "default_gateway": "10.0.1.100",
        },
        "router2": {
            "macs": {
                "net2": "52:54:00:02:00:01",
                "net12": "52:54:00:02:00:02",
                "net23": "52:54:00:02:00:03",
            },
            "ips": {
                "net2": "10.0.2.100",
                "net12": "10.0.12.101",
                "net23": "10.0.23.100",
            },
            "routes": {
                "10.0.1.0/24": "10.0.12.100",
                "10.0.3.0/24": "10.0.23.101",
            },
        },
        "vm2": {
            "macs": {"net2": "52:54:00:00:02:01"},
            "ips": {"net2": "10.0.2.101"},
            "default_gateway": "10.0.2.100",
        },
        "router3": {
            "macs": {"net3": "52:54:00:03:00:01", "net23": "52:54:00:03:00:02"},
            "ips": {"net3": "10.0.3.100", "net23": "10.0.23.101"},
            "routes": {
                "10.0.1.0/24": "10.0.23.100",
                "10.0.2.0/24": "10.0.23.100",
            },
        },
        "vm3": {
            "macs": {"net3": "52:54:00:00:03:01"},
            "ips": {"net3": "10.0.3.101"},
            "default_gateway": "10.0.3.100",
        },
    },
}

class Host:
    def __init__(self, name, macs, ips):
        self.name = name
        self.macs = macs
        self.ips = ips

    def __getitem__(self, item):
        return getattr(self, item)

    def __repr__(self):
        return f"<Host(name={self.name}, macs={self.macs}, ips={self.ips})>"

    def __eq__(self, other):
        if isinstance(other, Host):
            return self.name == other.name
        return False

    def __hash__(self):
        return hash(self.name)

class Router(Host):
    def __init__(self, name, macs, ips, routes):
        super().__init__(name, macs, ips)
        self.routes = routes

    def __repr__(self):
        return f"<Router(name={self.name}, macs={self.macs}, ips={self.ips}, routes={self.routes})>"

class VM(Host):
    def __init__(self, name, macs, ips, default_gateway):
        super().__init__(name, macs, ips)
        self.default_gateway = default_gateway

    def __repr__(self):
        return f"<VM(name={self.name}, macs={self.macs}, ips={self.ips}, default_gateway={self.default_gateway})>"

# Convenience dictionary:

hosts = {}
routers = {}
vms = {}

for device_name, device_attrs in context['devices'].items():
    if 'routes' in device_attrs:  # It's a router
        router = Router(
            name=device_name,
            macs=device_attrs.get('macs', {}),
            ips=device_attrs.get('ips', {}),
            routes=device_attrs.get('routes', {}),
        )
        routers[device_name] = router
        hosts[device_name] = router  # Routers are also hosts
    elif 'default_gateway' in device_attrs:  # It's a VM
        vm = VM(
            name=device_name,
            macs=device_attrs.get('macs', {}),
            ips=device_attrs.get('ips', {}),
            default_gateway=device_attrs.get('default_gateway'),
        )
        vms[device_name] = vm
        hosts[device_name] = vm  # VMs are also hosts
    else:  # It's a generic host
        host = Host(
            name=device_name,
            macs=device_attrs.get('macs', {}),
            ips=device_attrs.get('ips', {}),
        )
        hosts[device_name] = host

# These lists can be imported from this module:
# from config import hosts, routers, vms

if __name__ == '__main__':
    print("Hosts:", hosts)
    print("Routers:", routers)
    print("VMs:", vms)
