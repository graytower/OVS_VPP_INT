# OVS_VPP_INT

## Introduction

Software-based virtual switches are widely deployed in today’s multi-tenant cloud networks. For example, Open vSwitches (OVS) are installed on racks of physical servers, bridging the hosted virtual machines with the outside world via encapsulating and decapsulating VXLAN tags. Vector Packet Processors (VPP) are deployed in high-speed x86 machines to implement diverse virtual network functions. The cloud service should never sleep and be available in a 7*24 manner. Therefore, fine-grained, network-wide performance monitoring of these virtual switches is crucial to the reliability of mega-scale data centers. With such fine-grained telemetry, rapid failure detection and localization, load balancing of imbalanced traffic or even high-precision congestion control can be conducted inside data center networks. For achieving the required high precision, the recently proposed In-band Network Telemetry (INT) completes the device-internal state collection entirely on the data plane thus greatly eliminates the intervention by the controller. The collected data will be inserted into the packet header and uploaded to the remote controller only at the last hop of the forwarding path. In this work, we provide the detailed design and implementation of label-based INT and probe-based INT on top of OVS and VPP, the two mainstream software-based virtual switches with non-PISA architecture.

------

## System

### OVS

The OVS source code including INT feature based on the version 2.13.90.

### VPP

The VPP source code including INT feature based on the version 20.05

### example

Several example PYTHON files to simulate the packet forwarding process with enabled INT feature.

./OVS

OVS example PYTHON files

./OVS/int_hdrs.py

INT header definition file.

./OVS/parse.py

INT header parsing script.

./OVS/receive.py

The packet receiving and processing script.

./OVS/send100.py

The packet sending script.

./OVS/topo-2sw-2host.py

Topology definition script using in mininet.

./VPP

VPP example PYTHON files

./VPP/int_hdrs.py

INT header definition file.

./VPP/parse.py

INT header parsing script.

./VPP/receive.py

The packet receiving and processing script.

./VPP/send.py

The packet sending script.

------

## How to run

### Requisite third parties

Mininet

### OVS

First, start mininet:

```
sudo mn --switch ovsk
```

Second, configure flow entry

```
ovs-ofctl add-flow s1 "in_port=1,udp, actions=int_forwarding:2"
```

Third, run receive.py

```
h1 python receive.py
```

Fourth, run send100.py

```
h1 python send100.py 
```

### VPP

First, create a test topology using different namespaces, referring to:

https://fd.io/docs/vpp/master/gettingstarted/progressivevpp/interface.html

Second, start vpp and configure vpp host-interface:

```
sudo vpp -c startup.conf

vpp# create host-interface name vpp1out
vpp# set int state host-vpp1out up
vpp# set int ip address host-vpp1out 10.10.1.2/24

vpp# create host-interface name vpp2out
vpp# set int state host-vpp2out up
vpp# set int ip address host-vpp2out 10.10.2.2/24
```

Third, in one namespace, run receive.py.

```
python receive.py
```

Fourth, in other namespace run send.py.

```
python send.py
```

