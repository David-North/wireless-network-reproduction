# Wireless Network Reproduction

More introduction for the project is available at [https://finaltheory.github.io/wireless-network-reproduction/](https://finaltheory.github.io/wireless-network-reproduction/).


## Overview

**Wireless Network Reproduction** (aka WNR) is a network emulator which allows developers to exactly reproduce any kind of terrible network condition on your own mobile device, or even Android/iOS emulators running on Mac OS.

Aspects that can be controlled by WNR include:

- Bandwidth
- Latency
- Packet loss
- Packet corruption
- Packet reordering
- Packet duplication
- Packet throttling


## Architecture

In WNR, data flows between server and client are considered as two different streams: the inbound stream and outbound stream, which represents incoming packet(data/segments) flow and outgoing packet flow. When we need to interfere the network traffic to reproduce some bad network condition, we could add pipes on that stream, so the packets would flow into this pipe and then affected by it.

For example, if we want to emulate network latency and packet loss on incoming traffic, we need a `delay pipe`, which guarantees that each packet flows into this pipe would be delayed for exactly some time; and a `drop pipe`, which would randomly (or deterministically) drop the packets flow into it.

So when WNR is started, all the incoming packets would first flow into `delay pipe`, delayed for sometime, and then injected into `drop pipe`, suffer some packet loss, and finally injected into next pipe. If there is no more pipes ahead, packets would be re-injected into IP stack and delivered to application. This is the entire working process of WNR.


## Configuration

You can easily use `json` file to configure different types of WNR pipes. They will be described below in detail. The example `json` configuration files could be found [here](https://github.com/FinalTheory/wireless-network-reproduction/tree/master/macdivert/examples).

Basically there are 7 different pipes supported by WNR by now:

- Drop Pipe
- Delay Pipe
- Bandwidth Pipe
- Disorder Pipe
- Throttle Pipe
- Duplicate Pipe
- Tamper Pipe


## Compile && Build

Coming soon.


## Known issues

The issue list shown below originates from some subtle platform limitations when using [`Divert Socket`](https://developer.apple.com/library/mac/documentation/Darwin/Reference/ManPages/man4/divert.4.html) mechanism on Mac OS X.


### Packet recognition issue

WNR uses a Mac OS kernel extension [`PacketPID`](https://github.com/FinalTheory/PacketPID) to identify the sending process (PID) of each packet by querying some network-related kernel data structures with packets' source / destination addresses and port numbers as parameters. Thus, only TCP and UDP are supported, which is good enough for now.

But there is a problem that this query process may not always success. Actually, about 1% of TCP / UDP packets could not be recognized during emulation. So a simple but useful solution is to treat these unrecognized packets as our target packets, and perform emulation actions on them. It could generally be considered that this would not interfere other processes too much, and we don't need to concern about it.


### Internet-Sharing issues

When you're using Internet-Sharing to share network through WiFi to emulate network effects on real device, problems shown below may arise:

- WNR could not correctly divert ICMP packets, which means that WNR could only "see" incoming ICMP packets and then perform rule-defined actions on them, but do nothing on outgoing packets.
- Packets read from `Divert Socket` could not be re-injected correctly, which means that this packet should be manually sent to correct network device, which is `bridge100` in most cases. Fortunately, this special case is automatically handled in `libdivert` library of WNR.


## Hacking on the code

Coming soon.
