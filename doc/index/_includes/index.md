## Introduction

[Wireless Network Reproduction](https://github.com/FinalTheory/wireless-network-reproduction) (aka WNR) is a network emulator which allows developers to exactly reproduce any kind of terrible network condition on your own mobile device, or even Android/iOS emulators running on Mac OS.

<img src="/wireless-network-reproduction/images/interface.png" width="500px"></img>

Aspects that can be controlled by WNR include:

- Bandwith
- Latency
- Packet loss
- Packet corruption
- Packet reordering
- Packet duplication
- Packet throttling

You could run WNR in two different mode:

1. Gateway Mode: First share your internet connection through [Internet-Sharing](https://support.apple.com/kb/PH18704), and then WNR would shape / interfere the network traffic between your MacBook and your mobile device, just like a router.
2. Emulator Mode: Just start an Android / iOS emulator, specify the process name in WNR, and then you will have emulated network condition in your virtual machine. In this mode you don't need a real mobile phone.


## Requirements

- A MacBook running OS X Yosemite / EI Capitan
- An Android/iOS mobile phone, or emulators like [GenyMotion](https://www.genymotion.com), [Droid4X](http://www.droid4x.com), etc.


## Download

For Chinese users, please download WNR through [Baidu Yun](http://pan.baidu.com/s/1eRwLDQy).

For other users, check [Github releases](https://github.com/FinalTheory/wireless-network-reproduction/releases) for latest build.


## Notice

- **DO NOT** run this application directly in dmg image!!! You should first extract it from image, save it into a local folder, and then try to run it.
- Path to the application should **NOT** contain any non-ASCII characters, otherwise it would encounter an error.


## Examples

### Network Emulation

The following animation shows the basic usages of WNR.

<img src="/wireless-network-reproduction/images/demo.gif"></img>


### Bandwidth Limitation

The following animation shows how to limit bandwidth of a specific process such as `wget`.

<img src="/wireless-network-reproduction/images/bandwidth.gif"></img>


### TCP Connection Analyze

We use a time-related function `bandwidth(t) = 256 + 1024 * sin(t/4) (KB/s)` to emulate some sort of dynamic bandwidth limitation, and then use TCP data visualization of WNR to show the actual bandwidth variation, which results in the figure shown below:

<img src="/wireless-network-reproduction/images/bandwidth.png"></img>


## Architecture

Coming soon.


## Contributions

Please use [Github issues](https://github.com/FinalTheory/wireless-network-reproduction/issues) for requests.

**We guarantee that we will try our best to meet the need of new features / bug fixes in first 30 issues;** and we actively welcome pull requests.


## ChangeLog

Changes are tracked as Github [commits](https://github.com/FinalTheory/wireless-network-reproduction/commits/master) and [releases](https://github.com/FinalTheory/wireless-network-reproduction/releases).


## License

Wireless Network Reproduction is [BSD-licensed](https://github.com/FinalTheory/wireless-network-reproduction/blob/master/LICENSE).
