# iOS forensics tools

## Supported devices
- (iPhone 2G)
- iPhone 3G
- iPhone 3GS
- iPad 1
- iPhone 4 GSM
- iPhone 4 GSM rev A
- iPhone 4 CDMA

Newer devices are ~~NOT~~ supported as long as you have the correct offsets for each kernel version you run this on.

## Requirements
- Xcode (or Command Line Tools)
- iOS 8.4 SDK
- Mac OS X 10.9 SDK (open Xcode to accept the license agreement)

### Building Ramdisk tools
Run `make` in a `ramdisk_tools` folder 

### SSH access
- Run `./tcprelay.sh` in a new terminal window or use Sliver's 'Relay Device Info'
- Run `ssh -p 2222 root@localhost`
	root password is `alpine`
