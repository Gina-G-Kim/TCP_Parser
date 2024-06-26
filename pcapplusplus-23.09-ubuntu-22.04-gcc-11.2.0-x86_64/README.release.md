September 2023 release of PcapPlusPlus (v23.09)
===============================================

PcapPlusPlus web-site:  https://pcapplusplus.github.io/

GitHub page:            https://github.com/seladb/PcapPlusPlus


This package contains:
----------------------

 - PcapPlusPlus compiled libraries (under `lib/`)
    - libCommon++.a
    - libPacket++.a
    - libPcap++.a
 - PcapPlusPlus header files (under `include/pcapplusplus/`)
 - Compiled examples (under `bin/`)
 - Code example with a simple CMake file showing how to build applications with PcapPlusPlus (under `example-app/`)
 - CMake files required to build your application with PcapPlusPlus (under `lib/cmake/pcapplusplus`)
 - pkg-config information you can use to build your application with PcapPlusPlus (under `lib/pkgconfig`)


Using PcapPlusPlus in your project:
-----------------------------------

 - If your application uses CMake, you can add `PcapPlusPlus_ROOT=<PACKAGE_DIR>` when running CMake, for example:
   `cmake -S . -B build -DPcapPlusPlus_ROOT=<PACKAGE_DIR>`
 - If your application uses Makefiles, you can use pkg-config with `PcapPlusPlus.pc`:
   1. Edit `PcapPlusPlus.pc` and replace `prefix` with the package path, for example:
      `prefix="<PACKAGE_DIR>"`
   2. Use pkg-config in your Makefile, for example:
      ```
      all:
         g++ `pkg-config --cflags PcapPlusPlus` -c -o main.o main.cpp
         g++ -o MyApp main.o `pkg-config --libs PcapPlusPlus`
      ```
   3. When running `make` remember to set pkg-config path so it can find `PcapPlusPlus.pc`, for example:
      `PKG_CONFIG_PATH=<PACKAGE_DIR>/lib/pkgconfig make`


Running the examples:
---------------------

 - Make sure you have libpcap installed (it should come built-in with most Linux distributions)
 - You may need to run the executables as sudo

Release notes (changes from v22.11)
-----------------------------------

 - PcapPlusPlus moved from a custom build system to CMake! (thanks @clementperon !)
 - Added IP/IPv4/IPv6 network classes to better support netmask and subnets
 - Add support for opening NFLOG live device (thanks @MrPeck !)
 - MAC address OUI Lookup (thanks @egecetin !)
 - Intel oneAPI compiler support (icpx) (thanks @egecetin !)
 - DPDK improvements:
   - Properly support no RSS mode in `DpdkDevice`
   - Make DPDK app name configurable (thanks @szokovacs !)
   - More generic search of DPDK KNI kernel module in `setup_dpdk.py`
 - New protocols:
   - NFLOG (Linux Netfilter NFLOG) (thanks @jafar75 !)
   - SLL2 (Linux cooked capture v2) (thanks @jiangjiongyu !)
   - TPKT (thanks @wivien19 !)
   - COTP (thanks @wivien19 !)
   - VRRP (thanks @wangchong2023 !)
 - Existing protocols improvements:
   - HTTP - refactor and improve `HttpResponseStatusCode` (thanks @tigercosmos !)
   - SSL/TLS - better detection of possible encrypted handshake messages (thanks @axmahr !)
   - DNS - support parsing of resources with larger data (thanks @aengusjiang !)
   - STP - add editing/crafting support (thanks @egecetin !)
   - ARP - add `isRequest` and `isReply` methods (thanks @tigercosmos !)
   - FTP-DATA support (thanks @egecetin !)
   - NTP - support Kiss of Death (thanks @egecetin !)
   - SIP - refactor status codes + add a few missing ones
 - Modernize the codebase to use `nullptr` instead of `NULL` (thanks @clementperon !)
 - Remove usage of unsupported `pcap_compile_nopcap()` (thanks @yushijinhun !)
 - Internal tools:
   - Codecov integration for coverage reports (thanks @egecetin !)
   - Enable Clang-Tidy (thanks @clementperon !)
   - Enable `cppcheck` (thanks @egecetin !)
   - Improve the test framework
   - Increase test coverage
 - Remove deprecated methods (due to typos):
   - `DhcpLayer::getMesageType()` -> replaced by `DhcpLayer::getMessageType()`
   - `DhcpLayer::setMesageType()` -> replaced by `DhcpLayer::setMesasgeType()`
   - `SSLHandshakeMessage::createHandhakeMessage()` -> replaced by `SSLHandshakeMessage::createHandshakeMessage()`
   - `SSLClientHelloMessage::getExtensionsLenth()` -> replaced by `SSLClientHelloMessage::getExtensionsLength()`
   - `SSLServerHelloMessage::getExtensionsLenth()` -> replaced by `SSLServerHelloMessage::getExtensionsLength()`
 - Tons of bug fixes, security fixes, major and minor improvements (thanks @egecetin, @clementperon, @sashashura, @tigercosmos, @kolbex, @traversebitree, @JasMetzger, @tbhaxor, @yishai1999, @aengusjiang, @Heysunk, @jpcofr !)


Collaborators
-------------

 - @clementperon
 - @egecetin


Contributors
------------

 - @sashashura
 - @tigercosmos
 - @wivien19
 - @jafar75
 - @MrPeck
 - @szokovacs
 - @axmahr
 - @yishai1999
 - @traversebitree
 - @jiangjiongyu
 - @wangchong2023
 - @kolbex
 - @JasMetzger
 - @yushijinhun
 - @aengusjiang
 - @tbhaxor
 - @Heysunk
 - @jpcofr

**Full Changelog**: https://github.com/seladb/PcapPlusPlus/compare/v22.11...v23.09
