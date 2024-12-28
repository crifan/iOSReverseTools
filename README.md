# iOSReverseTools

* Update: `20241228`

## Function

Collect iOS reverse related tools for everyone use

* Note
  * Almost each tool has separate `README.md`, for details, please refer it

## Structure

```bash
➜  iOSReverseTools git:(main) ✗ tree .
.
├── README.md
├── dynamicDebug
│   ├── debugserver
│   │   ├── iOS12.4
│   │   │   ├── DeveloperDiskImage
│   │   │   │   ├── DeveloperDiskImage.dmg
│   │   │   │   └── DeveloperDiskImage.dmg.signature
│   │   │   ├── debugserver_debuggable
│   │   │   ├── debugserver_entitlement_debuggable.xml
│   │   │   ├── debugserver_entitlement_orig.xml
│   │   │   └── debugserver_orig
│   │   ├── iOS13.3.1
│   │   │   ├── debugserver
│   │   │   ├── debugserver_entitlements_debuggable.xml
│   │   │   └── debugserver_orig
│   │   └── iOS13.4
│   │       ├── debugserver_debuggable
│   │       ├── debugserver_entitlements_debuggable.xml
│   │       ├── debugserver_entitlements_orig.xml
│   │       └── debugserver_orig
│   ├── iOSOpenDev
│   │   ├── README.md
│   │   ├── Specifications
│   │   │   ├── iosOpenDev安装附件-新.zip
│   │   │   └── iosopendev专用Specifications.zip
│   │   └── iOSOpenDev-1.6-2.pkg
│   └── logging
│       └── com.apple.system.logging.plist
├── other
│   └── AutoRepackIpa
│       ├── README.md
│       └── autoRepackIpa.py
└── staticAnalysis
    ├── Mach-O
    │   ├── IDA
    │   │   └── plugins
    │   │       └── crifan
    │   │           ├── AutoRename
    │   │           │   ├── AutoRename.py
    │   │           │   └── README.md
    │   │           ├── exportIDASymbol
    │   │           │   ├── README.md
    │   │           │   └── exportIDASymbol.py
    │   │           └── ida_search_block
    │   │               ├── README.md
    │   │               └── ida_search_block.py
    │   ├── MachOView
    │   │   ├── MachOView-2.6.1.dmg
    │   │   └── README.md
    │   ├── jtool2
    │   │   ├── excitedplus1s
    │   │   │   └── README.md
    │   │   └── newosxbook.com
    │   │       ├── README.md
    │   │       └── jtool2.tgz
    │   └── radare2
    │       ├── Cutter
    │       │   └── Cutter-v2.0.5-x64.macOS.dmg
    │       ├── README.md
    │       ├── radare2-m1-5.9.8.pkg
    │       └── radare2-x64-5.9.8.pkg
    ├── exportStrResInfo
    │   ├── README.md
    │   └── exportMacho_StrResInfo.sh
    ├── framework
    │   └── dyld_shared_cache
    │       └── DyldExtractor
    │           └── README.md
    ├── header
    │   ├── class-dump
    │   │   ├── MonkeyDev
    │   │   │   ├── README.md
    │   │   │   └── class-dump
    │   │   ├── lechium
    │   │   │   ├── README.md
    │   │   │   └── classdumpc
    │   │   └── stevenygard
    │   │       ├── README.md
    │   │       ├── class-dump
    │   │       └── class-dump-3.5.dmg
    │   └── dsdump
    │       └── paradiseduo
    │           ├── README.md
    │           ├── dsdump
    │           └── dsdump.py
    └── symbol
        ├── restore-symbol
        │   ├── HeiTanBc
        │   │   ├── README.md
        │   │   └── restore-symbol
        │   ├── crifan
        │   │   ├── README.md
        │   │   └── restore-symbol
        │   └── tobefuturer
        │       ├── README.md
        │       └── restore-symbol
        └── resymbol
            ├── README.md
            ├── resymbol
            └── resymbol_x86_64

43 directories, 58 files
➜  iOSReverseTools git:(main) ✗ 
```
