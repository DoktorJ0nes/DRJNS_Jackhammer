# Dr_J0nes Jackhammer

DRJNS_Jackhammer (Dr_J0nes Jackhammer) is a low-level runtime patching and debugging tool based on Windows Debug APIs.

It allows injection of custom x86-64 instructions at runtime using pattern-based breakpoint interception.

## Key Properties
- no file modification
- runtime-only memory patching
- generic design (non application-specific)

## Execute
```DRJNS_Jackhammer.exe <targetApplicationPath>```

Example:
```call DRJNS_Jackhammer.exe "C:\Program Files (x86)\Steam\steamapps\common\RoadCraft\root\bin\pc\Roadcraft - Retail.exe"```

## Config
The payload pattern and runtime patches get defined in the ```config.json``` file.

```
{
  "payload": "xx yy zz",
  "patches": {
    "0xAA": [
      "00 01",
	  "11 22"
    ]
  }
}
```

The tool searches in the main module of the target process for the pattern matching the payloads byte code ```xx yy zz```.
The instruction bytes ```00 01``` will be executed temporarily when the target process reaches offset address ```0xAA``` at execution, which is relative to the payload patterns found address in the target process.
The tool makes sure that at the target process address the original bytes are matching the check bytes ```11 22``` and the tool terminates if the check bytes do not match.

## How it works
The tool searches the main module of the target process for the exact byte pattern defined by the payload.

For each patch entry, a breakpoint (INT3) is placed at the address calculated as found payload address + offset.

Before setting the breakpoint, the tool verifies that the bytes currently present at that address match the defined check bytes. If any byte differs, execution is aborted.

When the breakpoint is hit at runtime, the original byte is temporarily restored and the thread is single-stepped. During this single-step phase, the patch bytes are written to the target address and executed.

After execution, the original bytes are fully restored and all breakpoints are reinserted, leaving the original code intact outside of the execution window.

## Third-Party Libraries
This project uses nlohmann/json (MIT License).
The library is fetched automatically during build and is not included in this repository.

## Disclaimer
This project does not contain any assets, proprietary formats, code or copyrighted material of a third party.
The user is solely responsible for ensuring compliance with the terms of service of any software this tool is used on.
The author is not affiliated with any game developer or publisher.
Use at your own risk.

## License
MIT