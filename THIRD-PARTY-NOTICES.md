# Third-party notices

Corvus includes material derived from the following projects.

## Pre-release packages

The shipped projects' lock files resolve pre-release packages only by exception:

- Samboy063.LibCpp2IL `2022.1.0-pre-release.21` and its dependency
  Samboy063.WasmDisassembler `2022.1.0-pre-release.21` (https://github.com/SamboyCoding/Cpp2IL, MIT). Corvus reads
  Il2Cpp metadata versions 24-39 through the 2022.1 line, which has no stable release; the newest stable, 2022.0.7.2,
  dates from October 2022.
- Microsoft.CodeAnalysis.Analyzers `5.9.0-1.26328.17`, which Microsoft.CodeAnalysis.CSharp 5.9.0 depends on. It holds
  analyzers and build files only and puts no file in the program.

Each is pinned by version and content hash in `src/Corvus/packages.lock.json`, and a test refuses any other
pre-release package in the shipped projects' lock files.

## dotnet/runtime

The NativeAOT reader (`src/Corvus/Native/NativeAot`) ports the NativeFormat metadata record schema
(`src/coreclr/tools/Common/Internal/Metadata/NativeFormat/Generator/SchemaDef.cs` and the generated readers) and
follows the format definitions of the NativeAOT compiler and runtime (module headers, dehydrated data, MethodTable
layout, stack-trace and reflection maps) of https://github.com/dotnet/runtime.

```
The MIT License (MIT)

Copyright (c) .NET Foundation and Contributors

All rights reserved.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## ida-pro-mcp

Parts of the IDA worker (`src/Corvus/Native/Providers/Ida/ida_worker.py`: type text parsing, user type,
local variable and stack frame edits, struct member references, declaration parsing with messages, the Python
evaluation op, the analysis edits: code, functions, data items and undefined ranges, operand display formats, enum member
upserts, stack member deletion, the pseudocode object references of `decompile_native refs=true`, request cancellation and
deadlines: per-request deadlines that long loops check for partial results, IDA's cancel flag cleared around each request,
and the profile hook that stops a script) are adapted from
[mrexodia/ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp); the Ghidra worker's `EditOps.java` follows the same
operations on Ghidra's listing, and `search_instructions` (`src/Corvus/Tools/NativeAnalysis/NativeCodeTools.Search.cs`) follows
the query shape of its `insn_query` and `search_text`. The IDA marked positions the server keeps for notes (`set_marks`) use its bookmark slot handling. The output formats of `make_code_pattern` follow its signature maker, and the function roles of the `summarize_file` triage and the `analyze_native_function` component view follow its `survey_binary` and `analyze_component`.

```
MIT License

Copyright (c) 2025 Duncan Ogilvie

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## Ghidra servers

Parts of the Ghidra worker (`src/Corvus/Native/Providers/Ghidra/worker/*.java`) follow designs or adapt code
from these Apache License 2.0 projects (https://www.apache.org/licenses/LICENSE-2.0).

- [clearbluejar/pyghidra-mcp](https://github.com/clearbluejar/pyghidra-mcp), Copyright clearbluejar and contributors:
  the decompiler pool in `Decompilers.java` (LIFO reuse, bounded slots, one deadline over both the wait and the
  run, `flushCache` after writes), from `decompiler_pool.py`.
- [LaurieWired/GhidraMCP](https://github.com/LaurieWired/GhidraMCP), Copyright 2025 LaurieWired: keeping fd 1 for
  the protocol and sending `System.out` to stderr (`Worker.java`); type names resolved after Ghidra's parser through
  C and Windows aliases, `P`-prefixed pointer typedefs and a case-insensitive search over every category
  (`TypeOps.java`); the decompiler's parameters committed before a parameter edit when they differ from the
  database's, as Ghidra's own decompiler actions do (`FrameOps.java`).
- [bethington/ghidra-mcp](https://github.com/bethington/ghidra-mcp): a `BundleHost` acquired before analysis in a
  custom headless host, and the program saved before it and the project are released on shutdown (`Worker.java`);
  a decompilation that times out retried once with a longer limit inside the same request (`CodeOps.java`);
  inline scripts: a run() body wrapped into a GhidraScript class with its import lines moved to the top, the class name
  taken from `public class`, and the script's directory enabled on the bundle host (`ScriptOps.java`); the set of
  named type edits, after its data type tools (delete and rename a type; add, retype and remove one struct or union
  member: `TypeEditOps.java`).
  Its NOTICE file reads:

  ```
  Ghidra MCP Server
  Copyright 2025-2026 Ben Ethington and Ghidra MCP Server contributors

  This product was originally derived from the GhidraMCP project by
  LaurieWired (https://github.com/LaurieWired/GhidraMCP), licensed
  under the Apache License, Version 2.0. The current project has
  since been substantially rewritten and extended; LaurieWired retains
  copyright over any portions of the original work that remain.

  Acknowledgments to all listed contributors in README.md.
  ```
- [cyberkaida/reverse-engineering-assistant](https://github.com/cyberkaida/reverse-engineering-assistant) (ReVa),
  Copyright 2023 cyberkaida: a decompiler timeout reported as its own error, distinct from a decompilation failure
  (`CodeOps.java`); C declarations parsed with `CParser` into the program's data type manager with the replace
  handler, and types parsed against the program's manager so pointer sizes follow its data organization
  (`TypeOps.java`); decompiler variables renamed and retyped through `HighFunctionDBUtil.updateDBVariable`
  (`FrameOps.java`); the shape of `search_decompiled` (a regex over every function's pseudocode with a function cap), of
  `reanalyze_native` (per-run analyzer options over a re-run auto-analysis) and of `list_functions view=candidates`
  (code outside functions ranked by references) (`ControlOps.java`, `Worker.java`).
- [jtang613/GhidrAssistMCP](https://github.com/jtang613/GhidrAssistMCP), Copyright (c) 2025 Jason Tang, MIT License (text as
  for ida-pro-mcp above): a Java script run through `GhidraScriptUtil.getProvider` and `getScriptInstance`, then
  `execute` with a `GhidraState` and `ScriptControls` whose writers capture its output (`ScriptOps.java`).

## AsmArm64

The ARM64 decoder and disassembly (`src/Corvus/Native/Code/Arm64Decoder.cs`, `NativeDisassembler.cs`) use
the [xoofx/AsmArm64](https://github.com/xoofx/AsmArm64) library, which ships with the published server.

```
BSD 2-Clause License

Copyright (c) Alexandre Mutel
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

## YARA-X

`search_container kind=yara` calls the C API of [VirusTotal/yara-x](https://github.com/VirusTotal/yara-x) 1.22.0
(`libyara_x_capi`) inside a `corvus worker` process (`src/Corvus/Native/Providers/Worker/Yara`). The release archives
and the .NET tool ship the library under `runtimes/<rid>/native`: upstream's win-x64 build, and builds of the 1.22.0
source for the other platforms.

```
Copyright (c) 2024. The YARA-X Authors. All Rights Reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors
   may be used to endorse or promote products derived from this software without
   specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS “AS IS” AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (
INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

## Hermes

The Hermes bytecode reader (`src/Corvus/Core/Hermes`) carries opcode and builtin tables generated from
`include/hermes/BCGen/HBC/BytecodeList.def` and `Builtins.def` at each release tag, and follows the file format
definitions (`BytecodeFileFormat.h`, `DebugInfo.h`, `SerializedLiteralGenerator.h`) of https://github.com/facebook/hermes.

```
MIT License

Copyright (c) Meta Platforms, Inc. and affiliates.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## lzfse

The LZFSE and LZVN decoder (`src/Corvus/Core/Firmware/Lzfse.cs`) ports the reference decoder of
https://github.com/lzfse/lzfse 1.0 (`lzfse_decode_base.c`, `lzfse_fse.c`, `lzfse_fse.h`, `lzvn_decode_base.c`).

```
Copyright (c) 2015-2016, Apple Inc. All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

1.  Redistributions of source code must retain the above copyright notice,
    this list of conditions and the following disclaimer.

2.  Redistributions in binary form must reproduce the above copyright notice,
    this list of conditions and the following disclaimer in the documentation
    and/or other materials provided with the distribution.

3.  Neither the name of the copyright holder(s) nor the names of any contributors
    may be used to endorse or promote products derived from this software without
    specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
OF SUCH DAMAGE.
```

## carfile-go

The deepmap-2 decoder and the KCBC chunk reader (`src/Corvus/Core/Mobile/AssetCatalogBitmap.cs`) follow the format
description and decoders of https://github.com/devcxm/carfile-go 0.8.0.

```
MIT License

Copyright (c) 2026 devcxm

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## microsoft-ui-xaml

The XBF reader (`src/Corvus/Services/Dotnet/XbfReader.cs`) carries the stable type and property index tables
generated from `dxaml/xcp/core/Parser/StableXbfIndexes.g.h` (`XbfIndexes.g.cs`), and follows the XBF format and
object writer node definitions (`xamlbinaryformatsubreader2.cpp`, `ObjectWriterNodeType.h`, the custom runtime data
serializers) of https://github.com/microsoft/microsoft-ui-xaml.

```
MIT License

Copyright (c) Microsoft Corporation. All rights reserved.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## Swift

The Swift demangler (`src/Corvus/Native/Swift/SwiftDemangler*.cs`) ports the demangler, old-mangling demangler, node
printer and punycode decoder of the Swift project (`lib/Demangling/Demangler.cpp`, `OldDemangler.cpp`,
`NodePrinter.cpp`, `Punycode.cpp`) of https://github.com/swiftlang/swift. Its test corpus
(`tests/Corvus.Tests/NativeFormats/SwiftManglings.txt`) is `test/Demangle/Inputs/manglings.txt` of the same project.
Copyright (c) 2014 - 2017 Apple Inc. and the Swift project authors, licensed under the Apache License 2.0
(https://www.apache.org/licenses/LICENSE-2.0) with the Runtime Library Exception:

```
## Runtime Library Exception to the Apache 2.0 License: ##

    As an exception, if you use this Software to compile your source code and
    portions of this Software are embedded into the binary product as a result,
    you may redistribute such product without providing attribution as would
    otherwise be required by Sections 4(a), 4(b) and 4(d) of the License.
```

## Sigstore trust root and npm keys

`src/Corvus/Services/Web/Packages/TrustRoots/sigstore-trusted-root.json` is `targets/trusted_root.json` of
https://github.com/sigstore/root-signing at commit c9bda74ad2221f938f7d2e0295ca3aad2da710a8, licensed under the Apache
License 2.0 (https://www.apache.org/licenses/LICENSE-2.0). `npm-attestation-keys.json` beside it is the public key list
npm publishes at https://registry.npmjs.org/-/npm/v1/keys.
