# Third-party notices

NetDecompilerMcp includes material derived from the following projects.

## dotnet/runtime

The NativeAOT reader (`src/NetDecompilerMcp/Native/NativeAot`) ports the NativeFormat metadata record schema
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

Parts of the IDA worker (`src/NetDecompilerMcp/Native/Providers/Ida/ida_worker.py`: type text parsing, user type,
local variable and stack frame edits, struct member references, declaration parsing with messages, and the Python
evaluation op) are adapted from [mrexodia/ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp).

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

## Ghidra servers (designs adapted, no code copied)

The Ghidra worker (`src/NetDecompilerMcp/Native/Providers/Ghidra/worker/*.java`) is original code. Some of its
designs follow these Apache License 2.0 projects (https://www.apache.org/licenses/LICENSE-2.0), and the files
concerned say so in their headers.

- [clearbluejar/pyghidra-mcp](https://github.com/clearbluejar/pyghidra-mcp), Copyright clearbluejar and contributors:
  the decompiler pool in `Decompilers.java` (LIFO reuse, bounded slots, one deadline over both the wait and the
  run, `flushCache` after writes), from `decompiler_pool.py`.
- [LaurieWired/GhidraMCP](https://github.com/LaurieWired/GhidraMCP), Copyright 2025 LaurieWired: keeping fd 1 for
  the protocol and sending `System.out` to stderr (`Worker.java`).
- [bethington/ghidra-mcp](https://github.com/bethington/ghidra-mcp): a `BundleHost` acquired before analysis in a
  custom headless host, and the program saved before it and the project are released on shutdown (`Worker.java`).
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
  (`TypeOps.java`).
