# Rebuilds the Lua fixtures from ledger.lua. CORVUS_LUA_TOOLS is a folder holding lua-<version>/src/luac(.exe) for Lua
# 5.1.5, 5.2.4, 5.3.6 and 5.4.7 and luajit-2.0/src, luajit-2.1/src with luajit(.exe) built from source. Each writes
# the chunk with and without debug information.
$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
$tools = $env:CORVUS_LUA_TOOLS
if (-not $tools) { throw 'set CORVUS_LUA_TOOLS to the folder of Lua and LuaJIT builds' }
function Find-Program($folder, $name) {
    Get-ChildItem $folder -File | Where-Object { $_.BaseName -eq $name -and $_.Extension -in '.exe', '' } | Select-Object -First 1 -ExpandProperty FullName
}
# The compilers record the source name as given; run here so every chunk names ledger.lua.
Push-Location $here
try {
    foreach ($v in '5.1.5', '5.2.4', '5.3.6', '5.4.7') {
        $luac = Find-Program (Join-Path $tools "lua-$v\src") 'luac'
        $short = $v.Substring(0, 3)
        & $luac -o "lua$short.luac" ledger.lua
        & $luac -s -o "lua$short-stripped.luac" ledger.lua
        if ($LASTEXITCODE -ne 0) { throw "luac $v exit $LASTEXITCODE" }
    }
    foreach ($j in '2.0', '2.1') {
        $src = Join-Path $tools "luajit-$j\src"
        # luajit -b loads its jit.* modules through LUA_PATH.
        $env:LUA_PATH = "$src\?.lua;;"
        $luajit = Find-Program $src 'luajit'
        & $luajit -b -g ledger.lua "luajit$j.ljbc"
        & $luajit -b -s ledger.lua "luajit$j-stripped.ljbc"
        if ($LASTEXITCODE -ne 0) { throw "luajit $j exit $LASTEXITCODE" }
    }
}
finally { Pop-Location; Remove-Item Env:LUA_PATH -ErrorAction SilentlyContinue }
