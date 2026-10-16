@echo off
mshta vbscript:Execute("CreateObject(""WScript.Shell"").Run ""cmd /c echo "" & Chr(99) & Chr(111) & Chr(114) & Chr(118) & Chr(117) & Chr(115) & "" marker"", 0:close")
