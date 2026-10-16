@echo off
goto b
:a
set s=%s% marker
goto c
:b
set s=corvus
goto a
:c
echo %s%
exit /b
