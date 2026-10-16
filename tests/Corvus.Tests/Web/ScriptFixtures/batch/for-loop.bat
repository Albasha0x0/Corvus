@echo off
set a=rekram suvroc
set o=
for /l %%i in (12,-1,0) do call set o=%%o%%%%a:~%%i,1%%
echo %o%
