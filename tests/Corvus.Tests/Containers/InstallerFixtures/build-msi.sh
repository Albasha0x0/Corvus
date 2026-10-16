#!/bin/sh
# Rebuilds sample.msi.gz from sample.wxs with msitools (wixl, msibuild) on Linux:  sh build-msi.sh
# wixl writes the files, cabinet and registry; msibuild adds a Binary-table VBScript custom action (type 6 + deferred
# 0x400 + no impersonation 0x800 + ignore errors 0x40), inline JScript (37), a property (51) and their sequence rows.
set -e
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
cd "$work"
mkdir files Binary
printf 'installed readme' > files/readme.txt
printf 'nested report' > files/report.txt
printf 'zipped' > inner.txt && python3 -c "import zipfile; z=zipfile.ZipFile('files/setup.zip','w'); z.write('inner.txt'); z.close()"
printf 'Function Main()\r\n  CreateObject("WScript.Shell").Run "cmd.exe /c whoami", 0\r\n  Main = 1\r\nEnd Function\r\n' > Binary/CheckScript.ibd
cp "$here/sample.wxs" .
wixl -o sample.msi sample.wxs
printf 'Name\tData\ns72\tv0\nBinary\tName\nCheckScript\tCheckScript.ibd\n' > Binary.idt
msibuild sample.msi -i Binary.idt
msibuild sample.msi -q "CREATE TABLE \`CustomAction\` (\`Action\` CHAR(72) NOT NULL, \`Type\` SHORT NOT NULL, \`Source\` CHAR(72), \`Target\` CHAR(255) PRIMARY KEY \`Action\`)" 2>/dev/null || true
msibuild sample.msi -q "INSERT INTO \`CustomAction\` (\`Action\`, \`Type\`, \`Source\`, \`Target\`) VALUES ('RunCheck', 3142, 'CheckScript', 'Main')"
msibuild sample.msi -q "INSERT INTO \`CustomAction\` (\`Action\`, \`Type\`, \`Target\`) VALUES ('Greet', 37, 'var shell = new ActiveXObject(\"WScript.Shell\"); shell.Run(\"cmd.exe /c echo hello\", 0);')"
msibuild sample.msi -q "INSERT INTO \`CustomAction\` (\`Action\`, \`Type\`, \`Source\`, \`Target\`) VALUES ('SetTarget', 51, 'TARGET_URL', 'http://example.test/update')"
msibuild sample.msi -q "INSERT INTO \`InstallExecuteSequence\` (\`Action\`, \`Condition\`, \`Sequence\`) VALUES ('SetTarget', '', 3990)"
msibuild sample.msi -q "INSERT INTO \`InstallExecuteSequence\` (\`Action\`, \`Condition\`, \`Sequence\`) VALUES ('Greet', 'NOT Installed', 3991)"
msibuild sample.msi -q "INSERT INTO \`InstallExecuteSequence\` (\`Action\`, \`Condition\`, \`Sequence\`) VALUES ('RunCheck', 'NOT REMOVE', 6599)"
gzip -9 -n -c sample.msi > "$here/sample.msi.gz"
cd / && rm -rf "$work"
