# Review a reported mail message

Read the headers, links and attachments of a message a user reported, without opening a link or running an attachment.

Requires Corvus ([installation](../installation.md)), jq 1.7, a POSIX shell, and the message saved as a file: `.eml` (MIME) or Outlook `.msg`.

## Identify the message

```sh
corvus summarize_file path=report.eml
```

- Prints hashes, the format (`MIME message` or Outlook message) and highlights.
- Highlights: sender, recipients, subject, date, the earliest Received hop, recorded results, each attachment and the first link.

## Read the headers

```sh
corvus summarize_file path=report.eml view=mail
```

- `from`, `sender`, `replyTo`, `returnPath`, `to`, `cc`, `date`, `messageId` and the mailer.
- `received`: each Received header's from, by, with and id clauses and date; the last row is the earliest hop.
- `authentication`: SPF, DKIM, DMARC and ARC results the receiving servers recorded; Corvus does not re-check them.
- DKIM and ARC signatures: domain, selector and signed headers; the signatures are not verified.
- An unsent or locally made `.msg` has no internet headers; the chain and results are then reported as unknown.

## List the links

```sh
corvus summarize_file path=report.eml view=mail --json | jq -r '.structured.detail.links[]'
```

- Every http, https and ftp URL in the bodies; nothing is fetched.

## List and extract the attachments

```sh
corvus search_container path="$PWD/report.eml" query='*' kind=file
corvus unpack_container path=report.eml extractOnly=true outputDirectory=case/report
```

- `view=mail` names each attachment's content type, disposition, size, detected type and SHA-256.
- `search_container kind=file` lists the bodies, attachments and members of attached archives, without writing them.
- `unpack_container` writes the bodies (`body.html`, `body.txt`) and `attachments/`; an attached archive is extracted beside it.
- A `.msg` also gets its compound file streams under `streams/`.
- A message attached to a `.msg` is read in place, with its own attachments.
- Runnable files get a `.bin` suffix; output stays inside `outputDirectory`.

## Read each attachment

```sh
for f in $(find case/report/attachments -type f); do corvus summarize_file path="$f"; done
corvus summarize_file path=case/report/attachments/invoice.docm view=office
corvus summarize_file path=case/report/attachments/statement.pdf view=pdf
corvus summarize_file path=case/report/attachments/readme.lnk view=lnk
corvus summarize_file path=case/report/attachments/update.ps1.bin view=script
```

- `office`: VBA source, Excel 4.0 macros, OLE packages and findings by line.
- `pdf`: keywords, actions, JavaScript and embedded files.
- `lnk`: the shortcut's target, arguments and noteworthy traits.
- `script`: PowerShell, batch, VBScript or JavaScript with obfuscation folded; nothing runs.

## Match rules

```sh
corvus rules fetch malcontent
corvus search_container path="$PWD/report.eml" query=pack:malcontent kind=yara
```

- Scans the message, then each body and attachment. Corvus ships no rules; `rules fetch` checks the pack's SHA-256.

## Record the case

```sh
corvus summarize_file path=report.eml stixPath=case/report.stix.json
```

- Writes a STIX 2.1 bundle of the message file and its analysis.
