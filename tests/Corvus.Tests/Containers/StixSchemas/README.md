# STIX 2.1 JSON schemas

The OASIS CTI TC's STIX 2.1 JSON schemas from https://github.com/oasis-open/cti-stix2-json-schemas (`schemas/`,
commit 9af1db41b7b86c06324f899649ae83480134f66e) under its BSD-3-Clause license (`LICENSE`), unchanged except that
the raw zero-width spaces and soft hyphen in `common/binary.json` are written as JSON escapes (the same string value).
`StixBundleTests` validates the bundles `summarize_file stixPath=` writes against them.
