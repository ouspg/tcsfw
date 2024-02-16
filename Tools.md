# Tools

The tcsfw can read output from several different tools to verify the security statement and claims.
The tool output is read from a directly structure, which root must be provided to the framework by `--read <directory>` command-line arguement.

## Batch files and directories

The back directory structure can be arbitarily deep. Each directory which contains data files, must have special metafile `00meta.json`. The metafile must always contain at least `file_type` of the data files. For example, consider the following metafile `00meta.json` for NMAP output data files.

```json
{
    "file_type": "nmap"
}
```

Each batch directory has also _label_, which allows to filter the processed data.
By default, label is the name of the directory, but it can be changed in the metafile, e.g. the following NMAP data is filtered by label `nmap-01`.
```json
{
    "file_type": "nmap",
    "label": "nmap-01"
}
```

See [end of this page](#advanced-metafile-definitions) for advanced options required with some data types.

## List of supported tools

The following lists the supported tools and formats and shortly describes what is actually supported.
A sample command to capture the output in proper format is shown for command-line tools.

### Android Manifest

Data files are APK manifest XML files with suffix `.xml`.
Example metafile `00meta.json`:

```json
{
    "file_type": "apk"
}
```

A manifest file can be extracted from Android package file by `apktool' or simply using 'unzip'.

```
$ apktool d <package>.apk -f -o apk-files
```
The file can be found from `apk-file/AndroidManifest.xml`.
As the package file is a zip, the following works as well.
```
$ unzip <package>.apk AndroidManifest.xml
```

### Black Duck vulnerabilities

Data files are csv-files downloaded from Black Duck binary analyser and named as `<component>.csv` where `<component>` is the name of the SW component.
Example metafile `00meta.json`:

```json
{
    "file_type": "blackduck-vulnerabilities"
}
```

### Censys

Data files are json-files fetched by Censys search API and named as `<address>.json` where `<address>` is address of the scanned remote host.
Example metafile `00meta.json`:

```json
{
    "file_type": "censys"
}
```

Use of Censys API requires an account with suitable permissions. Once account has been set up property, the framework utility can be used to fetch the JSON through API:
```
$ python tcsfw/censys_scan <address>
```

### Github releses

Data files are release json-files fetched from GitHub and named as `<component>.json` where `<component>` is the name of the SW component.
Example metafile `00meta.json`:

```json
{
    "file_type": "github-releases"
}
```

### HAR

Data files are HAR json-files saved by browser and named as `<host>.json` where `<host>` is the name of the browsing host.
Example metafile `00meta.json`:

```json
{
    "file_type": "har"
}
```
Chrome can save HAR-files compatible with the reader.
The way to save HAR-file depends on the browser.

### MITM proxy

Data files are custom log-files captured with MITM proxy having suffix  `.log`. Example metafile `00meta.json`:
```json
{
    "file_type": "mitmproxy"
}
```

The custom data is saved using the following very simple MTIM proxy addon hook (yes, very unsatisfactory, sorry):

```python
import logging
from datetime import datetime

class TLSCheck:
    """Log connection attempts with possible error message"""
    def tls_established_client(self, data):
        conn = data.conn
        ser = data.context.server
        logging.info("tls_established,%s,%d,%s,%d,%s,%s",
            conn.peername[0], conn.peername[1],
            ser.peername[0], ser.peername[1],
            conn.sni or "", conn.error or "")

    def tls_failed_client(self, data):
        conn = data.conn
        ser = data.context.server
        logging.info("tls_failed,%s,%d,%s,%d,%s,%s",
            conn.peername[0], conn.peername[1],
            ser.peername[0], ser.peername[1],
            conn.sni or "", conn.error or "")


addons = [TLSCheck()]
```

Refer MITM proxy documentation how to use addon hooks.

### Nmap

Data files are Nmap XML-formatted output files with suffix `.xml`. Example metafile `00meta.json`:
```json
{
    "file_type": "nmap"
}
```
The nmap-command is ran in the following manner to capture the data:

```
$ nmap -oX <file>.xml <target>
```

### PCAP

Data files are PCAP (not pcap-ng) files with suffix `.pcap`. Example metafile `00meta.json`:
```json
{
    "file_type": "pcap"
}
```

Files can be captured by _Wireshark_ or `tcpdump`, see their documentation for instructions.

### SPDX

### Ssh-audit

### Testssl.sh

### Tshark (BLE)

### HTTP responses

### ZED proxy

## Advanced metafile definitions

FIXME: To be done.

- Specify order to load data directores
- Specify addresses
- Specify extenal policy

```json
{
    "file_type": "mitmproxy",
    "addresses": {
        "192.168.4.8": "Ruuvi app"
    }
}
```
