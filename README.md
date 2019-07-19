# burp-wcf-gzip

## Author

Written by Anthony Marquez ([@BoogeyMarquez](https://twitter.com/boogeymarquez))

```
Tweaked by mazrog to include

- deciphering of requests that are not gzipped
- huge requests handling [WIP]

```

## Description

A couple of burp extensions that I created during a couple of security assessments, and I figure I would share them with others to save some pain.

## Instructions

1. Clone repo
2. Compile the NBFS.cs with `csc.exe` and copy the NBFS.exe to the same directory as your Burp JAR executable
3. Download Jython standalone JAR if you do not already have it (created using Jython 2.7) - http://www.jython.org/
4. Open Burp and click the Extender tab.
5. In `Options`, select the python environnement as the jython standalone.
6. In the `Extensions`, click `Add`, select 'python' as `Extension type` and choose the `WcfGzipBurpPlugin.py` file.
7. Finish the loading and you're done!


## Details

Within this repo are 2 files (not including this README):

***

#### WcfGzipBurpPlugin.py
This plugin is used to decompress and decode WCF traffic if it is binary encoded and compressed using 'gzip'.  Burp's builtin 'gzip' decompressing functionality was not correctly identifying the compressed traffic sent by the application I was testing. Each request in any of the Burp tools will have an additional tab that decodes the request and will re-encode on edit.

***

#### NBFS.cs
Here is the file used to create a binary to decode and encode WCF binary format.
I owe credit for the creation of this file to Brian Holyfield's Burp plugin located here: https://github.com/GDSSecurity/WCF-Binary-SOAP-Plug-In

As stated above, this must be in the same directory as the Burp JAR executable.
