# CrowdStrike Client Downloader

A simple command-line utility to download all current versions of the CrowdStrike Falcon client for Mac and Windows.  You can find pre-compiled versions over in the "Releases" section, to the right.

You will need an API key pair with the "sensor download" option enabled.

Run it like so:
```shell
./crowdstrike-downloader \
   -client-id abcd1234abcd1234 \
   -client-secret somesecretlettershere
```

It will download all sensor downloads into `mac` and `windows` folders. It skips files that already exist, comparing them by filename.

