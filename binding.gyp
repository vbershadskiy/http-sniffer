# node-gyp configure build
# node-gyp rebuild
{
    "targets": [{
        "target_name": "sniffer",
        "sources": [ "sniffer.c" ],
        "libraries": [
            "-lpcap"
        ]
    }]
}
