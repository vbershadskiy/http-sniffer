# http-sniffer

give node permission to capture packets:

linux: `which node | xargs sudo setcap cap_net_raw+eip`
mac: `sudo chmod o+r /dev/bpf*`

usage:
```javascript
var sniffer = require('bindings')('sniffer');

sniffer.start(config, function(err, tcp) {
  u.chunk(tcp, function(req, res){
    console.log(req);
  }
});

sniffer.stop();
```
