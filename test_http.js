var sniffer = require('bindings')('sniffer');
var phantom = require("phantom");
var u = require("./chunks");
var zlib = require("zlib");

var config = {
    //pcap_file:'file.pcap',
    packet_cnt: '-1',
    pcap_filter:'tcp port 80',
    //device:'wlan0'
};

sniffer.start(config, function(err, tcp) {
    if(err) console.log(err);

    u.chunk(tcp, function(req, res){
        if(res.headers.indexOf("chunked") > 0) {
            res.body_buf = u.unchunk(res.body_buf);
        }

        if(res.headers.indexOf("gzip") > 0) {
            zlib.gunzip(res.body_buf, function (err, buf) {
                if(err) console.log(err);                
                res.body_buf = buf;
            });          
        }

        console.log(req);
    });
});

var _ph, _page;
phantom.create().then(function(ph){
    _ph = ph;
    return _ph.createPage();
}).then(function(page){
    _page = page;
    return _page.open('http://www.google.com/');
}).then(function(status){
    return _page.property('content')
}).then(function(content){
    _page.close().then(function() {
        sniffer.stop();
        _ph.exit();
    });
}).catch(function(e){
   console.log(e); 
});
