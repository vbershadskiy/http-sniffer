var is_match = function(sub, data, data_ix){
    if(sub.length + data_ix > data.length) {
        return false;
    }

    for(var k=0;k<sub.length;k++) {
        if(String.fromCodePoint(data[data_ix+k]) != sub.charAt(k)) {
            return false;
        }
    }

    return true;
};

const FIND_HTTP_STATUS = 1;
const FIND_HEADERS = 2;
const FIND_BODY = 3;
const FIND_END = 4;

const EMPTY = {
    next: null,
    http: "",
    headers: "",
    body_buf: null
};

var http_regex = function(data){
    var pattern = FIND_HTTP_STATUS;

    var root = null;
    var curr = null;

    for(var i=0;i<data.length;) {
        var ix = i;

        switch(pattern) {
            case FIND_HTTP_STATUS: {
                while(i < data.length) {
                    if(is_match("HTTP/1.1", data, i)) {
                        pattern = FIND_HEADERS;
                        while(!is_match("\r\n", data, i)) {
                            i++;
                        }
                        break;
                    }

                    i++;
                }

                if(pattern == FIND_HEADERS) {
                    var n = {
                        next: null,
                        http: data.slice(ix, i).toString(),
                        headers: "",
                        body_buf: Buffer.from("")
                    };

                    if(root == null) {
                        root = n;
                        curr = n;
                    } else {
                        var walker = curr;

                        while(walker.next != null){
                            walker = walker.next;
                        }
                        walker.next = n;

                        curr = walker.next;
                    }

                    i+=2;
                } else {
                    pattern = FIND_END;
                }

                break;
            }
            case FIND_HEADERS: {
                while(i < data.length) {
                    if(is_match("\r\n\r\n", data, i)) {
                        pattern = FIND_BODY;
                        break;
                    }
                    i++;
                }

                if(pattern == FIND_BODY) {
                    curr.headers = data.slice(ix, i).toString();

                    i+=4;
                } else {
                    pattern = FIND_END;
                }

                break;
            }
            case FIND_BODY: {
                while(i<data.length) {
                    if(is_match("GET /", data, i) ||
                        is_match("POST /", data, i) ||
                        is_match("PUT /", data, i) ||
                        is_match("HEAD /", data, i) ||
                        is_match("HTTP/1.1", data, i) ) {
                        pattern = FIND_HTTP_STATUS;
                        break;
                    }
                    i++;
                }

                if(pattern != FIND_HTTP_STATUS) {
                    pattern = FIND_END;
                } 

                if((i-ix) > 0) {
                    curr.body_buf = data.slice(ix, i);
                }

                break;
            }            
            case FIND_END: {
                console.log("\nerror parsing http request/response\n");
            }
            default: 
                break;
        }
    }

    return root != null ? root : EMPTY;   
};

exports.chunk = function(tcp, callback) {
    var http_req = http_regex(tcp.req.payload);
    var http_res = http_regex(tcp.res.payload);

    while(http_req != null || http_res != null){
        var req = http_req || EMPTY;
        var res = http_res || EMPTY;

        callback(req, res);

        if(http_req != null) {
            http_req = http_req.next;
        }

        if(http_res != null) {
            http_res = http_res.next;
        }
    }
};

exports.unchunk = function(body_buf) {
    var buf = Buffer.from("");

    var ix = 0;
    for(var i =0;i<body_buf.length;i++) {
        if(is_match("\r\n", body_buf, i)) {
            var chunk_size_buf = body_buf.slice(ix, i);
            var chunk_size = parseInt(chunk_size_buf.toString(), 16);
            if(chunk_size == 0) break;

            if(chunk_size > 0) {
                ix = i + 2;
                i = ix + chunk_size;
                var chunk = body_buf.slice(ix, i);
                var len = buf.length+chunk.length;
                buf = Buffer.concat([buf, chunk], len);
                ix = i;
            }
        }
    }

    return buf;
};
