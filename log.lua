function logging(time,ip,rule_id,msg,pattern)
    
local request_method      = ngx.req.get_method()
local request_uri = ngx.var.request_uri      --网站url
local request_headers     = ngx.req.get_headers()

local post_data =  ngx.req.get_body_data() or ""
local time = ngx.localtime()
local ip = ngx.var.remote_addr --客户端IP
local cjson_safe = require "cjson.safe"
    _t = request_method.." "..request_uri.." HTTP/1.1" 
    _t1 = ""
    for k,v in pairs(request_headers)do
        _t1 = _t1..k..":"..v
    end
    packet = _t.._t1..post_data.."'"
    
    --text = "{'time':'"..time.."','ip':'"..ip.."','rule_id':"..rule_id..",'msg':'"..msg.."',"..packet.."}\n"
    text = {
        time = time,
        ip = ip,
        rule_id = rule_id,
        msg = msg,
        pattern = pattern,
        packet = packet,
    }
    text = cjson_safe.encode(text)
    
    file:write(text)
    file:flush()
end

if ngx.ctx.datalog  then
    logging(time,ip,ngx.ctx.rule_id,ngx.ctx.rule_msg,ngx.ctx.pattern)
end