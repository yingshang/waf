
local request_method      = ngx.req.get_method()
local request_uri = ngx.var.request_uri      --网站url
local request_headers     = ngx.req.get_headers()

local post_data =  ngx.req.get_body_data() or ""
local time = ngx.localtime()
local ip = ngx.var.remote_addr --客户端IP
local cjson_safe = require "cjson.safe"
local ngx_ctx = ngx.ctx





function logging(time,ip,rule_id,msg,pattern)
    _t = "'packet':'"..request_method.." "..request_uri.." HTTP/1.1" 
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
datalog = ngx_ctx.datalog or "no"

if datalog == "on" then
    logging(time,ip,ngx_ctx.rule_id,ngx_ctx.rule_msg)
end