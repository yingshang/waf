
--[[

local libinject = require "resty.libinjection"
input = '-1\'union select 1,2,3,4,5,6--'
xss = '1<script>alert(0)</script>'
output = libinject.xss(input)
ngx.log(ngx.ERR,output)

--]]



function test()
    for k,v in pairs(args) do
        ngx.log(ngx.ERR,k..'---'..v)
    end
    if request_method == 'POST' then
    
    --body的长度为0
    if post_data == nil  then
        ngx.log(ngx.ERR,'body length is 0')
    end
    --匹配a=b或者a=b&c=d
    local regex = [[^!{\S+=\S+|\S+=\S+&$!}]] 
    local m = ngx.re.match(post_data, regex, "jo")
    local regex1 = [[{.*?}]] 
    local m1 = ngx.re.match(post_data, regex1, "jo")
    if m then
        data = m[0]
        data = Split(data,'&')
        for k,v in pairs(data) do
            ngx.log(ngx.ERR,k..'---'..v)
        end
    elseif m1 then
            data = cjson.decode(post_data)
            for k,v in pairs(data) do
                if type(v) == 'table' then
                    for key,value in pairs(v)do 
                        ngx.log(ngx.ERR,key..'--'..value)
                    end
                end
            --ngx.log(ngx.ERR,k..'---'..v)
            end
            
    else
        ngx.log(ngx.ERR,'not match')
        end
    
    end
    end




local cjson_safe = require "cjson.safe"
local request_headers     = ngx.req.get_headers()
local request_method      = ngx.req.get_method()
local args = ngx.req.get_uri_args()
local User_Agent = request_headers['User-Agent'] or nil
local Cookie = request_headers['Cookie'] or nil
local Referer  = request_headers['Referer'] or nil
local request_host = request_headers['Host'] or nil
local request_uri = ngx.var.request_uri      --网站url
local remote_ip = ngx.var.remote_addr --客户端IP
local Content_Type = request_headers['Content-Type'] or ""  --识别是否upload

ngx.req.read_body()
local post_data =  ngx.req.get_body_data() or ""
local time = ngx.time()
local config_dict = ngx.shared.config_dict
local white_dict = ngx.shared.white_dict
local black_dict = ngx.shared.black_dict

local config = cjson_safe.decode(config_dict:get("config")) or {}
local white = cjson_safe.decode(white_dict:get("whitelist")) or {}
local black = cjson_safe.decode(black_dict:get("blacklist")) or {}



--日志记录
function logging(time,ip,rule_id,msg)
    _t = "'packet':'"..request_method.." "..request_uri.." HTTP/1.1" 
    _t1 = ""
    for k,v in pairs(request_headers)do
        _t1 = _t1..k..":"..v
    end
    packet = _t.._t1..post_data.."'"
    file = io.open("/data/waf/waf.log","a+")
    text = "{'timestamp':"..time..",'ip':'"..ip.."','rule_id':"..rule_id..",'msg':'"..msg.."',"..packet.."}\n"
    file:write(text)
    file:close()
end








--变量类型
function var_type( vars )
    if vars == 'request_uri'then
        t = {request_uri=request_uri}
    elseif vars == 'request_cookies' then
        t = {request_cookies=Cookie}
    elseif vars == 'request_referer' then
        t = {request_referer=Referer}
    elseif vars == 'request_post' then
        t = {request_post=post_data}
    elseif vars == 'request_host' then
        t = {request_host=request_host}
    elseif vars == 'User_Agent'then
        t = {User_Agent=User_Agent}
    elseif vars == 'remote_ip' then
        t = {remote_ip=remote_ip}
    elseif vars == 'args' then
        t = {
            request_uri=request_uri,
            request_cookies=Cookie,
            request_referer=Referer,
            request_post=post_data,
            request_host=request_host,
            User_Agent = User_Agent
        }
    else
        t = {}
    end
    --check_table(t)
    return t
end
--解码
function decode(translate,vars)
    _tmp = {}
    if translate == 'url_decode' then
        _t = var_type(vars)
        for k,v in pairs(_t)do
        translate_var = ngx.unescape_uri(v)
        _tmp[k]=string.lower( translate_var )
        
        end
        return _tmp
    else
        _t = var_type(vars)
        return _t
    end

    
end
--检测
function detect(rules)
    for _,t in pairs(rules) do
        for _,k in pairs(t.rulerset)do
            var = decode(k.translate,k.vars.type)
            pattern = k.pattern
            for vv,v in pairs(var)do
                re = ngx.re.match(v,pattern,"joi")

                if re then
                    ngx.exit(403)
                end
            end
            
        end
    end

end



--黑名单
function blackdeny(black)
    for _, w in pairs(black.rulerset) do
        var = decode(w.translate,w.vars.type)
        for k,v in pairs(var)do
            m = ngx.re.match(v,w.pattern,'joi')
            if m then
                return "true"
            end
        end
    end
end

--检测登录
function check_upload()
    ngx.log(ngx.ERR,post_data)
    regex = "Content-Disposition: form-data; name=.*filename=.*\\.(jsp|php|war|asp)"
    m = ngx.re.match(post_data,regex,'joi')
    if m then
        ngx.log(ngx.ERR,m[1])
        ngx.exit(403)
    end
end

--匹配到黑名单直接403
if blackdeny(black) == "true" then
    ngx.exit(403)
end

if ngx.re.find(Content_Type, [=[^multipart/form-data; boundary=]=]) then
    --check_upload()
    _t = "pass"
else
detect(config)
end










