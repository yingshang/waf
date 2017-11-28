
local cjson_safe = require "cjson.safe"
local request_headers     = ngx.req.get_headers()
local request_method      = ngx.req.get_method()
local args = ngx.req.get_uri_args()
local User_Agent = request_headers['User-Agent'] or ""
local Cookie = request_headers['Cookie'] or ""
local Referer  = request_headers['Referer'] or ""
local request_host = request_headers['Host'] or ""
local request_uri = ngx.var.request_uri      --网站url
local remote_ip = ngx.var.remote_addr --客户端IP
local Content_Type = request_headers['Content-Type'] or ""  --识别是否upload



local time = ngx.time()
local ngx_ctx = ngx.ctx


--post的json数据递归调用
function json_parse(value)
    _value = ""
    if type(value) == "table" then
        for _,v in pairs(value)do
            if type(v) ~= "table" then
                _value = tostring(v)..",".._value
            else
                json_parse(v)
            end
        end
        return _value
        
    end
return value
end

--post方式的判断，正常和json
function post_check()
    local parms = ""
    ngx.req.read_body()
    local post_args =  ngx.req.get_post_args()
    local post_data =  ngx.req.get_body_data()
    local cjon_post = cjson_safe.decode(post_data)
    if post_data == nil then
        _t = 'pass'
    else
        if cjon_post == nil then
            for _,v in pairs(post_args)do
                parms = v.."-"..parms
            end
        else
            for _,v in pairs(cjon_post)do
                 parms = json_parse(v).."-"..parms
            end
        end
    
    return parms
end
        
end

--获取GET数据
function get_data()
    local parms = ""
    args = ngx.req.get_uri_args() 
    for _,v in pairs(args)do
        parms = v.."-"..parms
    end
    return parms
end

function post_data()
    local post_parms = ""
    post_parms = post_check()

    return post_parms
end


local post_data =  post_data() or ""


--变量类型
function var_type( vars )
    if vars == 'request_uri'then
        t=request_uri
    elseif vars == 'request_cookies' then
        t=Cookie
    elseif vars == 'request_referer' then
        t=Referer
    elseif vars == 'request_post' then
         t=post_data
    elseif vars == 'request_host' then
         t=request_host
    elseif vars == 'User_Agent'then
         t=User_Agent
    elseif vars == 'remote_ip' then
         t=remote_ip
    elseif vars == 'args' then
        t = get_data()..'-'..post_data..'-'..User_Agent..'-'..request_host..'-'..Referer..'-'..Cookie
    else
        t = ""
    end
    return t
end

--解码
function decode(translate,vars)
    if translate == 'url_decode' then
        _t = var_type(vars)
        _tmp = ngx.unescape_uri(_t)
        _tmp=string.lower( _tmp )
        
        
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
            value = decode(k.translate,k.vars.type)
            pattern = k.pattern
            rule_id = k.id
            rule_msg = k.msg
                m = ngx.re.match(value,pattern,"joi")
                if m then
                    ngx_ctx.pattern = m[0]
                   ngx_ctx.datalog = "on"
                    ngx_ctx.rule_id = rule_id
                    ngx_ctx.rule_msg = rule_msg       
                    ngx.exit(403)
                
            end
            
        end
    end

end


--黑名单
function blackdeny(black)
    for _, w in pairs(black.rulerset) do
        var = decode(w.translate,w.vars.type)
        m = ngx.re.match(var,w.pattern,'joi')
        if m then     
            return true
        end
        
    end
end

--白名单
function whiteallow(white)
    for _,w in pairs(white.rulerset)do
        var = decode(w.translate,w.vars.type)
        m = ngx.re.match(var,w.pattern,'joi')
        if m then     
            return true
        end    
    end
end


--检测上传
function check_upload()
    ngx.log(ngx.ERR,post_data)
    regex = "Content-Disposition: form-data; name=.*filename=.*\\.(jsp|php|war|asp)"
    m = ngx.re.match(post_data,regex,'joi')
    if m then
        ngx.exit(403)
    end
end
--检测文件名是否是静态文件
function check_static()
    local request_path = ngx.var.document_uri
    regex = "\\.css|\\.js|\\.jpg|\\.png"
    m = ngx.re.match(request_path,regex,'joi')
    if m then
        return true
    end
    
end





local request={}

request.blackdeny =blackdeny
request.whiteallow = whiteallow
request.detect = detect
request.check_static = check_static
return request