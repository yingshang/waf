--post的json数据递归调用
function json_parse(value)
    local _value = ""
    if type(value) == "table" then
        for _,v in pairs(value)do
            if type(v) ~= "table" then
                _value = tostring(v)..",".._value
            else
                json_parse(v)
            end
        end
        return _value
    elseif type(value) == "userdata" then
        value = ""
    elseif type(value) == "boolean" then
        value = tostring(value)
    else
        _ = "pass"
    end
    return value
end


--检测上传
function check_upload()
    local request_headers  = ngx.req.get_headers()
    local Content_Type = request_headers['Content-Type'] or ""  --识别是否upload
    local regex = "multipart/form-data"
    local m = ngx.re.match(Content_Type,regex,'joi')

    if m then
        return true
    end
end


--post方式的判断，正常和json
function post_check()
    local parms = ""
    local cjson_safe = require "cjson.safe"
    ngx.req.read_body()
    local post_args =  ngx.req.get_post_args()
    local post_data =  ngx.req.get_body_data()
    local cjon_post = cjson_safe.decode(post_data)
    if post_data == nil then
        parms = ""  
    elseif check_upload() then
        parms = ""
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
    local args = ngx.req.get_uri_args()
    local parms = ""
    for _,v in pairs(args)do
        if type(v) ~= "boolean" then
        parms = v.."-"..parms
        end
    end
    return parms
end

--获取cookie，有时候cookie的变量名会重复
function getcookie()
    local request_headers  = ngx.req.get_headers()
    local _cookie = request_headers['Cookie'] 
    local _tmp = ""
    if type(_cookie) == "table"then
        for _,v in pairs(_cookie)do
            _tmp =_tmp.."-"..v
        end
        return _tmp
    end
    return _cookie
end


--变量类型
function var_type( vars )
    local request_method  = ngx.req.get_method()
    local post_data = ""
    if request_method == 'POST' then
        post_data = post_check() or ""
    end
    local request_headers     = ngx.req.get_headers()
    local User_Agent = request_headers['User-Agent'] or ""
    local Cookie = getcookie() or ""
    local Referer  = request_headers['Referer'] or ""
    local request_host = request_headers['Host'] or ""
    local request_uri = ngx.var.request_uri      --网站url
    local remote_ip = ngx.var.remote_addr --客户端IP
    local t = ""
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
        local _tt ="pass"
    end
    return t
end

--解码
function decode(translate,vars)
    if translate == 'url_decode' then
        local _t = var_type(vars)
        local _tmp = ngx.unescape_uri(_t)
        _tmp=string.lower( _tmp )
        return _tmp
    else
        _t = var_type(vars)
        return _t
    end
end

--检测
function detect(rules)
    for _,_t in pairs(rules) do
        for _,k in pairs(_t.rulerset)do
            local values = decode(k.translate,k.vars.type)
            local m1 = ngx.re.match(values,k.pattern,"joi")
            if m1 then
                ngx.ctx.pattern = m1[0]
                ngx.ctx.datalog = true
                ngx.ctx.rule_id = k.id
                ngx.ctx.rule_msg = k.msg       
                ngx.exit(403)   
            end
        end
    end

end


--黑名单
function blackdeny(black)
    for _, w in pairs(black.rulerset) do
        local var = decode(w.translate,w.vars.type)
        local m = ngx.re.match(var,w.pattern,'joi')
        if m then     
            return true
        end
        
    end
end

--白名单
function whiteallow(white)
    for _,w in pairs(white.rulerset)do
        local var = decode(w.translate,w.vars.type)
        local m = ngx.re.match(var,w.pattern,'joi')
        if m then     
            return true
        end    
    end
end



--检测文件名是否是静态文件
function check_static()
    local request_path = ngx.var.document_uri
    local regex = "\\.css|\\.js|\\.jpg|\\.png"
    local m = ngx.re.match(request_path,regex,'joi')
    if m then
        return true
    end
end


--IP控制黑名单,10秒内打出1000的访问量就封IP
function ip_control()
    local remote_ip = ngx.var.remote_addr --客户端IP
    local calc_dict = ngx.shared.calc_dict
    local get_ip = calc_dict:get(remote_ip)
    if get_ip == nil then
        calc_dict:safe_set(remote_ip,1,10)
    else
        calc_dict:incr(remote_ip,1)
        --ngx.log(ngx.ERR,calc_dict:get(remote_ip))
        local count = calc_dict:get(remote_ip)
        if  count > 1000 then
            ngx.exit(403)
        end
    end
end


local request={}
request.blackdeny =blackdeny
request.whiteallow = whiteallow
request.detect = detect
request.check_static = check_static
request.ip_control = ip_control
return request