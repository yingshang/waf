--[[
local libinject = require "resty.libinjection"
input = '-1\'union select 1,2,3,4,5,6--'
xss = '1<script>alert(0)</script>'
output = libinject.xss(input)
ngx.log(ngx.ERR,output)

--]]


local request = require "request"
local cjson_safe = require "cjson.safe"

local rules_dict = ngx.shared.rules_dict
local white_dict = ngx.shared.white_dict
local black_dict = ngx.shared.black_dict
--local config_dict = ngx.shared.config_dict

local rules = cjson_safe.decode(rules_dict:get("rules")) or {}
local white = cjson_safe.decode(white_dict:get("whitelist")) or {}
local black = cjson_safe.decode(black_dict:get("blacklist")) or {}
--local config = cjson_safe.decode(config_dict:get("configlist")) or {}



--匹配到黑名单直接403
 if request.blackdeny(black) then
    ngx.exit(403)
 end


--检测是否是静态文件
if request.check_static() then
    local _pass = 'pass'
elseif request.whiteallow(white)then
    local _pass = 'pass'

else
    --检测规则
     request.detect(rules)
end


