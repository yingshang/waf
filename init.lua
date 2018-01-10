local cjson_safe = require "cjson.safe"
local lfs = require"lfs"  

---------------当前文件路径-------------------
local info = debug.getinfo(1, "S")
local path = info.source
local path1 = string.sub(path, 2, -1)
local path2 = string.match(path1, "^.*/")  
------------------------------------

local rules = {}
local rules_dict = ngx.shared.rules_dict
local white_dict = ngx.shared.white_dict
local black_dict = ngx.shared.black_dict
local config_dict = ngx.shared.config_dict
local logic_dict = ngx.shared.logic_dict




--检测table是不是为空
--[[
function check_table(t)
    if next(t) == nil then
        ngx.log(ngx.ERR,"table is nil")
    elses
        for k,v in pairs(t)do
            ngx.log(ngx.ERR,k.."----"..v)
        end
    end
end
--
]]


--分割字符串函数
function Split(szFullString, szSeparator)  
    local nFindStartIndex = 1  
    local nSplitIndex = 1  
    local nSplitArray = {}  
    while true do  
       local nFindLastIndex = string.find(szFullString, szSeparator, nFindStartIndex)  
       if not nFindLastIndex then  
        nSplitArray[nSplitIndex] = string.sub(szFullString, nFindStartIndex, string.len(szFullString))  
        break  
       end  
       nSplitArray[nSplitIndex] = string.sub(szFullString, nFindStartIndex, nFindLastIndex - 1)  
       nFindStartIndex = nFindLastIndex + string.len(szSeparator)  
       nSplitIndex = nSplitIndex + 1  
    end  
    return nSplitArray  
    end  


--读取基本的规则json
function ruleread() 
    local filepath = path2.."ruleset/"
    for file in lfs.dir(filepath) do    
        if file ~= "." and file ~= ".." then    
            local fname = filepath..file
            local f = io.open(fname, "r")  
            local json = f:read("*a")  
            f:close()
            local r = cjson_safe.decode(json)
            filename = Split(file,'%.')[1]

            --将白名单放进dict
            if filename == "whitelist" then
                white_dict:safe_set("whitelist",cjson_safe.encode(r),0)
            --将黑名单放进dict
            elseif filename == "blacklist" then
                black_dict:safe_set("blacklist",cjson_safe.encode(r),0)
            elseif filename == "logic" then
                logic_dict:safe_set("logic",cjson_safe.encode(r),0)
            --将规则文件放进dict
            else
                rules[filename] = r 
            end
        end    
    end
    rules_dict:safe_set("rules",cjson_safe.encode(rules),0)

end  






ruleread()
config_dict:safe_set("configlist",cjson_safe.encode(config),0)
file = io.open("/data/waf/waf.log","a+")



--regex = "\\.jpg|\\.png|\\.css|\\.js|\\.bmp"

--if ngx.re.find(Content_Type, [=[^multipart/form-data; boundary=]=],"joi") then
    --check_upload()
--    _t = "pass"
--elseif ngx.re.match(request_uri,regex,"joi")then
--    _t = "pass"
--else
--detect(rules)
--end