-- Version 0.1
-- Created 4 Jan 2022 - v0.1 - created by Chapman Schleiss

description = [[
Performs sslscan (required in path)
]]

author = "Chapman (R3naissance) Schleiss"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

---
-- @usage
-- nmap -p 443 <target> --script sslscan --script-args sslscan.out=<dir>
---
-- @args sslscan.out Directory to save output
--
-- @output
-- PORT   STATE SERVICE
-- 443/tcp open  https
-- |   Runtime: 0.598s - ACCESS DENIED (Likely)
-- |_  Enumeration can be found in null-session-enumeration.txt
-- @output
-- PORT   STATE SERVICE
-- 389/tcp open  ldap
-- |   Runtime: 59.003s - ACCESS ALLOWED (Likely)
-- |_  Enumeration can be found in null-session-enumeration_192.168.1.1.txt

categories = {"discovery", "safe"}

-- Required stuff
local shortport = require "shortport"
local stdnse = require "stdnse"
portrule = shortport.ssl

-- Business end of script
action = function(host, port)
        local dir = "."

        if stdnse.get_script_args('sslscan.out') then
                dir = stdnse.get_script_args('sslscan.out')
        end

        local result = {}
        local domain = ""
        if host.targetname then
                domain = host.targetname
        else
                domain = host.ip
        end

        local filename = dir .. "/" .. domain .. "_" .. port.number .. ".xml"

        local cmd = "sslscan --xml=" .. filename .. " --connect-timeout=5 " .. domain .. ":" .. port.number .. " > /dev/null"
        stdnse.debug(1, "Command: %s", cmd)

        local ret = os.execute(cmd)
        if ret then
                result[#result + 1] = "sslscan output saved to: " .. filename
        else
                result[#result + 1] = "Error: Could not run sslscan"
        end

        -- Return result
        return stdnse.format_output(true,  result)
end
