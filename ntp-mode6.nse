-- Version 0.1
-- Created 3 Jan 2024 - v0.1 - created by Chapman Schleiss

description = [[
Performs ntpq (required in path)
]]

author = "Chapman (R3naissance) Schleiss"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"discovery", "safe"}

-- Required stuff
local shortport = require "shortport"
local stdnse = require "stdnse"
portrule = shortport.port_or_service(123, "ntp", {"udp", "tcp"}, "open")

-- Capture function
function os.capture(cmd, raw)
  local f = assert(io.popen(cmd, 'r'))
  local s = assert(f:read('*a'))
  f:close()
  if raw then return s end
  s = string.gsub(s, '^%s+', '')
  s = string.gsub(s, '%s+$', '')
  --s = string.gsub(s, '[\n\r]+', ' ')
  return s
end

-- Business end of script
action = function(host, port)
        local result = {}
        local domain = ""
        if host.targetname then
                domain = host.targetname
        else
                domain = host.ip
        end
        
        local cmd = "ntpq -c rv " .. domain
        stdnse.debug(1, "Command: %s", cmd)

        local ret = os.capture(cmd)
        if ret then
                if (ret == nil) then
                        stdnse.debug(1, "Timeout on %s", domain)
                else
                        result[#result + 1] = cmd
                        result[#result + 1] = ret
                end
        else
                result[#result + 1] = "Error: Could not run ntpq"
        end

        -- Return result
        return stdnse.format_output(true,  result)
end
