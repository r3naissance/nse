-- Version 0.1
-- Created 15 Feb 2016 - v0.1 - created by Chapman Schleiss

description = [[
Attempts to enumerate null sessions using enum4linux (required)
]]

author = "Chapman (R3naissance) Schleiss"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

---
-- @usage
-- nmap -p 389 <target> --script null-sessions --script-args null-sessions.separate=true
---
-- @args null-sessions.separate Separate output for each host
-- instead of appending one file
--
-- @output
-- PORT   STATE SERVICE
-- 389/tcp open  ldap
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
portrule = shortport.port_or_service(389, {"open", "open|filtered"})

-- Business end of script
action = function(host, port)
	-- We will be appending all enumerated data to the same file, you can sort/uniq it later
	local filename = "null-session-enumeration.txt"

	-- Or if you opted to separate each host
	local separate = stdnse.get_script_args('null-sessions.separate')
  	if separate then
    		filename = "null-session-enumeration_" .. host.ip .. ".txt"
  	end
	
	local result = {}
	local start_time = nmap.clock_ms()

	-- Run - `enum4linx <ip> >> filename.txt` and ignore program errors, we'll do this later
	local cmd = "enum4linux -U -M -S -P -G -d" .. host.ip .. " >> " .. filename .. " 2> /dev/null"
	
	local ret = os.execute(cmd)

	local end_time = (nmap.clock_ms() - start_time) / 1000
	
	-- Check runtime, if less than 1 second, it's likely that null session enumeration is not allowed
	if ret then
		if end_time < 1 then
			result[#result + 1] = "Runtime: " .. end_time .. "s - ACCESS DENIED (Likely)"
			result[#result + 1] = "Enumeration can be found in " .. filename
		else
			result[#result + 1] = "Runtime: " .. end_time .. "s - ACCESS ALLOWED (Likely)"
			result[#result + 1] = "Enumeration can be found in " .. filename
		end
	else
		result[#result + 1] = "Error: Run the following command and debug"
		result[#result + 1] = "enum4linux " .. host.ip	
	end

	-- Return result
	return stdnse.format_output(true,  result)
end
