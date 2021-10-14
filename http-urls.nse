description = [[
This script will return a list of valid urls and optionally save to file for use later.
]]

local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"

---
-- @usage
-- nmap -p <port> --script http-urls <target>
--
-- @output
-- PORT    STATE SERVICE
-- 80/tcp  open  http
-- | http-urls: 
-- |_  http://www.google.com
-- 443/tcp open  https
-- | http-urls: 
-- |_  https://www.google.com
--
-- @usage
-- nmap -p 80,443 --script http-urls -iL subdomains.txt --open --script-args=http-urls.out=urls.txt
-- 
-- @output
-- PORT    STATE SERVICE
-- 80/tcp  open  http
-- | http-urls: 
-- |   Saved url to opt/urls.txt
-- |_  http://www.google.com
-- 443/tcp open  https
-- | http-urls: 
-- |   Saved url to opt/urls.txt
-- |_  https://www.google.com
--
-- @args http-urls.out Where to save the results

author = "Chapman (R3naissance) Schleiss"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = { "discovery" }

-- aquatone xlarge ports
portrule = shortport.port_or_service( {80, 81, 300, 443, 591, 593, 832, 981, 1010, 1311, 2082, 2087, 2095, 2096, 2480, 3000, 3128, 3333, 4243, 4567, 4711, 4712, 4993, 5000, 5104, 5108, 5800, 6543, 7000, 7396, 7474, 8000, 8001, 8008, 8014, 8042, 8069, 8080, 8081, 8088, 8090, 8091, 8118, 8123, 8172, 8222, 8243, 8280, 8281, 8333, 8443, 8500, 8834, 8880, 8888, 8983, 9000, 9043, 9060, 9080, 9090, 9091, 9200, 9443, 9800, 9981, 12443, 16080, 18091, 18092, 20720, 28017}, {"http", "https"}, "tcp", "open")

local function try_url (url)
	stdnse.debug(0, "Attempting: %s", url)
        local response = http.get_url(url .. "/")
        stdnse.debug(0, "%s [%s]", url, response.status)
	return response
end

local function write_log (filename, url)
        file = io.open(filename, "a")
        io.output(file)
        io.write(url .. "\n")
        io.close(file)
	stdnse.debug(0, "Saved %s to %s", url, filename)
end

-- Business end of script
action = function(host, port)

	local result = {}
	local filename = stdnse.get_script_args('http-urls.out')
	local domain = ""
        if host.targetname then
                domain = host.targetname
        else
                domain = host.ip
        end

	local response = try_url("http://" .. domain .. ":" .. port.number)
	if response and response.status then
		result[#result + 1] = "http://" .. domain .. ":" .. port.number
		if filename then
			write_log(filename, "http://" .. domain .. ":" .. port.number)
		end
		return stdnse.format_output(true,  result)
	end

        response = try_url("https://" .. domain .. ":" .. port.number)
        if response and response.status then
                result[#result + 1] = "https://" .. domain .. ":" .. port.number
                if filename then
                        write_log(filename, "https://" .. domain .. ":" .. port.number)
                end
		return stdnse.format_output(true,  result)
        end
end
