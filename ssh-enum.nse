-- Version 0.1
-- Created 5 Apr 2022 - v0.1 - created by Chapman Schleiss

description = [[
Performs ssh-enum (required in path)
]]

author = "Chapman (R3naissance) Schleiss"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

---
-- @usage
-- nmap -p 443 <target> --script ssh-enum --script-args ssh-enum.out=<dir>
---
-- @args ssh-enum.out Directory to save output
--
-- @output
-- PORT   STATE SERVICE
-- 22/tcp open  ssh
-- |_  Enumeration can be found in file.txt

categories = {"discovery", "safe"}

-- Required stuff
local shortport = require "shortport"
local stdnse = require "stdnse"
local vulns = require "vulns"
portrule = shortport.port_or_service( {22}, {"ssh"}, "tcp", "open")

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
  local vuln = {
    title = "OpenSSH through 7.7 User Enumeration",
    state = vulns.STATE.NOT_VULN,
    description = [[
OpenSSH through 7.7 is prone to a user enumeration vulnerability due to not delaying bailout for an invalid
authenticating user until after the packet containing the request has been fully parsed, related to auth2-gss.c,
auth2-hostbased.c, and auth2-pubkey.c.
    ]],
    IDS = {
        CVE = "CVE-2018-15473"
    },
    references = {
        'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-15473',
        'https://github.com/Sait-Nuri/CVE-2018-15473'
    },
    dates = {
        disclosure = { year = '2018', month = '08', day = '17' }
    }
  }
        local dir = "."
        local wordlist = "/opt/SecLists/Usernames/cirt-default-usernames.txt"

        if stdnse.get_script_args('ssh-enum.out') then
                dir = stdnse.get_script_args('ssh-enum.out')
        end

        if stdnse.get_script_args('ssh-enum.wordlist') then
                wordlist = stdnse.get_script_args('ssh-enum.wordlist')
        end

        local result = {}
        local domain = ""
        if host.targetname then
                domain = host.targetname
        else
                domain = host.ip
        end

        local filename = dir .. "/" .. domain .. "_" .. port.number .. ".txt"

        local cmd = "/opt/eatt/CVE-2018-15473/CVE-2018-15473.py -u notapossibleusername -p " .. port.number .. " " .. domain
        stdnse.debug(1, "Command: %s", cmd)

        local ret = os.capture(cmd)
        if ret then
                if string.find(ret, "is an invalid username") then
                        stdnse.debug(1, "Potential ssh-enum found. Running %s list", wordlist)
                        local cmd = "/opt/eatt/CVE-2018-15473/CVE-2018-15473.py -w " .. wordlist .. " -p " .. port.number .. " " .. domain
                        ret = os.capture(cmd)
                        if string.find(ret, "No valid user detected") then
                                stdnse.debug(1, "False Positive")
                        else
                                result[#result + 1] = cmd
                                result[#result + 1] = ret
                                vuln.state = vulns.STATE.LIKELY_VULN
                        end
                end
        else
                result[#result + 1] = "Error: Could not run ssh-enum"
        end

        -- Return result
        return stdnse.format_output(true,  result)
end
