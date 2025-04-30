-- Version 0.1
-- Created 5 Apr 2022 - v0.1 - created by Chapman Schleiss

description = [[
Performs an ssh audit using ssh-audit
]]

author = "Chapman (R3naissance) Schleiss"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

---
-- @usage
-- nmap -p 22 <target> --script ssh-audit --script-args ssh-audit.out=<dir>
---
-- @args ssh-audit.out Directory to save output
--
-- @output
-- PORT   STATE SERVICE
-- 22/tcp open  ssh     syn-ack ttl 240 OpenSSH 7.4 (protocol 2.0)
-- | ssh-audit:
-- |   /opt/ssh-audit/ssh-audit.py -n -l warn -p 22 IP/HOST
-- |   # security
-- |   (cve) CVE-2021-41617                        -- (CVSSv2: 7.0) privilege escalation via supplemental groups
-- |   (cve) CVE-2020-15778                        -- (CVSSv2: 7.8) command injection via anomalous argument transfers
-- |   (cve) CVE-2018-15919                        -- (CVSSv2: 5.3) username enumeration via GS2
-- |   (cve) CVE-2018-15473                        -- (CVSSv2: 5.3) enumerate usernames due to timing discrepancies
-- |   (cve) CVE-2016-20012                        -- (CVSSv2: 5.3) enumerate usernames via challenge response
-- |   # key exchange algorithms
-- |   (kex) ecdh-sha2-nistp256                    -- [fail] using elliptic curves that are suspected as being backdoored by the U.S. National Security Agency

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
    title = "Insecure SSH Configuration",
    state = vulns.STATE.NOT_VULN,
    description = [[
Potential SSH issues found (CVEs/algos)
    ]]
  }
        local dir = "."

        if stdnse.get_script_args('ssh-audit.out') then
                dir = stdnse.get_script_args('ssh-audit.out')
        end

        local result = {}
        local domain = ""
        if host.targetname then
                domain = host.targetname
        else
                domain = host.ip
        end

        local filename = dir .. "/" .. domain .. "_" .. port.number .. ".txt"

        local cmd = "/opt/ssh-audit/ssh-audit.py -n -l warn -p " .. port.number .. " " .. domain
        stdnse.debug(1, "Command: %s", cmd)

        local ret = os.capture(cmd)
        if ret then
                if string.find(ret, '%pcve%p') or string.find(ret, '%pkex%p') or string.find(ret, '%pkey%p') or string.find(ret, '%pmac%p') or string.find(ret, '%prec%p') then
                        stdnse.debug(1, "SSH audit items found")
                        result[#result + 1] = cmd
                        result[#result + 1] = ret
                        vuln.state = vulns.STATE.LIKELY_VULN
                else
                        stdnse.debug(1, "SSH has a clean configuration!")
                end
        else
                result[#result + 1] = "Error: Could not run ssh-audit"
        end

        -- Return result
        return stdnse.format_output(true,  result)
end
