local http = require "http"
local shortport = require "shortport"
local string = require "string"
local stdnse = require "stdnse"
local vulns = require "vulns"
local table = require "table"

description = [[
OpenVPN Access Server CVE-2017-5868 CRLF Injection Vulnerability
]]

---
-- @usage nmap --script http-vuln-cve2017-5868 -p 80 <target>
-- @output
-- PORT   STATE SERVICE VERSION
-- 80/tcp open  http    OpenVPN AS
-- | http-vuln-cve2017-5868:
-- |   VULNERABLE:
-- |   OpenVPN Access Server CRLF Injection Vulnerability
-- |       State: VULNERABLE
-- |     IDs:  CVE:CVE-2017-5868
-- |     Risk factor: Medium
-- |       A remote user can create a specially crafted URL containing the '%0A' character that, 
-- |       when loaded by the target user prior to authentication, will inject headers and set the 
-- |       session cookie to a specified value. After the target user authenticates to the target
-- |       OpenVPN Access Server, the remote user can hijack the target user's session.
-- |
-- |     Disclosure date: 2017-05-24
-- |     Extra information:
-- |     References:
-- |       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5868
--
-- @xmloutput
-- <table key="CVE-2017-5868">
-- <elem key="title">OpenVPN Access Server CRLF Injection Vulnerability</elem>
-- <elem key="state">VULNERABLE</elem>
-- <table key="ids">
-- <elem>CVE:CVE-2017-5868</elem>
-- </table>
-- <table key="description">
-- <elem>A remote user can create a specially crafted URL containing the '%0A' character that, when loaded by the target user prior to authentication, will inject headers and set the session cookie to a specified value. After the target user authenticates to the target OpenVPN Access Server, the remote user can hijack the target user's session.</elem>
-- </table>
-- <table key="dates">
-- <table key="disclosure">
-- <elem key="day">24</elem>
-- <elem key="month">05</elem>
-- <elem key="year">2017</elem>
-- </table>
-- </table>
-- <elem key="disclosure">2017-05-24</elem>
-- <table key="check_results">
-- </table>
-- <table key="extra_info">
-- </table>
-- <table key="refs">
-- <elem>https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5868</elem>
-- </table>
-- </table>
--
---

author = "Chapman (R3naissance) Schleiss"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "intrusive"}

portrule = shortport.http

action = function(host, port)
  local vuln_table = {
    title = "OpenVPN Access Server CRLF Injection Vulnerability",
    IDS = {CVE = 'CVE-2017-5868'},
    risk_factor = "Medium",
    references = {
        'http://openvpn.net/index.php/access-server/overview.html',
    },
    dates = {
      disclosure = {year = '2017', month = '05', day = '24'},
    },
    check_results = {},
    extra_info = {}
  }

  local vuln_report = vulns.Report:new(SCRIPT_NAME, host, port)
  vuln_table.state = vulns.STATE.NOT_VULN

  local vuln_uri = '/__session_start__/%0aVulnerable:%20CVE-2017-5868'
  stdnse.debug1("Getting cookie")
  local options = {}
  options['redirect_ok'] = false
  local get_cookie = http.get(host, port, '/', options)
  stdnse.debug1("Response %s", get_cookie.status) 

  if get_cookie.status then
    stdnse.debug1("Payload: %s", vuln_uri)
    options['cookies'] = get_cookie.cookies
    options['redirect_ok'] = false
    local response = http.get(host, port, vuln_uri, options)
    stdnse.debug1("Response %s", response.status)
    
    if response['header']['vulnerable'] then
      stdnse.debug1("Vulnerability found!")
      vuln_table.state = vulns.STATE.VULN
      table.insert(vuln_table.extra_info, string.format("Arbitrary header (Vulnerable: %s) found in response", response['header']['vulnerable']))
    end
  end

  return vuln_report:make_output(vuln_table)

end
