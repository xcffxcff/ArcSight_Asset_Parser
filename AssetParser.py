import os, re, string, _winreg,argparse
from xlrd import *
from itertools import *
import dns.resolver, dns.reversename
from dns.resolver import NXDOMAIN
from dns.exception import DNSException, Timeout

__progname__ = "ArcSight Asset Parser"
__version__ = "0.8.3"
__author__ = "Robert McGinley"
__description__ = "Parses Excel and CSV files for information to build a valid ArcSight ESM asset import CSV file."

"""------------------------------------------------"""
"""      Description                               """
"""------------------------------------------------"""
"""
ArcSight Asset Parser version 0.8.3
Written by Robert McGinley, ArcSight Professional Services - August 2011
Send bugs, suggestions, compliments, constructive criticism, awards, kudos and oversized novelty checks to robert.mcginley@hp.com
Send flames, complaints, unconstructive criticism, reprimands and bad vibes to /dev/null :)

This script accepts an input file (Only supports Microsoft Excel currently. CSV is planned for the very near future) and scans through each sheet, row and cell in a attempt to retrieve the following values representing the properties of an ArcSight Asset: IP Address, Hostname, Static Address/DHCP, Asset Categories.
This is done by comparing each cell in a given row, in a given sheet against a list of regular expressions which are intended to match on specific values.
Currently this is done in a static, brute-force way with no modularity concerning the mappings between a regular expression and (For example) an ArcSight asset category. The mapping is done manually and with the massive amount of categories ArcSight uses at any given time, for any given asset this is not scalable or maintainable in any sane fashion.
The script outputs to either a CSV formatted file or to stdout in the following format:
    IP Address (string), Hostname (string), MAC Address (string), Static/DHCP Addressing (Boolean),

Changelog
    * v0.8 - Initial version. Still "beta", but most functions should work correctly. See the Todo below for planned features. The version will increment in 1/10th steps until 1.0 at which the script should be completely stable for most uses.
    * v0.8.1 - BUGS: Bug 001 - Fixed a concatenation issue when parsing a successful DNS resolution result, FEATURES: added feature to either remove or preserve the domain portion of a DNS lookup (If one exists), DOC: added more documentation and code comments
    * v0.8.2 - Added support for specifying which nameservers are used in the attempt to identify hostnames from parsed IP addresses. Additionally, if there are hostnames returned from multiple domains for one IP, you may specify which domain suffix is preferred.
    * v0.8.3 - Fixed a bug (BUG 002) in the DNS lookup function concerning the "preferred domain suffix" option

Todo (In no particular order):
    * Add support for command line arguments
    * Expand the selection of asset categories that we look for. Currently we only look for PCI and SOX compliance. I believe this needs to be rewritten to accommodate any more categories (I just have to figure out how) :)
    * Support the parsing of CSV files
    * Fix some current regular expressions. For example, the hostname regex is tailored specifically to find hostnames on a particular client's network. Since their naming scheme is erratic, the regex quickly grew more complex and unmanagable than I would have liked. This is why we also attempt a DNS lookup on each IP (Configurable)
    * Take advantage of the python threading modules for the DNS lookup function, which takes up 99% of the execution time of this script, to run multiple DNS lookups in parallel (Currently not available due to the structure of the parsing loop. (Perhaps passing an object or pointer will work?))
    * Attempt to identify if the asset truly has a static address or if it is assigned via DHCP (This should be VERY rare in a server/non-user environment). Currently this value is statically assigned to all assets as True.
    * Put a copy of the above documentation into a readme file


"""

# TODO: Use getopts/argparse module to retrieve each of these variables from the command line instead of statically defining them here.
# Working on it :)
#argParser.add_argument('','')
argParser = argparse.ArgumentParser(prog=__progname__,description=__description__,epilog="",add_help=True)
argParser.add_argument('inputfile',type=str,default=None,help="Input file to parse")
argParser.add_argument('outputfile',type=str,default=None,help="Output CSV file")
argParser.add_argument('-d','--dns-lookup',action='store_true',help="If a discovered IP address does not have an associated hostname, attempt a DNS lookup on the IP to identify the proper hostname (Useful if program is run on the associated internal network) - DEFAULT: False")
argParser.add_argument('-s','--strip-domain',action='store_true',help="When a hostname is discovered via DNS lookup, remove the domain name suffix from the discovered value - DEFAULT: False")
argParser.add_argument('-p','--preferdomain',type=str,help="If there are multiple hostname results found on differing domains, prefer results from the specified domain")
argParser.add_argument('-n','--nameservers', action='append',type=list,nargs="+",help="DNS nameservers to query (If not specified, system nameservers will be used)")
argParser.add_argument('-D','--debug',action='store_true',help="Enable debugging messages (Noisy but informative)")
argParser.add_argument('-v','--version', action='version', version='%(prog)s __version__',help="Display this programs version")
#argParser.parse_args()

# Set script specific variables here.
# Input file to parse
inputFileName = ".\Event_Source_Asset_Model_-_FROZEN_July_4 - Script Testing.xls"

# Output file to write results to (CSV only)
outputFile = "C:\ParsedAssetList.csv"

# If we don't find a hostname associated with an IP address in the row, try querying DNS for one.
dnsTryLookup = True

# Strip the domain component from any resolved hostname so that "workstation.arcsight.com" becomes "workstation". if no domain is contained in the string, nothing is changed.
dnsStripFqdn = False

# If the resolution of an IP address returns multiple domain suffixes, prefer the domain specified in preferDnsDomain
dnsPreferDomain = "gridmark.pvt"

# DNS Nameservers. If this is None or empty, the client system's default nameservers will be used. Must be a list (or None).
# nsNameServers = ['8.8.8.8']
dnsNameServers = None

# Turn on debugging messages
debug = True

"""------------------------------------------------"""
"""       Function Definitions                     """
"""------------------------------------------------"""

# Functions to make our output consistently pretty :)
def printInfo(info, noNewLine=False):
    prefix = "[*] "

    if noNewLine is False:
        print(prefix + info)
    else:
        print(prefix + info),


def printError(error, noNewLine=False):
    prefix = "[!] "

    if noNewLine is False:
        print(prefix + "Error: " + error)
    else:
        print(prefix + "Error: " + error)

# Shamelessly taken from pydns-2.3.5:Base.py and modified for use in this script.
def parseResolvConf(resolv_path="/etc/resolv.conf"):
    # Parse the /etc/resolv.conf file on UNIX\Linux and return the default name servers
    result = None
    lines = open(resolv_path).readlines()
    for line in lines:
        line = string.strip(line)
        if not line or line[0] == ';' or line[0] == '#':
            continue
        fields = string.split(line)
        if len(fields) < 2:
            continue
        elif fields[0] == 'domain' and len(fields) > 1:
            result['domain'] = fields[1]
        elif fields[0] == 'search':
            pass
        elif fields[0] == 'options':
            pass
        elif fields[0] == 'sortlist':
            pass
        elif fields[0] == 'nameserver':
            result['server'].append(fields[1])
    return result

# Taken from pydns-2.3.5:win32dns.py and modified for this purpose
def win32Nameservers():
    nameservers = []
    x = _winreg.ConnectRegistry(None, _winreg.HKEY_LOCAL_MACHINE)
    try:
        y = _winreg.OpenKey(x,
                            r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters")
    except EnvironmentError: # so it isn't NT/2000/XP
        # windows ME, perhaps?
        try: # for Windows ME
            y = _winreg.OpenKey(x,
                                r"SYSTEM\CurrentControlSet\Services\VxD\MSTCP")
            nameserver, dummytype = _winreg.QueryValueEx(y, 'NameServer')
            if nameserver and not (nameserver in nameservers):
                nameservers.extend(map(str, re.split("[ ,]", nameserver)))
        except EnvironmentError:
            pass
        return nameservers # no idea
    try:
        nameserver = _winreg.QueryValueEx(y, "DhcpNameServer")[0].split()
    except:
        nameserver = _winreg.QueryValueEx(y, "NameServer")[0].split()
    if nameserver:
        nameservers = nameserver
    nameserver = _winreg.QueryValueEx(y, "NameServer")[0]
    _winreg.CloseKey(y)
    try: # for win2000
        y = _winreg.OpenKey(x,
                            r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\DNSRegisteredAdapters")
        for i in range(1000):
            try:
                n = _winreg.EnumKey(y, i)
                z = _winreg.OpenKey(y, n)
                dnscount, dnscounttype = _winreg.QueryValueEx(z,
                                                              'DNSServerAddressCount')
                dnsvalues, dnsvaluestype = _winreg.QueryValueEx(z,
                                                                'DNSServerAddresses')
                nameservers.extend(binipdisplay(dnsvalues))
                _winreg.CloseKey(z)
            except EnvironmentError:
                break
        _winreg.CloseKey(y)
    except EnvironmentError:
        pass
        #
    try: # for whistler
        y = _winreg.OpenKey(x,
                            r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces")
        for i in range(1000):
            try:
                n = _winreg.EnumKey(y, i)
                z = _winreg.OpenKey(y, n)
                try:
                    nameserver, dummytype = _winreg.QueryValueEx(z, 'NameServer')
                    if nameserver and not (nameserver in nameservers):
                        nameservers.extend(stringdisplay(nameserver))
                except EnvironmentError:
                    pass
                _winreg.CloseKey(z)
            except EnvironmentError:
                break
        _winreg.CloseKey(y)
    except EnvironmentError:
        #print "Key Interfaces not found, just do nothing"
        pass
        #
    _winreg.CloseKey(x)
    return nameservers


def IPToHost (ipAddr, dnsNameServers=None):
    """
        Performs DNS lookups via dnspython which will accept custom nameserver arguments
    """
    dnsHostName = None
    if debug is True:
        printInfo("Debug: Hostname for " + str(ipAddr) + " not found. Attempting DNS lookup.")
        # If no nameservers were provided, find the system's nameservers and use them (Functions taken from pydns)
    if dnsNameServers is False or dnsNameServers == "" or dnsNameServers == {} or dnsNameServers is None:
        # If the OS is win32, retrieve the hosts nameservers from win32Nameservers(). If not, try to detect the contents of /etc/resolv.conf on unix-like machines
        if sys.platform in ('win32', 'nt'):
            dnsNameServers = win32Nameservers()
        else:
            dnsNameServers = parseResolvConf()

    # Query DNS for the hostname of our IP using the dnspython resolver
    try:
        # Initialize the resolver
        dnsResolver = dns.resolver.Resolver()
        # Set our preferred nameservers or system nameservers if none were specified
        dnsResolver.nameservers = dnsNameServers
        # Start the reverse lookup
        addr = dns.reversename.from_address(ipAddr)
        # Query the nameservers
        dnsAnswer = dnsResolver.query(addr, "PTR")

        # Find the first answer that matches our preferred domain suffix, assign it to our result and quit the loop
        for answer in dnsAnswer:
            findDomainSuffix = string.find(str(answer), dnsPreferDomain)
            if findDomainSuffix != -1:
                if debug is True:
                    printInfo(
                        "Debug: Found hostname with our preferred domain suffix (" + dnsPreferDomain + "). Hostname: " + string.rstrip(
                            str(answer)), ".")
                dnsHostName = string.rstrip(str(answer), ".")
                break
            # If there's still no match after looping through all of our results, set our result to the first answer given.
        if dnsHostName is None:
            dnsHostName = dnsAnswer[0]
            # If configured to do so, strip the domain suffix from the result
        if dnsStripFqdn is True:
            dnsHostNameTuple = str.partition(dnsHostName, '.')
            dnsHostName = dnsHostNameTuple[0]
        if debug is True:
            printInfo("Debug: DNS host name found: " + str(dnsHostName))
        return dnsHostName
    except Timeout:
        if debug is True:
            printError("Debug: Query to DNS servers: " + string.join(dnsNameServers) + " has timed out.")
        return None
    except NXDOMAIN:
        if debug is True:
            printError("Debug: Name lookup of " + ipAddr + " failed. Nameserver had no answer to this query.")
        return None
    except DNSException, e:
        if debug is True:
            printError(
                "Debug: Unexpected error occurred while querying DNS servers: " + string.join(
                    dnsNameServers) + ". " + str(e))
        return None


def returnUniqueIterable (iterable):
    countMap = {}
    for v in iterable.itervalues():
        countMap[v] = countMap.get(v, 0) + 1
    uni = [k for k, v in iterable.iteritems() if countMap[v] == 1]
    return uni


def unique_everseen(iterable, key=None):
    seen = set()
    seen_add = seen.add
    if key is None:
        for element in ifilterfalse(seen.__contains__, iterable):
            seen_add(element)
            yield element
    else:
        for element in iterable:
            k = key(element)
            if k not in seen:
                seen_add(k)
                yield element

"""------------------------------------------------"""
"""       ArcSight Categories Definitions          """
"""------------------------------------------------"""

# TODO: Make this less kludgy
# TODO: Insert more categories and corresponding regular expressions to identify said categories (Member server, network device, Location, etc)
#Complaince = ['SOX', 'PCI']
PCICategories = [
    '/All Asset Categories/Site Asset Categories/Business Impact Analysis/Data Role/Reporting Requirement/PCI',
    '/All Asset Categories/Site Asset Categories/Compliance/Compliance Requirement/PCI',
    '/All Asset Categories/ArcSight Solutions/Compliance Insight Package/Regulation/PCI']
SOXCategories = [
    '/All Asset Categories/Site Asset Categories/Business Impact Analysis/Data Role/Reporting Requirement/Sarbanes-Oxley'
    ,
    '/All Asset Categories/Site Asset Categories/Compliance/Compliance Requirement/Sarbanes-Oxley',
    '/All Asset Categories/ArcSight Solutions/Compliance Insight Package/Regulation/Sarbanes-Oxley']

Networks = ['Markham', 'Carefactor', 'Retail']
NetworksCategoriesMarkham = ['/All Networks/Suncor/HP Markham']
NetworksCategoriesCareFactor = ['/All Networks/Suncor/GCA Prime']

Locations = ['Calgary', 'Toronto']
LocationsCategoriesCalgary = ['/All Locations/Suncor/Calgary']
LocationsCategoriesToronto = ['/All Locations/Suncor/Toronto']
LocationsCategoriesRetail = ['/All Locations/Suncor/Retail']

"""------------------------------------------------"""
"""       Regular Expressions                      """
"""------------------------------------------------"""

# Compile the regular expressions we will be using as we'll be using them many times. This saves some work on the part of the regex.match/search method
# Match IPv4 addresses. Capture each number into a group (4 groups)
ipAddrRegex = re.compile(
    r"(\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\b)",
    re.IGNORECASE)

# Please forgive me for this. They know not what they have kludged. I can only make this not suck so much.
hostNameRegex = re.compile(
    r"((^[a-z0-9]{2,7}\.pcacorp\.net$)|(^[a-z0-9]{2,7}\.network\.local$)|(^[a-zA-Z]{2,5}(prd|dev|tst)(tor|cgy|ret|mkm|cft)[0-9]{3}$)|(^(Mark|Clgy|CAL).*)|(^[a-zA-Z]{2,3}prod[0-9]{1,3})|(([a-z]{2,4})?[0-9]{4})$|(^(rsrtl|Prism-|sun|ppts|ora)prd.*$)|(^sunor.*)|(^db.*(ent|infra)p.*[0-9]{2,4})|(^v[a-zA-Z]{3}(pm|qm|pa)[0-9]{2})|(sap(app|biaq)[0-9]{2}$)|(hrms[0-9])|(^bnk-.*-.*$)|^(lynx|mondavi|osgsunow|Cvrl)|^([0-9]{4}-[a-z]*))"
    , re.IGNORECASE)

# MAC Address matching
macAddrRegex = re.compile(
    r"^[A-F0-9]{2}(:|-|\|)[A-F0-9]{2}(:|-|\|)[A-F0-9]{2}(:|-|\|)[A-F0-9]{2}(:|-|\|)[A-F0-9]{2}(:|-|\|)[A-F0-9]{2}$",
    re.IGNORECASE)

# Try to match any cells that identify this asset as having a SOX compliance requirement
soxRegex = re.compile(r".*(SOX|Sarbanes\-Oxley).*", re.IGNORECASE)
# Try to match any cells that identify this asset as having a PCI compliance requirement
pciRegex = re.compile(r".*(PCI|Payment Card Industry).*", re.IGNORECASE)

# Try to identify if there's a specific Network or Datacenter location (Mapped to Network asset category)
#networksRegex = []

# Try to identify if there's a specific geographic location (Mapped to Location asset category)
#locationRegex = re.compile('')

osRegex = re.compile(
    r"(Windows.(Server|Server.R2|Workstation)?.?(95|98|ME|XP|2000|2k|2003|2k3|2008|2k8|7).?(Workstation|Professional|Server|Tablet|Home|Home.Premium|Enterprise|Business|Ultimate)?(R2)?$)|((Redhat|Oracle|SuSE|Gentoo|Mandriva)?(Linux))|(AIX|HP-?UX|.*BSD|Solaris|OEL|SuSE|RHEL|Tru64)$"
    , re.IGNORECASE)

"""------------------------------------------------"""
"""       Script Code                              """
"""------------------------------------------------"""

# TODO: Check CSV CR/LF Format (DOS,Mac,Unix)

# Prompt user for filename
# TODO: Functionalize this code in order to allow the following "file check" statement to prompt the user again (If Failed) instead of quitting the script
if inputFileName == "":
    # Note: Determination of file format is based on file extension NOT file contents
    printInfo('Please specify file containing asset information (Excel\CSV):', True)
    inputFileName = raw_input()
else:
    if debug is True:
        printInfo("Debug: Using input file name defined in script, " + inputFileName)

# Check if the file exists, if not quit. Possible race condition exists here: http://stackoverflow.com/questions/82831/how-do-i-check-if-a-file-exists-using-python#answer-85237
if not os.path.isfile(inputFileName):
    printError("Specified input file, " + inputFileName + " does not exist or is not readable.")
    quit()
# TODO: Check file format CSV or Excel
if re.search(r".*\.csv$", inputFileName):
    if debug is True:
        printInfo('Debug: Found CSV file format: ' + inputFileName)
    fileFormat = 'csv'
elif re.search(r".*\.xls$", inputFileName):
    if debug is True:
        printInfo('Debug: Found (old) excel file format: ' + inputFileName)
    fileFormat = 'xls'
elif re.search(r".*\.xlsx$", inputFileName):
    if debug is True:
        printInfo('Debug: Found (new) Excel file format: ' + inputFileName)
    fileFormat = 'xlsx'
else:
    fileFormat = ''
    printError(
        'Could not determine file format based on file extension.\n\tPlease ensure your filename ends with one of the supported file extensions; .csv .xls .xlsx that properly identifies the data format contained within.\n\tProgram cannot continue.')
    quit()

# TODO: Read in the file, based on its format
if debug is True:
    printInfo("Debug: Opening file " + inputFileName)
if fileFormat == "csv":
#TODO: Read in a CSV file
    inputFileData = file(inputFileName, 'rb')
    printError("CSV file input support does not exist yet. Please provide a proper Microsoft Excel file.")
    quit(-2)

elif fileFormat == "xls" or fileFormat == "xlsx":
    # Open the given filename and begin parsing the spreadsheet
    inputWorkbook = open_workbook(inputFileName)
    # We need to pre-define a dictionary and some lists to hold our data.
    assetDict = {}
    ipList = []
    hostList = []
    pciList = []
    soxList = []
    dupeIP = 0
    # TODO: Search for Host properties (Per cell)
    # Iterate through each sheet in the workbook (File)
    for sheet in inputWorkbook.sheets():
        if debug is True:
            printInfo("Debug: Parsing workbook sheet: " + str(sheet.name))
            # Iterate though each row in the current sheet
        for  row in range(sheet.nrows):
            rowVals = str(sheet.row_values(row))
            # Start sucking down values matched by our regular expressions. Various methods from re are used according to our needs on a per-item level
            # Try to find an IP address
            ipResult = ipAddrRegex.search(rowVals)
            # If we did not find an IP address, skip this iteration as the IP address is a required field for our output.
            if ipResult is None:
                continue
            else:
                ipResultStr = ipResult.group()

            # Try to find a hostname (Will most likely fail due to inconsistent naming schemes and poor regular expressions used)
            hostResult = hostNameRegex.search(rowVals)
            if hostResult is not None:
                hostResult = str(hostResult.group(1))
            else:
                # If we did not find a hostname, attempt to query DNS for one.
                if dnsTryLookup is True:
                    hostResult = IPToHost(ipResultStr, dnsNameServers)
            if pciRegex.match(rowVals) is not None:
                pciResult = True
            else:
                pciResult = False
            if soxRegex.match(rowVals) is not None:
                soxResult = True
            else:
                soxResult = False

            # Append the list for each item as appropriate with our results from the regex searches
            ipList.append(ipResult.group(0))
            hostList.append(hostResult)
            soxList.append(soxResult)
            pciList.append(pciResult)

            # "Zip" each list together so that there are second tier lists with each IP addresses properties within a dictionary.
            assetSet = zip(ipList, hostList, soxList, pciList)

# Sort the values in the set and remove any duplicate entries
assetSet = sorted(unique_everseen(assetSet))

# Convert our lists of categories into a comma separated string
# TODO: This can probably be placed elsewhere or functionalized for better optimization.
soxValuesStr = str()
for value in SOXCategories:
    soxValuesStr += value + ","

pciValuesStr = str()
for value in PCICategories:
    pciValuesStr += value + ","

# Open our output file for writing. If we weren't given one, write to stdout and notify the user
if outputFile is not None and outputFile != "":
    try:
        writeFile = open(outputFile, "wb")
    except IOError as (errorno, strerror):
        printError("An error occured while opening the output file: " + str(outputFile) + ". " + string.capitalize(
            str(strerror)))
        quit(-1)
    printInfo("Opened output file " + outputFile + " for writing.")
else:
    writeFile = None
    printInfo("No output file specified. Writing final data to stdout.")

# Iterate through each tuple item within assetSet, assigning the values we want, prepare the data to our needs and assign it to a variable for writing to file or stdout
for ip, host, sox, pci in assetSet:
    if sox is True:
        soxValues = string.rstrip(soxValuesStr, ",")
    else:
        soxValues = ""
    if pci is True:
        pciValues = string.rstrip(pciValuesStr, ",")
    else:
        pciValues = ""
    if host is None:
        host = ""

    # TODO: Need a better, more dynamic way to do this. Especially if we start adding more categories. Case/Switch perhaps?
    if soxValues != "" and pciValues != "":
        outputLine = str(ip) + "," + str(host) + "," + "True," + str(soxValues) + "," + str(pciValues)
    elif soxValues == "" and pciValues != "":
        outputLine = str(ip) + "," + str(host) + "," + "True," + str(pciValues)
    elif pciValues == "" and soxValues != "":
        outputLine = str(ip) + "," + str(host) + "," + "True," + str(soxValues)
    elif soxValues == "" and pciValues == "":
        outputLine = str(ip) + "," + str(host) + "," + "True,"

    if writeFile:
        try:
            writeFile.write(outputLine + "\n")
        except IOError as (errorno, strerror):
            printError("An error occurred while writing to the file " + outputFile + ". " + string.capitalize(strerror))
            writeFile.close()
            quit(-1)
        except:
            printError(
                "An unspecified error occured while writing to the file " + outputFile + ". " + string.capitalize(
                    strerror))
            writeFile.close()
            quit(-1)
    else:
        print(outputLine)
if writeFile:
    if debug is True:
        printInfo("Debug: Writing to output file complete.")
    writeFile.close()

quit(0)