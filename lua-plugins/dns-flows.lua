--
-- dns-flows.lua
--
--	This script is a plugin for Wireshark and tshark.  It displays a
--	set of the DNS packet flows between a pair of hosts.  Each port used
--	in the communication is included, along with the elapsed time from
--	the beginning of the packet capture until that particular packet
--	was sent.
--
--	This program will register a menu item in the Tools/GAWSEED menu.
--
--	Some debugging info may be written to a script-specific log file.
--	The filename is defined in the LOGFILE directory.  Set it as desired.
--
--	Wireshark calls tap.packet() to examine packet in turn.  tap.packet()
--	passes a pinfo table and a tvb.  The pinfo table contains a bunch
--	of data associated with the packet.  The tvb is the actual raw packet
--	contents.  The actions taken by tap.packet() are dependent on the
--	needs of the plugin.
--
--	For each packet passed to tap.packet(), this script parses the tvb
--	and builds a table called pkt.  Each pkt table is saved into a table
--	of pkts.  Some pinfo fields are also saved in pkt for easy reference.
--
--		pkt.protocols	table of protocols parsed in packet.  As a new
--				protocol header is parsed from the packet, the
--				protocol name is added to this table.
--				e.g., ('ethernet', 'ip', 'udp', 'dns')
--
--		pkt.hdrindex	byte index into tvb data; used to find the
--				position of the next protocol header
--
--		pkt['pinfo']		table of some fields from pinfo table
--			pkt['pinfo'].packetnum	packet number in data stream
--			pkt['pinfo'].srcaddr	packet's source address
--			pkt['pinfo'].dstaddr	packet's destination address
--			pkt['pinfo'].srcport	packet's source port
--			pkt['pinfo'].dstport	packet's destination port
--			pkt['pinfo'].reltime	relative time of packet in
--						data stream
--
--		pkt['ether']		table of ethernet header fields
--			pkt['ether'].dstaddr	destination MAC address
--			pkt['ether'].srcaddr	source MAC address
--			pkt['ether'].type	Ethernet type; values for type:
--							0x0800 - IPv4
--							0x0806 - ARP
--							0x86DD - IPv6
--							0x8100 - IEEE 802.1Q
--
--		pkt['ip']		table of IP header fields
--			pkt['ip'].version	IP version
--			pkt['ip'].hdrlen	length of packet header
--			pkt['ip'].svctype	type of service
--			pkt['ip'].totallen	total length of packet
--			pkt['ip'].ident		packet identifier
--			pkt['ip'].flags		flag values
--			pkt['ip'].fragoff	frament offset
--			pkt['ip'].ttl		time to live
--			pkt['ip'].proto		protocol number of next header
--			pkt['ip'].checksum	header checksum
--			pkt['ip'].srcaddr	source address
--			pkt['ip'].dstaddr	destination address
--			pkt['ip'].options	options
--
--			See RFC 791 for details about IP fields.
--
--		pkt['udp']		table of UDP header fields
--			pkt['udp'].srcport	source port
--			pkt['udp'].dstport	destination port
--			pkt['udp'].length	length of header and data
--			pkt['udp'].checksum	checksum
--
--			See RFC 768 for details about UDP fields.
--
--		pkt['tcp']		table of TCP header fields
--			pkt['tcp'].srcport	source port
--			pkt['tcp'].dstport	destination port
--			pkt['tcp'].seqnum	sequence number
--			pkt['tcp'].acknum	acknowledgment number
--			pkt['tcp'].offset	data offset
--
--			pkt['tcp'].urg		URG bit
--			pkt['tcp'].ack		ACK bit
--			pkt['tcp'].psh		PSH bit
--			pkt['tcp'].rst		RST bit
--			pkt['tcp'].syn		SYN bit
--			pkt['tcp'].fin		FIN bit
--
--			pkt['tcp'].window	window
--			pkt['tcp'].checksum	checksum
--			pkt['tcp'].urgent	urgent pointer
--			pkt['tcp'].options	options
--
--			See RFC 793 for details about TCP fields.
--
--		pkt['dns']		table of DNS header fields
--			pkt['dns'].transid	transaction identifier
--			pkt['dns'].qrcode	QR code  (Query/Response)
--			pkt['dns'].opcode	opcode -- type of operation
--			pkt['dns'].rcode	response code
--
--			pkt['dns'].aaflag	AA bit	(Authoritative Answer)
--			pkt['dns'].tcflag	TC bit	(Truncation)
--			pkt['dns'].rdflag	RD bit	(Recursion Desired)
--			pkt['dns'].raflag	RA bit	(Recursion Available)
--
--			pkt['dns'].qdcount	number of queries
--			pkt['dns'].ancount	number of answers
--			pkt['dns'].nscount	number of nameserver rrecs
--			pkt['dns'].arcount	number of additional rrecs
--
--			pkt['dns'].queries	list of queries
--			pkt['dns'].answers	list of answers
--			pkt['dns'].nsrrecs	list of ns rrecs
--			pkt['dns'].addtnls	list of additional rrecs
--
--			See RFC 1035 for details about TCP fields.
--
--			There is a small number of other fields in the
--			pkt['dns'] table.  These are constructed and saved
--			as part of the parsing of the DNS header.  They are
--			available for additional use as needed.
--
--				pkt['dns'].offsets	These are the name/index
--							offsets used for DNS
--							name compression.
--							index - index number
--							value - name field
--
--		Caveats:
--			- No checksums are being calculated for any protocols.
--			  This code can be added, but it isn't there in this
--			  version.
--
--
-- Revision History
--	1.0 Initial revision.					190226
--

--
-- Version information.
--
NAME   = "dns-flows";
VERS   = NAME .. " version: 1.0";

------------------------------------------------------------------------------
--
-- Ports we might be interested in.
--

PORT_FTP	= 21
PORT_SSH	= 22 
PORT_TELNET	= 23 
PORT_SMTP	= 25 
PORT_TIME	= 37 
PORT_NAME	= 42 
PORT_WHOIS	= 43 
PORT_DNS	= 53 
PORT_TFTP	= 69 
PORT_HTTP	= 80 
PORT_POP2	= 109 
PORT_POP3	= 110 
PORT_SFTP	= 115 
PORT_NTP	= 123 
PORT_IMAP	= 143 
PORT_SNMP	= 161 
PORT_SNMPTRAP	= 162 
PORT_BGP	= 179 
PORT_IMAP3	= 220 
PORT_LDAP	= 389 
PORT_HTTPS	= 443 
PORT_SYSLOG	= 514 
PORT_LDAPS	= 636 
PORT_FTPSDATA	= 989 
PORT_FTPS	= 990 
PORT_TELNETS	= 992 
PORT_IMAPS	= 993 
PORT_POP3S	= 995 
PORT_SSDP	= 1900 

--
-- Number-to-name translation table for ports.  Others are added
-- in as numerics.
--
local ports = {}

ports[PORT_FTP]		= 'ftp'
ports[PORT_SSH]		= 'ssh'
ports[PORT_TELNET]	= 'telnet'
ports[PORT_SMTP]	= 'smtp'
ports[PORT_TIME]	= 'time'
ports[PORT_NAME]	= 'name'
ports[PORT_WHOIS]	= 'whois'
ports[PORT_DNS]		= 'dns'
ports[PORT_TFTP]	= 'tftp'
ports[PORT_HTTP]	= 'http'
ports[PORT_POP2]	= 'pop2'
ports[PORT_POP3]	= 'pop3'
ports[PORT_SFTP]	= 'sftp'
ports[PORT_NTP]		= 'ntp'
ports[PORT_IMAP]	= 'imap'
ports[PORT_SNMP]	= 'snmp'
ports[PORT_SNMPTRAP]	= 'snmptrap'
ports[PORT_BGP]		= 'bgp'
ports[PORT_IMAP3]	= 'imap3'
ports[PORT_LDAP]	= 'ldap'
ports[PORT_HTTPS]	= 'https'
ports[PORT_SYSLOG]	= 'syslog'
ports[PORT_LDAPS]	= 'ldaps'
ports[PORT_FTPSDATA]	= 'ftps-data'
ports[PORT_FTPS]	= 'ftps'
ports[PORT_TELNETS]	= 'telnets'
ports[PORT_IMAPS]	= 'imaps'
ports[PORT_POP3S]	= 'pop3s'
ports[PORT_SSDP]	= 'ssdp'

--
-- Protocol numbers.
--
local PROTO_IP	 = 0
local PROTO_ICMP = 1
local PROTO_TCP	 = 6
local PROTO_UDP	 = 17

--
-- Query classes.
--
local QCLASS_IN		= 1				-- Internet.
local QCLASS_CHAOS	= 3				-- MIT Chaos-net.
local QCLASS_HS		= 4				-- MIT Hesiod.
local QCLASS_ANY	= 255				-- Wildcard.


--
-- Query types.
--
local QTYPE_A		= 1		-- Host address.
local QTYPE_NS		= 2		-- Authoritative server.
local QTYPE_MD		= 3		-- Mail destination.
local QTYPE_MF		= 4		-- Mail forwarder.
local QTYPE_CNAME	= 5		-- Canonical name.
local QTYPE_SOA		= 6		-- Start of authority zone.
local QTYPE_MB		= 7		-- Mailbox domain name.
local QTYPE_MG		= 8		-- Mail group member.
local QTYPE_MR		= 9		-- Mail rename name.
local QTYPE_NULL	= 10		-- Null resource record.
local QTYPE_WKS		= 11		-- Well known service.
local QTYPE_PTR		= 12		-- Domain name pointer.
local QTYPE_HINFO	= 13		-- Host information.
local QTYPE_MINFO	= 14		-- Mailbox information.
local QTYPE_MX		= 15		-- Mail routing information.
local QTYPE_TXT		= 16		-- Text strings.
local QTYPE_RP		= 17		-- Responsible person.
local QTYPE_AFSDB	= 18		-- AFS cell database.
local QTYPE_X25		= 19		-- X_25 calling address.
local QTYPE_ISDN	= 20		-- ISDN calling address.
local QTYPE_RT		= 21		-- Router.
local QTYPE_NSAP	= 22		-- NSAP address.
local QTYPE_NSAP_PTR	= 23		-- Reverse NSAP lookup.	    (deprecated)
local QTYPE_SIG		= 24		-- Security signature.
local QTYPE_KEY		= 25		-- Security key.
local QTYPE_PX		= 26		-- X.400 mail mapping.
local QTYPE_GPOS	= 27		-- Geographical position.    (withdrawn)
local QTYPE_AAAA	= 28		-- Ip6 Address.
local QTYPE_LOC		= 29		-- Location Information.
local QTYPE_NXT		= 30		-- Next domain.
local QTYPE_EID		= 31		-- Endpoint identifier.
local QTYPE_NIMLOC	= 32		-- Nimrod Locator.
local QTYPE_SRV		= 33		-- Server Selection.
local QTYPE_ATMA	= 34		-- ATM Address
local QTYPE_NAPTR	= 35		-- Naming Authority Pointer.
local QTYPE_KX		= 36		-- Key Exchange
local QTYPE_CERT	= 37		-- Certification record.
local QTYPE_A6		= 38		-- IPv6 address.       (deprecates AAAA)
local QTYPE_DNAME	= 39		-- Non-terminal DNAME.        (for IPv6)
local QTYPE_SINK	= 40		-- Kitchen sink.          (experimental)
local QTYPE_OPT		= 41		-- EDNS0 option.
local QTYPE_TKEY	= 249		-- Transaction key.
local QTYPE_TSIG	= 250		-- Transaction signature.
local QTYPE_IXFR	= 251		-- Incremental zone transfer.
local QTYPE_AXFR	= 252		-- Transfer zone of authority.
local QTYPE_MAILB	= 253		-- Transfer mailbox records.
local QTYPE_MAILA	= 254		-- Transfer mail agent records.
local QTYPE_ANY		= 255		-- Wildcard match.
local QTYPE_ZXFR	= 256		-- BIND-specific, nonstandard.

--
-- Query types' strings.
--

local querytypes = {}

querytypes[QTYPE_A]		= 'A'
querytypes[QTYPE_NS]		= 'NS'
querytypes[QTYPE_MD]		= 'MD'
querytypes[QTYPE_MF]		= 'MF'
querytypes[QTYPE_CNAME]		= 'CNAME'
querytypes[QTYPE_SOA]		= 'SOA'
querytypes[QTYPE_MB]		= 'MB'
querytypes[QTYPE_MG]		= 'MG'
querytypes[QTYPE_MR]		= 'MR'
querytypes[QTYPE_NULL]		= 'NULL'
querytypes[QTYPE_WKS]		= 'WKS'
querytypes[QTYPE_PTR]		= 'PTR'
querytypes[QTYPE_HINFO]		= 'HINFO'
querytypes[QTYPE_MINFO]		= 'MINFO'
querytypes[QTYPE_MX]		= 'MX'
querytypes[QTYPE_TXT]		= 'TXT'
querytypes[QTYPE_RP]		= 'RP'
querytypes[QTYPE_AFSDB]		= 'AFSDB'
querytypes[QTYPE_X25]		= 'X25'
querytypes[QTYPE_ISDN]		= 'ISDN'
querytypes[QTYPE_RT]		= 'RT'
querytypes[QTYPE_NSAP]		= 'NSAP'
querytypes[QTYPE_NSAP_PTR]	= 'NSAP_PTR'
querytypes[QTYPE_SIG]		= 'SIG'
querytypes[QTYPE_KEY]		= 'KEY'
querytypes[QTYPE_PX]		= 'PX'
querytypes[QTYPE_GPOS]		= 'GPOS'
querytypes[QTYPE_AAAA]		= 'AAAA'
querytypes[QTYPE_LOC]		= 'LOC'
querytypes[QTYPE_NXT]		= 'NXT'
querytypes[QTYPE_EID]		= 'EID'
querytypes[QTYPE_NIMLOC]	= 'NIMLOC'
querytypes[QTYPE_SRV]		= 'SRV'
querytypes[QTYPE_ATMA]		= 'ATMA'
querytypes[QTYPE_NAPTR]		= 'NAPTR'
querytypes[QTYPE_KX]		= 'KX'
querytypes[QTYPE_CERT]		= 'CERT'
querytypes[QTYPE_A6]		= 'A6'
querytypes[QTYPE_DNAME]		= 'DNAME'
querytypes[QTYPE_SINK]		= 'SINK'
querytypes[QTYPE_OPT]		= 'OPT'
querytypes[QTYPE_TKEY]		= 'TKEY'
querytypes[QTYPE_TSIG]		= 'TSIG'
querytypes[QTYPE_IXFR]		= 'IXFR'
querytypes[QTYPE_AXFR]		= 'AXFR'
querytypes[QTYPE_MAILB]		= 'MAILB'
querytypes[QTYPE_MAILA]		= 'MAILA'
querytypes[QTYPE_ANY]		= 'ANY'
querytypes[QTYPE_ZXFR]		= 'ZXFR'

----------------------------------------------------------
--
-- DNS constants   (taken from proto.lua)
--

local DNS_HDR_LEN = 12					-- DNS header size

--
-- The smallest possible DNS query field size.  This has to be at least a
-- label length octet, label character, label null terminator, 2-bytes type
-- and 2-bytes class.
--
local MIN_QUERY_LEN = 7
 
------------------------------------------------------------------------------

local debug = 1					-- Flag for *some* logging.

local logpackets = 0				-- Flag to log packet contents
						-- after parsing.

local LOGFILE = "/tmp/save.dns-flows"		-- General log file.

local SAVELOG = "/tmp/dnsflows.log"		-- Log file for saving flows.

if(debug ~= 0) then
	local loggy = io.open(LOGFILE,"a")
	if loggy ~= nil then
--		loggy:write("\ndns-flows.lua:  down in\n\n")
		io.close(loggy)
	end                
end

local rootdot = 1				-- Add root '.' to FQDNs.

--------------------------------------------------------------------------------
--------------------------------------------------------------------------------
--------------------------------------------------------------------------------
--
-- This section contains routine specific for handling ethernet packets.
--
-- Interfaces:
--	parse(pkt, tvb)		Parses the ethernet header portion of a tvb
--				buffer and adds the fields to a pkt table.
--
--	log(pkt)		Logs the parsed fields from an ethernet header.
--

ether = {}				-- Table for grouping IP functions.

----------------------------------------------------------------------
-- Routine:	ether.parse()
--
-- Purpose:	This function saves the required fields from the ethernet
--		portion of the packet.
--
--		Values for the type field:
--			IPv4 - 0x0800
--			ARP  - 0x0806 
--			IPv6 - 0x86DD
--			IEEE 802.1Q - 0x8100
--
--		It is unknown if these will be needed.
--
function ether.parse(pkt,tvb)

--	loggit("ether.parse:  hdrindex 0 - " .. tostring(pkt.hdrindex) .. "\n")

	tvbr = tvb:range(0,14)

	--
	-- Save the ethernet-header fields.
	--
	pkt['ether']	     = {}
	pkt['ether'].dstaddr = tvbr:range(0, 6)
	pkt['ether'].srcaddr = tvbr:range(6, 6)
	pkt['ether'].type    = tvbr:range(12, 2):uint()

	--
	-- Account for the length of the ethernet header.
	--
	pkt.hdrindex = pkt.hdrindex + 14

	--
	-- Mark the packet as having parsed ethernet fields.
	--
	if(pkt.protocols == nil) then
		pkt.protocols = {}
	end
	table.insert(pkt.protocols, 'ether')

end

----------------------------------------------------------------------
-- Routine:	ether.log()
--
-- Purpose:	This function logs the saved contents of an ethernet header.
--
function ether.log(pkt)

	loggit("ethernet fields:\n")

	loggit("\t dstaddr    - <" .. tostring(pkt['ether'].dstaddr) .. ">\n")

	loggit("\t srcaddr    - <" .. tostring(pkt['ether'].srcaddr) .. ">\n")

	out = string.format("%04x", pkt['ether'].type)
	loggit("\t type       - <" .. tostring(pkt['ether'].type) .. ">\t\t\t(" .. out .. ")\n")

	loggit("\n")

end


--------------------------------------------------------------------------------
--------------------------------------------------------------------------------
--------------------------------------------------------------------------------
--
-- This section contains routine specific for handling IP packets.
--
-- Interfaces:
--	parse(pkt, tvb)		Parses the IP header portion of a tvb buffer
--				and adds the fields to a pkt table.
--
--	log(pkt)		Logs the parsed fields from an IP header.
--

ip = {}				-- Table for grouping IP functions

----------------------------------------------------------------------
-- Routine:	ip.parse()
--
-- Purpose:	This function saves the required fields from the IP portion
--		of the packet.
--
function ip.parse(pkt,tvb)

	tvbr = tvb:range(pkt.hdrindex)

	--
	-- Squirrel away the IP fields.
	--
	pkt['ip']	   = {}
	pkt['ip'].version  = tvbr:bitfield(0, 4)
	pkt['ip'].hdrlen   = tvbr:bitfield(4, 4)
	pkt['ip'].svctype  = tvbr:bitfield(8, 8)
	pkt['ip'].totallen = tvbr:range(2, 2):uint()
	pkt['ip'].ident	   = tvbr:range(4, 2):uint()
	pkt['ip'].flags	   = tvbr:bitfield(48, 3)
	pkt['ip'].fragoff  = tvbr:bitfield(51, 13)
	pkt['ip'].ttl	   = tvbr:range(8, 1):uint()
	pkt['ip'].proto	   = tvbr:range(9, 1):uint()
	pkt['ip'].checksum = tvbr:range(10, 2):uint()
	pkt['ip'].dstaddr  = tvbr:range(12, 4):ipv4()
	pkt['ip'].srcaddr  = tvbr:range(16, 4):ipv4()

	--
	-- If we have no options, we'll nil out the options field.
	-- If we do, we'll copy them all into the options field.
	-- This will include whatever padding is required.
	--

	if(pkt['ip'].hdrlen == 5) then
		pkt['ip'].options = nil
	else
		optlen = (pkt['ip'].hdrlen - 5) * 8
		pkt['ip'].options = tvbr:bitfield(160, optlen)
	end

	--
	-- Account for the length of the IP header.
	--

	pkt.hdrindex = pkt.hdrindex + (pkt['ip'].hdrlen * 4)

	--
	-- Mark the packet as having parsed IP fields.
	--
	if(pkt.protocols == nil) then
		pkt.protocols = {}
	end
	table.insert(pkt.protocols, 'ip')

end


----------------------------------------------------------------------
-- Routine:	ip.proto2str()
--
-- Purpose:	This function translates a transport-layer number into a text
--		string.  The text string is then returned to the caller.
--
--		This number is all of the following:
--			- the protocol field of an IP header
--			- defined in /etc/protocols	(in Unix)
--
--		Examples:
--			- 0	-> IP
--			- 1	-> ICMP
--			- 6	-> TCP
--			- 17	-> UDP
--
function ip.proto2str(transnum)

	if(transnum == PROTO_IP) then
		proto = 'IP'
	elseif(transnum == PROTO_ICMP) then
		proto = 'ICMP'
	elseif(transnum == PROTO_TCP) then
		proto = 'TCP'
	elseif(transnum == PROTO_UDP) then
		proto = 'UDP'
	else
		proto = string.format("UNKNOWN Transport Type -- %d", transnum)
	end

	return proto
end


----------------------------------------------------------------------
-- Routine:	ip.log()
--
-- Purpose:	This function logs the saved contents of an IP header.
--
function ip.log(pkt)
	local out					-- Output string.

	loggit("IP fields:\n")

	out = string.format("\tversion    - %d\t\t\t%08x\n", pkt['ip'].version, pkt['ip'].version)
	loggit(out)

	out = string.format("\thdrlen     - %d\t\t\t%08x\n", pkt['ip'].hdrlen, pkt['ip'].hdrlen)
	loggit(out)

	out = string.format("\tsvctype    - %d\t\t\t%08x\n", pkt['ip'].svctype, pkt['ip'].svctype)
	loggit(out)

	out = string.format("\ttotallen   - %d\t\t\t%08x\n", pkt['ip'].totallen, pkt['ip'].totallen)
	loggit(out)

	out = string.format("\tident      - %d\t\t%08x\n", pkt['ip'].ident, pkt['ip'].ident)
	loggit(out)

	out = string.format("\tflags      - %d\t\t\t%08x\n", pkt['ip'].flags, pkt['ip'].flags)
	loggit(out)

	out = string.format("\tfragoff    - %d\t\t\t%08x\n", pkt['ip'].fragoff, pkt['ip'].fragoff)
	loggit(out)

	out = string.format("\tttl        - %d\t\t\t%08x\n", pkt['ip'].ttl, pkt['ip'].ttl)
	loggit(out)

	out = string.format("\tproto      - %d\t\t\t%08x\t%s\n", pkt['ip'].proto, pkt['ip'].proto, ip.proto2str(pkt['ip'].proto))
	loggit(out)

	out = string.format("\tchecksum   - %d\t\t%08x\n", pkt['ip'].checksum, pkt['ip'].checksum)
	loggit(out)

	out = string.format("\tdstaddr    - %s\n", pkt['ip'].dstaddr)
	loggit(out)

	out = string.format("\tsrcaddr    - %s\n", pkt['ip'].srcaddr)
	loggit(out)

	loggit("\n")

end


--------------------------------------------------------------------------------
--------------------------------------------------------------------------------
--------------------------------------------------------------------------------
--
-- This section contains routine specific for handling UDP packets.
--
-- Interfaces:
--	parse(pkt, tvb)		Parses the UDP header portion of a tvb buffer
--				and adds the fields to a pkt table.
--
--	log(pkt)		Logs the parsed fields from an UDP header.
--

udp = {}				-- Table for grouping UDP functions.

----------------------------------------------------------------------
-- Routine:	udp.parse()
--
-- Purpose:	This function saves the required fields from the UDP portion
--		of the packet.
--
function udp.parse(pkt,tvb)

	tvbr = tvb:range(pkt.hdrindex)

	--
	-- Save the UDP fields.
	--
	pkt['udp']	     = {}
	pkt['udp'].srcport  = tvbr:range(0, 2):uint()
	pkt['udp'].dstport  = tvbr:range(2, 2):uint()
	pkt['udp'].length   = tvbr:range(4, 2):uint()
	pkt['udp'].checksum = tvbr:range(6, 2):uint()

	--
	-- Account for the length of the UDP header.
	--
	pkt.hdrindex = pkt.hdrindex + 8

	--
	-- Mark the packet as having parsed UDP fields.
	--
	if(pkt.protocols == nil) then
		pkt.protocols = {}
	end
	table.insert(pkt.protocols, 'udp')

end

----------------------------------------------------------------------
-- Routine:	udp.log()
--
-- Purpose:	This function logs the saved contents of a UDP header.
--
function udp.log(pkt)

	loggit("UDP fields:\n")

	pkt['udp'].srcport  = tvbr:range(0, 2):uint()
	pkt['udp'].dstport  = tvbr:range(2, 2):uint()
	pkt['udp'].length   = tvbr:range(4, 2):uint()
	pkt['udp'].checksum = tvbr:range(6, 2):uint()

	out = string.format("%04x", pkt['udp'].srcport)
	loggit("\t srcport    - <" .. tostring(pkt['udp'].srcport) .. ">\t\t(" .. out .. ")\n")

	out = string.format("%04x", pkt['udp'].dstport)
	loggit("\t dstport    - <" .. tostring(pkt['udp'].dstport) .. ">\t\t(" .. out .. ")\n")

	out = string.format("%04x", pkt['udp'].length)
	loggit("\t length     - <" .. tostring(pkt['udp'].length) .. ">\t\t(" .. out .. ")\n")

	out = string.format("%04x", pkt['udp'].checksum)
	loggit("\t checksum   - <" .. tostring(pkt['udp'].checksum) .. ">\t\t(" .. out .. ")\n")

	loggit("\n")

end


--------------------------------------------------------------------------------
--------------------------------------------------------------------------------
--------------------------------------------------------------------------------
--
-- This section contains routine specific for handling TCP packets.
--
-- Interfaces:
--	parse(pkt, tvb)		Parses the TCP header portion of a tvb buffer
--				and adds the fields to a pkt table.
--
--	log(pkt)		Logs the parsed fields from an TCP header.
--				(This function is a stub and is not yet
--				implemented.)
--

tcp = {}				-- Table for grouping TCP functions.

----------------------------------------------------------------------
-- Routine:	tcp.parse()
--
-- Purpose:	This function saves the required fields from the TCP portion
--		of the packet.
--
function tcp.parse(pkt,tvb)

	tvbr = tvb:range(pkt.hdrindex)

	--
	-- Save the TCP fields.
	--
	pkt['tcp']	     = {}
	pkt['tcp'].srcport = tvbr:range(0, 2):uint()
	pkt['tcp'].dstport = tvbr:range(2, 2):uint()
	pkt['tcp'].seqnum  = tvbr:range(4, 4):uint()
	pkt['tcp'].acknum  = tvbr:range(8, 4):uint()

	pkt['tcp'].offset = tvbr:bitfield(96, 4)
	pkt['tcp'].urg	  = tvbr:bitfield(106, 1)
	pkt['tcp'].ack	  = tvbr:bitfield(107, 1)
	pkt['tcp'].psh	  = tvbr:bitfield(108, 1)
	pkt['tcp'].rst	  = tvbr:bitfield(109, 1)
	pkt['tcp'].syn	  = tvbr:bitfield(110, 1)
	pkt['tcp'].fin	  = tvbr:bitfield(111, 1)

	pkt['tcp'].window   = tvbr:range(14, 2):uint()
	pkt['tcp'].checksum = tvbr:range(16, 2):uint()
	pkt['tcp'].urgent   = tvbr:range(18, 2):uint()
	pkt['tcp'].options  = tvbr:range(20, 2):uint()

	--
	-- Account for the length of the TCP header.
	--
	pkt.hdrindex = pkt.hdrindex + (pkt['tcp'].offset * 4)

	--
	-- Mark the packet as having parsed TCP fields.
	--
	if(pkt.protocols == nil) then
		pkt.protocols = {}
	end
	table.insert(pkt.protocols, 'tcp')

end

----------------------------------------------------------------------
-- Routine:	tcp.log()
--
-- Purpose:	This function logs the saved contents of a TCP header.
--
function tcp.log(pkt)

	loggit("\nTCP logging -- NYO\n");
	if(42 > 0) then
		return
	end

	loggit("TCP fields:\n")

	loggit("\n")

end


--------------------------------------------------------------------------------
--------------------------------------------------------------------------------
--------------------------------------------------------------------------------
--
-- This section contains routine specific for handling DNS packets.
--
-- Interfaces:
--	parse(pkt, tvb)		Parses the DNS header portion of a tvb buffer
--				and adds the fields to a pkt table.
--
--	log(pkt)		Logs the parsed fields from an DNS header.
--
--	dns.getanswer(pkt, rrecdata, ind)
--				Digs an answer out of a tvb buffer.  This may
--				be in the answer section, the ns-rrec section,
--				or the additional rrecs section.
--

dns = {}				-- Table for grouping DNS functions.


----------------------------------------------------------------------
-- Routine:	dns_getanswer()
--
-- Purpose:	This function parses the next entry in the answer section of
--		a DNS packet.  The NS rrecs section and additional rrecs
--		section use the same format, so this is also called to parse
--		those sections.
--
--		The answer entry is returned to the caller.
--		Also, the index of the next entry in the data is returned.
--
function dns_getanswer(pkt, rrecdata, ind)

	local offsets = pkt['dns'].offsets

	local len		-- Name length.
	local domain = ''	-- Domain in answer.
	local answer = {}	-- Answer table for each rrec.

	--
	-- Grab each piece of the domain name and add it to our name buffer.
	-- We'll handle both inline names and names that are stored with
	-- DNS compression.
	--
	while(42) do
		local len	-- Name length.

		--
		-- Get the length of the name element.
		--
		len = rrecdata:range(ind, 1):uint()

		--
		-- Move on if we're at the end of the name element.
		--
		if(len == 0) then
			break
		end

		--
		-- If this is a compressed name, we'll look it up in the table
		-- of known offsets.  Otherwise, we'll just grab the entry.
		--
		if(len == 0xc0) then
			local bitind	-- Bit index for offset.
			local offset	-- Name offset for compression.

			--
			-- Get the bit position of the name offset.
			--
			bitind = (ind * 8) + 2

			offset  = rrecdata:bitfield(bitind, 14)

			--
			-- Get the name element.
			--
			atom = offsets[offset]
			if(atom == nil) then
				atom = "<<<unknown name offset>>>"
			end

			--
			-- Move past the compression index.
			--
			ind = ind + 2

		else

			--
			-- Move past the length to the name.
			--
			ind = ind + 1

			--
			-- Get the name element.
			--
			atom = rrecdata:range(ind, len):string()

			--
			-- Move to the end of this name.
			--
			ind = ind + len

		end

		--
		-- Add the name element to the domain.
		--
		domain = domain .. atom .. '.'

	end

	--
	-- Strip off the root domain's dot if it shouldn't be displayed.
	--
	if(rootdot == 0) then
		domain = string.gsub(domain, '%.$', '')
	end

	--
	-- Use the root domain if there wasn't anything found.
	--
	if(domain == '') then
		domain = '.'
		ind = ind + 1
	end

	--
	-- Save the domain name and query type in the answer.
	--
	answer['name']  = domain

	answer['type']  = rrecdata:range(ind, 2):uint()

	--
	-- Get the rest of the resource record and add the fields to the answer
	-- table.  If any query types have special answer formats, they'll be
	-- recognized here.
	-- We'll also move the index pointer past this answer.
	--
	if(answer['type'] == QTYPE_OPT) then

		answer['class'] = ''
		answer['ttl']	= ''
		answer['len']	= ''
		answer['data']	= rrecdata:range((ind + 2), 8)

		ind = ind + 2 + 8

	else

		answer['class'] = rrecdata:range((ind + 2), 2):uint()
		answer['ttl']	= rrecdata:range((ind + 4), 4):uint()
		answer['len']	= rrecdata:range((ind + 8), 2):uint()
		answer['data']	= rrecdata:range((ind + 10), answer['len'])

		ind = ind + 10 + answer['len']

	end

	--
	-- Return the answer to our caller.
	--
	return answer, ind

end

----------------------------------------------------------------------
-- Routine:	dns.parse()
--
-- Purpose:	This function saves the required fields from the DNS portion
--		of the packet.
--
function dns.parse(pkt,tvb)

	local len			-- General length field.
	local offsets = {}		-- Table of offsets/domains.

	local queries = {}		-- List of queries.
	local answers = {}		-- List of answers.

	local hdrindex			-- Length of headers in packet.
	local enddata			-- Remaining data in packet.
	local endlen			-- Length of data in packet.
	local pktlen			-- Length of the packet.

	local cnt			-- Data elements per section.
	local ind = 0			-- Index into end data.

	--
	-- We'll only handle DNS packets here.
	--
	if((pkt['pinfo'].srcport ~= PORT_DNS)	and
	   (pkt['pinfo'].srcport ~= "dns")	and
	   (pkt['pinfo'].dstport ~= PORT_DNS)	and
	   (pkt['pinfo'].dstport ~= "dns"))	then
		return
	end

	--
	-- Get the length of the packet buffer.
	-- (There are two different way; one code blob said the second is the
	-- better way.  We'll use it until we see it shouldn't be.)
--		len = tvb:len()
	--
	len = tvb:reported_length_remaining()

	--
	-- Get the DNS part of the packet.
	--
	tvbr = tvb:range(pkt.hdrindex)

	--
	-- Save the DNS fields.
	--
	pkt['dns']	   = {}
	pkt['dns'].transid = tvbr:range(0,2):uint()

	pkt['dns'].qrcode  = tvbr:bitfield(16,1)
	pkt['dns'].opcode  = tvbr:bitfield(17,4)
	pkt['dns'].aaflag  = tvbr:bitfield(21,1)
	pkt['dns'].tcflag  = tvbr:bitfield(22,1)
	pkt['dns'].rdflag  = tvbr:bitfield(23,1)
	pkt['dns'].raflag  = tvbr:bitfield(24,1)
	pkt['dns'].rcode   = tvbr:bitfield(28,4)
	pkt['dns'].qdcount = tvbr:bitfield(32,16)
	pkt['dns'].ancount = tvbr:bitfield(48,16)
	pkt['dns'].nscount = tvbr:bitfield(64,16)
	pkt['dns'].arcount = tvbr:bitfield(80,16)

	--
	-- Need to initialize the packet data, even if these are empty.
	--
	pkt['dns'].queries = {}
	pkt['dns'].answers = {}
	pkt['dns'].nsrrecs = {}
	pkt['dns'].addtnls = {}

	--
	-- Get some lengths for the remaining packet chunk.
	--
	pktlen = tvb:len()
	hdrindex = pkt.hdrindex + DNS_HDR_LEN

	--
	-- Get the DNS data at the end of the packet.
	--
	endlen = pktlen - hdrindex
	enddata = tvbr:range(DNS_HDR_LEN, endlen)

	--
	-- Build each query into a domain name and put it on the queries list.
	--
	cnt = pkt['dns'].qdcount
	while(cnt > 0) do

		local query = {}	-- Query table for each query.
		local domain = ''	-- Domain under construction.
		local qtype		-- Query type.
		local qclass		-- Query class.

		--
		-- Grab each piece of the domain name and add it to our
		-- name buffer.
		--
		while(42) do
			local len	-- Name length.

			--
			-- Get length of name element.
			--
			len = enddata:range(ind, 1):uint()

			--
			-- Drop out if at the end of this name element.
			--
			if(len == 0) then
				break
			end

			--
			-- Move past length to name.
			--
			ind = ind + 1

			--
			-- Get the name element and add it to domain.
			--
			atom = enddata:range(ind, len):string()
			domain = domain .. atom .. '.'

			--
			-- Add this atom to the end of each saved name in
			-- the offsets table.
			--
			for i in pairs(offsets) do
				offsets[i] = offsets[i] .. "." .. atom
			end

			--
			-- Save this name element in the offsets table.
			--
			offsets[(DNS_HDR_LEN + ind - 1)] = atom

			--
			-- Move to the end of this name.
			--
			ind = ind + len

		end

		--
		-- Move past the name-ending null.
		--
		ind = ind + 1

		--
		-- Get the query type and class.
		--
		qtype  = enddata:range(ind, 2):uint()
		qclass = enddata:range((ind + 2), 2):uint()

		--
		-- Strip off the root domain's dot if it shouldn't be displayed.
		--
		if(rootdot == 0) then
			domain = string.gsub(domain, '%.$', '')
		end

		--
		-- Add the query fields to the query table.
		--
		query['name']  = domain
		query['type']  = qtype
		query['class'] = qclass

		--
		-- Save the query to our list of queries.
		--
		table.insert(queries, query)

		if(debug ~= 0) then
			local str

			loggit("		domain - <" .. domain .. ">\n")

			str = string.format("%08x", qtype)
			loggit("		qtype  - <" .. str .. ">\n")
			str = string.format("%08x", qclass)
			loggit("		qclass - <" .. str .. ">\n")
		end

		--
		-- Bump our counters and go to the next query.
		--
		ind = ind + 4
		cnt = cnt - 1

	end

	--
	-- Save the list of queries and the offsets table to the packet.
	--
	pkt['dns'].queries = queries
	pkt['dns'].offsets = offsets


	--
	-- Now we'll pick up any answers and other rrecs.
	--

	--
	-- If there are any answer rrecs, parse them and add 'em to the
	-- answers list.
	--
	cnt = pkt['dns'].ancount
	if(cnt > 0) then
		while(cnt > 0) do
			local ans			-- Answer rrec.

			ans, ind = dns_getanswer(pkt, enddata, ind)
			table.insert(answers, ans)

			cnt = cnt - 1
		end

		--
		-- Save the list of answers to the packet.
		--
		pkt['dns'].answers = answers

	end

	--
	-- Now look for some name-server rrecs.
	--
	cnt = pkt['dns'].nscount
	if(cnt > 0) then
		answers = {}
		while(cnt > 0) do
			local ans			-- Answer rrec.

			ans, ind = dns_getanswer(pkt, enddata, ind)
			table.insert(answers, ans)

			cnt = cnt - 1
		end

		--
		-- Save the list of ns rrecs to the packet.
		--
		pkt['dns'].nsrrecs = answers

	end

	--
	-- And finally, look for the additional rrecs.
	--
	cnt = pkt['dns'].arcount
	if(cnt > 0) then
		answers = {}
		while(cnt > 0) do
			local ans			-- Answer rrec.

			ans, ind = dns_getanswer(pkt, enddata, ind)
			table.insert(answers, ans)

			cnt = cnt - 1
		end

		--
		-- Save the list of additional rrecs to the packet.
		--
		pkt['dns'].addtnls = answers

	end


	--
	-- Account for the length of the DNS header.
	--
	pkt.hdrindex = pkt.hdrindex + DNS_HDR_LEN

	--
	-- Mark the packet as having parsed DNS fields.
	--
	if(pkt.protocols == nil) then
		pkt.protocols = {}
	end
	table.insert(pkt.protocols, 'dns')

end


----------------------------------------------------------------------
-- Routine:	dns.qclass2str()
--
-- Purpose:	This function translates a DNS query class number into a
--		text string.  The text string is then returned to the caller.
--
--		Examples:
--			- 1  -> IN	(Internet)
--			- 3  -> CHAOS	(MIT Chaos-net)
--			- 4  -> HS	(MIT Hesiod)
--			- 255 -> ANY	(wildcard)
--
function dns.qclass2str(qcnum)

	local qstr				-- Query-class string.

	if((qcnum == nil) or (qcnum == '')) then
		qstr = string.format("UNKNOWN DNS Query Class - no class given")
		return qstr
	end

	if(qcnum == QCLASS_IN) then
		qstr = 'IN'
	elseif(qcnum == QCLASS_CHAOS) then
		qstr = 'CHAOS'
	elseif(qcnum == QCLASS_HS) then
		qstr = 'HESIOD'
	elseif(qcnum == QCLASS_ANY) then
		qstr = 'ANY'
	else
		qstr = string.format("UNKNOWN DNS Query Class - %d", qcnum)
	end

	return qstr
end

----------------------------------------------------------------------
-- Routine:	dns.log()
--
-- Purpose:	This function logs the saved contents of a DNS header.
--
function dns.log(pkt)

	local srcdst			-- Source/destination string.
	local qtstr			-- Query-type string.

	--
	-- Ensure we weren't called for a non-DNS packet.
	--
	if(pkt['dns'] == nil) then
		loggit("dns.log() called for non-DNS packet\n")
		return
	end

	--
	-- Build a source/destination address string.
	--
	srcdst = tostring(pkt['pinfo'].srcaddr) ..  " || " ..  tostring(pkt['pinfo'].dstaddr)

	loggit("DNS fields:\n")

	out = string.format("%08x", pkt['dns'].transid)
	loggit("\t transid    - <" .. tostring(pkt['dns'].transid) ..  "\t\t(" .. out .. ")\n")

	out = (((pkt['dns'].qrcode) == 0) and 'query') or 'response'
	loggit("\t qrcode     - <" .. tostring(pkt['dns'].qrcode) ..  ">\t\t(" .. out .. ")\n")

	--
	-- Translate the numeric opcode into a string.
	--
	out = "(reserved!)"
	if(pkt['dns'].opcode == 0) then
		out = "(standard query -- QUERY)"
	elseif(pkt['dns'].opcode == 1) then
		out = "(inverse query -- IQUERY)"
	elseif(pkt['dns'].opcode == 2) then
		out = "(server status request -- STATUS)"
	end

	loggit("\t opcode     - <" .. tostring(pkt['dns'].opcode) ..  ">\t\t" .. out .. "\n")

	loggit("\t aaflag     - <" .. tostring(pkt['dns'].aaflag) ..  ">\n")

	loggit("\t tcflag     - <" .. tostring(pkt['dns'].tcflag) ..  ">\n")

	loggit("\t rdflag     - <" .. tostring(pkt['dns'].rdflag) ..  ">\n")

	loggit("\t raflag     - <" .. tostring(pkt['dns'].raflag) ..  ">\n")

	--
	-- Translate the numeric rcode into a string.
	--
	out = "(reserved)"
	if(pkt['dns'].rcode == 0) then
		out = "(no error)"
	elseif(pkt['dns'].rcode == 1) then
		out = "(format error)"
	elseif(pkt['dns'].rcode == 2) then
		out = "(server error)"
	elseif(pkt['dns'].rcode == 3) then
		out = "(name error)"
	elseif(pkt['dns'].rcode == 4) then
		out = "(not-implemented error)"
	elseif(pkt['dns'].rcode == 5) then
		out = "(refused)"
	end
	local rcodestr = string.format("%0x", pkt['dns'].rcode)
	loggit("\t rcode      - <" .. rcodestr ..  ">\t\t" .. out .. "\n")

	loggit("\t qdcount    - <" .. tostring(pkt['dns'].qdcount) ..  ">\n")
	loggit("\t ancount    - <" .. tostring(pkt['dns'].ancount) ..  ">\n")
	loggit("\t nscount    - <" .. tostring(pkt['dns'].nscount) ..  ">\n")
	loggit("\t arcount    - <" .. tostring(pkt['dns'].arcount) ..  ">\n")
	loggit("\n")

	--
	-- Display the list of questions.
	--
	if(pkt['dns'].qdcount > 0) then
		loggit("\t questions:\n")

		for ind, qry in ipairs(pkt['dns'].queries) do
			qcl = dns.qclass2str(qry['class'])

			qtstr = querytypes[qry['type']]
			if(qtstr == nil) then
				qtstr = tostring(qry['type'])
			end

			loggit("\t\t" .. qry['name'] .. "\t" .. qtstr .. "\t" .. qcl .. "\n")
		end
	else
		loggit("\t no questions\n")
	end

	--
	-- Display the list of answers.
	--
	if(pkt['dns'].ancount > 0) then
		loggit("\n")
		loggit("\t answers:\n")

		for ind, ans in ipairs(pkt['dns'].answers) do
			qcl = dns.qclass2str(ans['class'])

			qtstr = querytypes[ans['type']]
			if(qtstr == nil) then
				qtstr = tostring(ans['type'])
			end

			loggit("\t\t" .. ans['name'] .. "\t" .. qtstr .. "\t" .. qcl .. "\t" .. tostring(ans['data']) .. "\n")
		end
	else
		loggit("\n")
		loggit("\t no answers\n")
	end

	--
	-- Display the list of NS rrecs.
	--
	if(pkt['dns'].nscount > 0) then
		loggit("\n")
		loggit("\t ns rrecs:\n")

		for ind, nsrr in ipairs(pkt['dns'].nsrrecs) do
			qcl = dns.qclass2str(nsrr['class'])

			qtstr = querytypes[nsrr['type']]
			if(qtstr == nil) then
				qtstr = tostring(nsrr['type'])
			end

			loggit("\t\t" .. nsrr['name'] .. "\t" .. qtstr .. "\t" .. qcl .. "\t" .. tostring(nsrr['data']) .. "\n")
		end
	else
		loggit("\n")
		loggit("\t no ns rrecs\n")
	end

	--
	-- Display the list of additional rrecs.
	--
	if(pkt['dns'].arcount > 0) then
		loggit("\n")
		loggit("\t additional rrecs:\n")

		for ind, addl in ipairs(pkt['dns'].addtnls) do
			qtstr = querytypes[addl['type']]
			if(qtstr == nil) then
				qtstr = tostring(addl['type'])
			end

			if(addl['class'] ~= '') then
				qcl = dns.qclass2str(addl['class'])
				loggit("\t\t" .. addl['name'] .. "\t" .. qtstr .. "\t" .. qcl .. "\t" .. tostring(addl['data']) .. "\n")
			else
				loggit("\t\t" .. addl['name'] .. "\t" .. qtstr .. "\t" .. qcl .. "\t(no class for type)\n")
			end
		end
	else
		loggit("\n")
		loggit("\t no additional rrecs\n")
	end

	loggit("\n")

end

--------------------------------------------------------------------------------
--------------------------------------------------------------------------------
--------------------------------------------------------------------------------

------------------------------------------------------------------------------

local function menuable_tap()

	local dnswind = nil			-- Window for dns-flows.

	local tap = Listener.new()		-- The network tap.

	--
	-- These are tables to gather and order some functionality.
	--
	xlate	= {}				-- Translation routines.
	log	= {}				-- Protocol-logging routines.

	--
	-- This collects packets transferred from one host to another.
	-- It is one-way only (for now), so 1.1.1.1 -> 2.2.2.2 will have
	-- a different stream than 2.2.2.2 -> 1.1.1.1.
	--
	local collector = {}

	----------------------------------------------------------------------
	-- Routine:	remove()
	--
	-- Purpose:	Remove the listener that otherwise will remain
	--		running indefinitely.
	--
	local function remove()
		tap:remove();
	end


	----------------------------------------------------------------------
	-- Routine:	streamsaver()
	--
	-- Purpose:	Save the recorded packet streams.
	--
	local function streamsaver()
		tap:streamsaver();
	end


	----------------------------------------------------------------------
	-- Routine:	dlgsaver()
	--
	-- Purpose:	Save the Packet Flow data to a user-specified file.
	--
	--		Status is saved in /tmp/pf.log because it isn't
	--		clear how to communicate errors to user otherwise.
	--
	--		Used by new_dialog() calls.
	--
	local function dlgsaver(newfile)

		log = io.open(SAVELOG,"w")
		log:write("\n\nSaving DNS-Flow data\n")

		--
		-- Save file must be specified.
		--
		if((newfile == nil) or (newfile == "")) then
			print("\nSave file for packet flows must be specified\n")
			log:write("\nSave file for packet flows must be specified\n")
			io.close(log)
			return
		end

		--
		-- Save file must not exist.
		--
		saver = io.open(newfile,"r")
		if saver ~= nil then
			print("\nPacket flow save file \"" ..  newfile .. "\" already exists\n")
			log:write("\nPacket flow save file \"" ..  newfile .. "\" already exists\n")
			io.close(log)
			return
		end

		--
		-- Now we'll create and open the save file.
		--
		saver = io.open(newfile,"w")
		if saver == nil then
			print("\nUnable to open packet flow save file \"" ..  newfile .. "\"\n")
			log:write("\nUnable to open packet flow save file \"" ..  newfile .. "\"\n")
			io.close(log)
			return
		end

		--
		-- Write each packet flow's info to the Packet Flow window.
		--
		for srcdst, pkt  in pairs(collector) do

			--
			-- Variables for output formatting.
			--
			local srcfmt = "%-15s\t"
			local dstfmt = "%-15s\t"
			local out

			saver:write("\n----------------------------------------------------------\n")

			saver:write("Originator || Target:  " .. tostring(srcdst) .. "\n\n")
			saver:write("Packets:\n")

			--
			-- IPv6 addresses are longer than IPv4 addresses, so
			-- we'll check for them and adjust the format if found.
			--
			-- THIS IS NOT PERFECT!!!  A preferable way of doing
			-- this would require Lua to support * functionality
			-- in string.format().  If this hasn't been done after
			-- all these years, I doubt they'd do it just for us.
			--
			if(string.find(srcdst, ':') ~= nil) then

				src, dst = string.match(srcdst, "(%S+) || (%S+)")

				if(string.find(src, ':') ~= nil) then
					len = string.len(src) + 1
					srcfmt = "%-" .. tostring(len) .. "s\t"
				end

				if(string.find(dst, ':') ~= nil) then
					dstfmt = "%-24s\t"

					len = string.len(dst) + 1
					dstfmt = "%-" .. tostring(len) .. "s\t"
				end
			end

			--
			-- Build the header and display it.
			--
			out = string.format(srcfmt .. dstfmt .. "%4s\t%s\n", "Source", "Destination", "Port", "Relative Time")

			saver:write(out)

			--
			-- Build the packet lines and display them.
			--
			for pnum, val  in pairs(pkt) do
				outfmt = srcfmt .. dstfmt .. "%-4s\t%7.5f\n"

out = string.format(outfmt, tostring(val.src), tostring(val.dst), tostring(val.port), reltime)
				saver:write(out)
			end

		end

		io.close(saver)

		log:write("\nfinished writing DNS Flow save file \"" ..  newfile .. "\"\n")
		io.close(log)

	end


	----------------------------------------------------------------------
	-- Routine:	loggit()
	--
	-- Purpose:	This function writes a message to the log file.
	--		The log file is opened and closed on each call,
	--		so it isn't particularly conservative of time.
	--
	function loggit(str)
		local logger			-- I/O object for logging.

		logger = io.open(LOGFILE,"a")
		logger:write(str)
		io.close(logger)
	end


	----------------------------------------------------------------------
	-- Routine:	tap.packet()
	--
	-- Purpose:	This function will be called once for each packet.
	--		Filter-specific handling occurs to do something with
	--		the data.
	--
	--		dns-flows divides the packets into sets that hold
	--		the packets flowing between a particular pair of
	--		hosts.  The packets are stored in a table that is
	--		implicitly sorted by the elapsed time from the start
	--		of packet capture.
	--
	--		Wireshark gathers lots of other data into pinfo, but
	--		few of those fields are being used by dns-flows.
	--		Maybe we'll make use of this extra data in the future.
	--
	function tap.packet(pinfo,tvb)

		local srcprt		-- Source port.
		local dstprt		-- Destination port.

		local pkt		-- Saved info for this packet.

		--------------------------------------------------
		--
		-- Set up some info about the packet.
		--

		--
		-- Get the source port.
		--
		srcprt = pinfo.src_port

		--
		-- Get the destination port.
		--
		dstprt = pinfo.dst_port

		--
		-- Filter out everything but packets to the  DNS.
		--
		if((srcprt ~= 53) and (dstprt ~= 53))
		then
			return
		end

		--
		-- Add the source and destination ports to the translation
		-- table, if they aren't there already.
		--
		if(ports[srcprt] == nil) then
			ports[srcprt] = tostring(srcprt)
		end
		if(ports[dstprt] == nil) then
			ports[dstprt] = tostring(dstprt)
		end

		--
		-- Get the text form of the ports.
		--
		srcprt = ports[srcprt]
		dstprt = ports[dstprt]

		--
		-- Find the appropriate source/destination group, even if this
		-- is a destination's response.  This includes the source port
		-- and destination port as well.  If there's already a
		-- collector table for dst/src, we'll use it.  If not, we can
		-- safely assume that src/dst should be used.
		--
		addrs = tostring(pinfo.dst) .. "/" .. tostring(pinfo.dst_port) .. " || " .. tostring(pinfo.src) .. "/" .. tostring(pinfo.src_port)
		if(collector[addrs] == nil) then
			addrs = tostring(pinfo.src) .. "/" .. tostring(pinfo.src_port) .. " || " .. tostring(pinfo.dst) .. "/" tostring(pinfo.dst_port)
		end

		--
		-- Save a few pieces of data from the pinfo.
		--
		pkt = {}
		pkt['pinfo']		= {}
		pkt['pinfo'].srcaddr	= pinfo.src
		pkt['pinfo'].dstaddr	= pinfo.dst
		pkt['pinfo'].srcport	= srcprt
		pkt['pinfo'].dstport	= dstprt
		pkt['pinfo'].reltime	= pinfo.rel_ts
		pkt['pinfo'].packetnum	= pinfo.number

		--
		-- Initialize our list of parsed protocols.
		--
		pkt.protocols = {}

		--
		-- Initialize the header index so we're starting at the top.
		--
		pkt.hdrindex = 0

		--
		-- Initialize a list if the source/destination collector
		-- entry doesn't exist yet.
		--
		if(collector[addrs] == nil) then
			collector[addrs] = {}
		end

		--
		-- Add this packet to our list of parsed packets.
		--
		table.insert(collector[addrs], pkt)


		--------------------------------------------------
		--
		-- Parse the packet contents.
		--

		--
		-- Get info from the ethernet part of the packet header.
		--
		ether.parse(pkt, tvb)

		--
		-- Get info from the IP header.
		--
		ip.parse(pkt, tvb)

		--
		-- Get the protocol from the UDP or TCP header.
		-- We're expecting this to be either UDP or TCP.
		--
		if(pkt['ip'].proto == PROTO_UDP) then
			udp.parse(pkt, tvb)
		else
			tcp.parse(pkt, tvb)
		end

		--
		-- At long last, we come to the DNS header.
		--
		dns.parse(pkt, tvb)


		--------------------------------------------------
		--
		-- Log some of the packet contents.
		--

		if(debug ~= 0) then
			local ostr

			loggit("\n----------------------------\n")

			loggit("src - <" .. tostring(pinfo.src) .. ">\t\tport - <" .. ports[pinfo.src_port] .. ">\n")
			loggit("dst - <" .. tostring(pinfo.dst) .. ">\t\tport - <" .. ports[pinfo.dst_port] .. ">\n")
			loggit("pnum - " .. pinfo.number .. "\trelative time - " .. pinfo.rel_ts .. "\n")

			ostr = string.format("%s/%s/%s/%s", tostring(pinfo.src), tostring(pinfo.dst), ports[pinfo.src_port], ports[pinfo.dst_port])
			loggit("pnum - " .. pinfo.number .. "\t" .. ostr .. "\n")
		end


		--
		-- Log the pieces of the header.
		--
		if(logpackets == 1) then
			ether.log(pkt)
			ip.log(pkt)
			udp.log(pkt)
		end

		dns.log(pkt)
	end


	----------------------------------------------------------------------
	-- Routine:	tap.streamsaver()
	--
	-- Purpose:	This function initiates the saving of the DNS streams
	--		streams to a file.  It creates a dialog box, passing
	--		it a reference to dlgsaver().  That routine gets and
	--		validates a filename for the new file, then saves the
	--		flow data to it.
	--
	function streamsaver(t)

		new_dialog("DNS Flows Saved", dlgsaver, "Enter Save File")

	end

	----------------------------------------------------------------------
	-- Routine:	tap.draw()
	--
	-- Purpose:	This function updates dns-flow's window with
	--		new data.  It is called once every few seconds.
	--
	function tap.draw(t)

		--
		-- Create the DNS Flows window if it hasn't been created.
		-- We'll also arrange to call remove() when window is closed.
		--
		if(dnswind == nil) then
			dnswind = TextWindow.new("DNS Flows")

			dnswind:set_atclose(remove)

			dnswind:add_button("Save Data", streamsaver)
		end

		--
		-- Clear the window contents.
		--
		dnswind:clear()

		--
		-- Write each dns-flow's info to the DNS Flow window.
		--
		for srcdst, pkt  in pairs(collector) do

			--
			-- Variables for output formatting.
			--
			local srcfmt = "%-15s\t"
			local dstfmt = "%-15s\t"
			local out

			dnswind:append("\n----------------------------------------------------------\n")

			dnswind:append("Originator || Target:  " .. tostring(srcdst) .. "\n\n")
			dnswind:append("Packets:\n")

			--
			-- IPv6 addresses are longer than IPv4 addresses, so
			-- we'll check for them and adjust the format if found.
			--
			-- THIS IS NOT PERFECT!!!  A preferable way of doing
			-- this would require Lua to support * functionality
			-- in string.format().  If this hasn't been done after
			-- all these years, I doubt they'd do it just for us.
			--
			if(string.find(srcdst, ':') ~= nil) then

				src, dst = string.match(srcdst, "(%S+) || (%S+)")

				if(string.find(src, ':') ~= nil) then
					len = string.len(src) + 1
					srcfmt = "%-" .. tostring(len) .. "s\t"
				end

				if(string.find(dst, ':') ~= nil) then
					dstfmt = "%-24s\t"

					len = string.len(dst) + 1
					dstfmt = "%-" .. tostring(len) .. "s\t"
				end
			end

			--
			-- Build the header and display it.
			--
			out = string.format(srcfmt .. dstfmt .. "%4s\t%s\n", "Source", "Destination", "Port", "Relative Time")

			dnswind:append(out)

			--
			-- Build the packet lines and display them.
			--
local foo = 0
if(foo == 1) then
dnswind:append("wakka wakka wakka")
end
			for pnum, val  in pairs(pkt) do

out = string.format(srcfmt .. dstfmt .. "%-4s\t%7.5f\n", tostring(val['pinfo'].srcaddr), tostring(val['pinfo'].dstaddr), tostring(val['pinfo'].dstport), val['pinfo'].reltime)
				dnswind:append(out)
			end

		end

	end

	----------------------------------------------------------------------
	-- Routine:	tap.reset()
	--
	-- Purpose:	This function will be called whenever a reset is
	--		needed, e.g. when reloading the capture file.
	--
	function tap.reset()

		if(dnswind ~= nil) then
			dnswind:clear()
		end

	end

	--
	-- Ensure that all existing packets are processed.
	--
	retap_packets()
end


--
-- Register the function to be called when the user selects the
-- Tools->Lua->Packet Flows menu
--
register_menu("GAWSEED/DNS Flows", menuable_tap, MENU_TOOLS_UNSORTED)


