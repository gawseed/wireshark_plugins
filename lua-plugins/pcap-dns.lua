--
-- pcap-dns.lua
--
--	This script is a plugin tap for tshark.  It collects information from
--	a set of DNS packet flows between pairs of hosts.  Each port used in
--	the communication is included, along with the elapsed time from the
--	beginning of the packet capture until that particular packet was sent.
--
--	This tap is an adaptation of the wireshark-dns-flows.lua plugin for
--	Wireshark.
--
--	Some debugging info may be written to a script-specific log file.
--	The filename is defined in the LOGFILE directory.  Set it as desired.
--
--	tshark calls tap.packet() to examine packet in turn.  tap.packet()
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
--			Queries store these fields:
--				query['name']		domain name
--				query['type']		query type
--				query['class']		query class
--				query['nameelts']	elements in domain name
--
--			Answers, NS rrecs, and additional rrecs store these
--			fields:
--				answer['name']		domain name
--				answer['type']		answer type
--				answer['class']		answer class
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
--		Major Caveats:
--			- dns_rrecdata() for NSEC3 rrecs should be checked to
--			  ensure that the next-owner and bitmaps fields are
--			  correctly saved.
--
--		Minor Caveats:
--			- No checksums are being calculated for any protocols.
--			  This code can be added, but it isn't there in this
--			  version.
--
--
-- Revision History
--	1.0 Initial revision.					190226
--

--******************************************************************************

--
-- Version information.
--
NAME	= "pcap-dns"
VERSNUM	= 1.0
VERS	= NAME .. " version: " .. VERSNUM

local argv = {...}				-- Arguments to the tap.

local tapinfo = {
	version	    = VERSNUM,
	author	    = "Wayne Morrison",
	description = NAME .. ":  tshark plugin to summarize and display DNS packets from PCAP data, created for the GAWSEED project, part of the CHASE program."
}


--******************************************************************************
--
-- Networking "constants" we might need.
--

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

----------------------------------------------------------

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
-- Table to allow organized port displays.
--
local portindices =
	{
		PORT_FTP,
		PORT_SSH,
		PORT_TELNET,
		PORT_SMTP,
		PORT_TIME,
		PORT_NAME,
		PORT_WHOIS,
		PORT_DNS,
		PORT_TFTP,
		PORT_HTTP,
		PORT_POP2,
		PORT_POP3,
		PORT_SFTP,
		PORT_NTP,
		PORT_IMAP,
		PORT_SNMP,
		PORT_SNMPTRAP,
		PORT_BGP,
		PORT_IMAP3,
		PORT_LDAP,
		PORT_HTTPS,
		PORT_SYSLOG,
		PORT_LDAPS,
		PORT_FTPSDATA,
		PORT_FTPS,
		PORT_TELNETS,
		PORT_IMAPS,
		PORT_POP3S,
		PORT_SSDP
	}


--
-- IANA provides guidelines for how port numbers should be used.  These are:
--		lowest well-known port		    0
--		highest well-known port		 1023
--		lowest registered port		 1024
--		highest registered port		49151
--		lowest dynamic port		49152
--		highest dynamic port		65535
--
-- Naturally, many systems take these guidelines as mere suggestions.
--
local WKPORT_LOW	=     0
local WKPORT_HIGH	=  1023
local REGPORT_LOW	=  1024
local REGPORT_HIGH	= 49151
local DYNPORT_LOW	= 49152
local DYNPORT_HIGH	= 65535

----------------------------------------------------------
--
-- DNS info.
--

--
-- QR codes from the DNS header.
--
local DNSQR_QUERY	= 0			-- DNS query.
local DNSQR_RESPONSE	= 1			-- DNS response.

--
-- Opcodes from the DNS header.
--
local DNSOP_QUERY	= 0			-- Standard DNS query.
local DNSOP_IQUERY	= 1			-- Inverse DNS query.
local DNSOP_STATUS	= 2			-- Server status query.

--
-- Response codes from the DNS header.
--
local DNSRCODE_NOERR		= 0		-- No error.
local DNSRCODE_FMTERR		= 1		-- Format error.
local DNSRCODE_SERVERFAIL	= 2		-- Server failure.
local DNSRCODE_NAMEERR		= 3		-- Name error.
local DNSRCODE_NOTIMPL		= 4		-- Query not implemented.
local DNSRCODE_REFUSED		= 5		-- Operation refused.

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
local QTYPE_APL		= 42		-- Address Prefix List
local QTYPE_DS		= 43		-- Delegation Signer
local QTYPE_SSHFP	= 44		-- SSH Key Fingerprint
local QTYPE_IPSECKEY	= 45		-- IPSECKEY
local QTYPE_RRSIG	= 46		-- RRSIG
local QTYPE_NSEC	= 47		-- Denial of Existence
local QTYPE_DNSKEY	= 48		-- DNSKEY
local QTYPE_DHCID	= 49		-- DHCP Client Identifier
local QTYPE_NSEC3	= 50		-- Hashed Auth'd Denial of Existence
local QTYPE_NSEC3PARAM	= 51		-- Hashed Auth'd Denial of Existence
				-- Numeric gaps here.
local QTYPE_HIP		= 55		-- Host Identity Protocol
				-- Numeric gaps here.
local QTYPE_SPF		= 99		-- Sender Policy Framework for E-Mail
local QTYPE_UINFO	= 100		-- IANA-Reserved
local QTYPE_UID		= 101		-- IANA-Reserved
local QTYPE_GID		= 102		-- IANA-Reserved
local QTYPE_UNSPEC	= 103		-- IANA-Reserved
				-- Numeric gaps here.
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
querytypes[QTYPE_APL]		= 'APL'
querytypes[QTYPE_DS]		= 'DS'
querytypes[QTYPE_SSHFP]		= 'SSHFP'
querytypes[QTYPE_IPSECKEY]	= 'IPSECKEY'
querytypes[QTYPE_RRSIG]		= 'RRSIG'
querytypes[QTYPE_NSEC]		= 'NSEC'
querytypes[QTYPE_DNSKEY]	= 'DNSKEY'
querytypes[QTYPE_DHCID]		= 'DHCID'
querytypes[QTYPE_NSEC3]		= 'NSEC3'
querytypes[QTYPE_NSEC3PARAM]	= 'NSEC3PARAM'
querytypes[QTYPE_HIP]		= 'HIP'
querytypes[QTYPE_SPF]		= 'SPF'
querytypes[QTYPE_UINFO]		= 'UINFO'
querytypes[QTYPE_UID]		= 'UID'
querytypes[QTYPE_GID]		= 'GID'
querytypes[QTYPE_UNSPEC]	= 'UNSPEC'
querytypes[QTYPE_TKEY]		= 'TKEY'
querytypes[QTYPE_TSIG]		= 'TSIG'
querytypes[QTYPE_IXFR]		= 'IXFR'
querytypes[QTYPE_AXFR]		= 'AXFR'
querytypes[QTYPE_MAILB]		= 'MAILB'
querytypes[QTYPE_MAILA]		= 'MAILA'
querytypes[QTYPE_ANY]		= 'ANY'
querytypes[QTYPE_ZXFR]		= 'ZXFR'


local DNS_HDR_LEN = 12					-- DNS header size

--
-- The smallest possible DNS query field size.  This has to be at least a
-- label length octet, label character, label null terminator, 2-bytes type
-- and 2-bytes class.
--
local MIN_QUERY_LEN = 7
 
--------------------------------------------------------------------
--
-- These port types are used to identify a packet's port type, noted in
-- the pinfo.port_type field.
--
-- The values were taken from epan/conversation.h

local WS_PORTTYPE_NONE		= 0
local WS_PORTTYPE_SCTP		= 1
local WS_PORTTYPE_TCP		= 2
local WS_PORTTYPE_UDP		= 3
local WS_PORTTYPE_DCCP		= 4
local WS_PORTTYPE_IPX		= 5
local WS_PORTTYPE_NCP		= 6
local WS_PORTTYPE_EXCHG		= 7
local WS_PORTTYPE_DDP		= 8
local WS_PORTTYPE_SBCCS		= 9
local WS_PORTTYPE_IDP		= 10
local WS_PORTTYPE_TIPC		= 11
local WS_PORTTYPE_USB		= 12
local WS_PORTTYPE_I2C		= 13
local WS_PORTTYPE_IBQP		= 14
local WS_PORTTYPE_BLUETOOTH	= 15
local WS_PORTTYPE_TDMOP		= 16
local WS_PORTTYPE_DVBCI		= 17
local WS_PORTTYPE_ISO14443	= 18
local WS_PORTTYPE_ISDN		= 19
local WS_PORTTYPE_H223		= 20
local WS_PORTTYPE_X25		= 21
local WS_PORTTYPE_IAX2		= 22
local WS_PORTTYPE_DLCI		= 23
local WS_PORTTYPE_ISUP		= 24
local WS_PORTTYPE_BICC		= 25
local WS_PORTTYPE_GSMTAP	= 26
local WS_PORTTYPE_IUUP		= 27
local WS_PORTTYPE_ENDVALUE	= WS_PORTTYPE_IUUP

local ws_porttypes =
{
	"SCTP",
	"TCP",
	"UDP",
	"DCCP",
	"IPX",
	"NCP",
	"Fibre Channel",
	"DDP AppleTalk",
	"FICON",
	"XNS IDP",
	"TIPC PORT",
	"USB",
	"I2C",
	"Infiniband QP",
	"BLUETOOTH",
	"TDMOP",
	"DVBCI",
	"ISO14443",
	"ISDN Channel",
	"H.223 Logical Channel",
	"X.25 Logical Channel",
	"IAX2 Call ID",
	"Frame Relay DLCI",
	"ISDN User Part CIC",
	"BICC Circuit",
	"GSMTAP",
	"IUUP"
}

 
------------------------------------------------------------------------------
-- 
-- Logging and debugging stuff.
-- 
--		(Is any of this is in current use?  Maybe delete it.)
--


local debug = 0					-- Flag for *some* logging.

local logpackets = 0				-- Flag to log packet contents
						-- after parsing.

local LOGFILE = "/tmp/z.dns-flows"		-- General log file.


local SAVELOG = "/tmp/dnsflows.log"		-- Log file for saving flows.

if(debug ~= 0) then
	local loggy = io.open(LOGFILE,"a")
	if loggy ~= nil then
		loggy:write("\npacket-flows.lua:  down in\n\n")
		io.close(loggy)
	end                
end

--
-- Flags for logging the different protocols.
--
local logether = false
local logip = false
local logtcp = false
local logudp = false
local logdns = false

--------------------------------------------------------------------
--
-- Global data needed by the tap.
--

local packetcnt		= 0		-- Number of packets we've seen.
local dnspacketcnt	= 0		-- Number of DNS packets we've seen.

local ips	= {}			-- Hash of src/dest counters.
local prots	= {}			-- Hash of protocol counters.

--
-- This collects packets.
--
local packets = {}

--
-- This collects packets transferred from one host to another.
-- It is one-way only (for now), so 1.1.1.1 -> 2.2.2.2 will have
-- a different stream than 2.2.2.2 -> 1.1.1.1.
--
local collector = {}

--------------------------------------------------------------------

--
-- The network tap.  This adds us to tshark's cloud of attendants.
-- Without this, none of this plugin would be called.
--
local tap


--******************************************************************************
-- Routines in this section initialize the tap.  They are modified by
-- command-line options.   
--


--------------------------------------------------------------------
--
-- Data for the command-line options.
--

local outfn	  = nil			-- Output filename.

local op_dnsflows = false		-- Collect DNS flows.
local op_nameelts = false		-- Check name elements in DNS queries.


--------------------------------------------------------------------
-- Routine:	inittap()
--
-- Purpose:	Initialize the tap and handle options.
--
--		Options recognized:
--			-save		Specify output file.
--
function inittap()

	local errs = 0					-- Error count.

	--
	-- Initialize some info about the tap.
	--
	set_plugin_info(tapinfo)

	--
	-- options:
	--	- save	store results to file
	--

	--
	-- Check our argument list for options.
	--
	for ind, arg in ipairs(argv) do

		--
		-- If we found -save, we'll get the output filename.
		--
		if(string.sub(arg, 0, 5) == "-save") then

			if(string.sub(arg, 0, 6) ~= "-save=") then
				print("-save must include output file; e.g., -save=/tmp/pcap.summary")
				errs = errs + 1
			else
				outfn = string.sub(arg, string.find(arg,"-save=") + 6)
			end

		--
		-- If we found -plog, we'll get the logging argument
		--
		elseif(string.sub(arg, 0, 5) == "-plog") then

			if(string.sub(arg, 0, 6) ~= "-plog=") then
				print("-plog must include output file; e.g., -plog=ip,dns")
				errs = errs + 1
			else
				local plog	     -- Option value.
				local prots = {}     -- Table of options values.

				--
				-- Get the value of the -plog option and
				-- convert it to lowercase.
				--
				plog = string.sub(arg, string.find(arg, "-plog=") + 6)
				plog = string.lower(plog)

				--
				-- Break the comma-separated values into
				-- a table of the various options.
				--
				string.gsub(plog, "(%a+)", function (w)
					table.insert(prots, w)
				end)

				--
				-- Set logging flags based on what the
				-- user requested.
				--
				for c,pv in ipairs(prots) do
					if(pv == 'ether')then logether = true end
					if(pv == 'ip')  then logip = true  end
					if(pv == 'tcp') then logtcp = true end
					if(pv == 'udp') then logudp = true end
					if(pv == 'dns') then logdns = true end
				end
			end

		--
		-- If we found -dnsflows, we'll get the logging argument
		--
		elseif(string.sub(arg, 0, 9) == "-dnsflows") then
			op_dnsflows = true

		--
		-- If we found -nameelts, we'll get the logging argument
		--
		elseif(string.sub(arg, 0, 9) == "-nameelts") then
			op_nameelts = true

		else
			--
			-- Unrecognized option; increase the error count.
			--
			print("unrecognized option:  \"" .. arg .. "\"")
			errs = errs + 1
		end
	end

	--
	-- Stop running if we hit any errors.
	--
	if(errs ~= 0) then
		print("\ninitialization errors; unable to continue")
		os.exit(4)
	end

	--
	-- If an output file was named, open the file.
	--
	if(outfn ~= nil) then
		sumfd = io.open(outfn, "w")
	end

	--
	-- Create the tap itself and open up for business.
	--
	tap = Listener.new()

end

--
-- Initialize the tap and module.
--
inittap()


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
-- Routine:	dns_addoffsets()
--
-- Purpose:	This function adds a set of offsets to a packet's offsets
--		table.  No existing entries in the packet's offsets table
--		are overwritten; if any are found, they are quietly dropped.
--
function dns_addoffsets(pkt, newoffsets)

	local offsets = pkt['dns'].offsets		-- Shorthand reference.
local count = 0

print("\ndns_addoffsets:  adding offsets:")
	--
	-- Add this atom to the end of each name in the offsets table.
	--
	for ind in pairs(newoffsets) do

		if(offsets[ind] == nil) then
print("\t\t\tadding - <" .. newoffsets[ind] .. ">")
			offsets[ind] = newoffsets[ind]
else
print("\t\t\tNOT adding - <" .. newoffsets[ind] .. ">")
		end

		count = count + 1

	end

print("\tchecked " .. count .. " offset entries\n")
end

----------------------------------------------------------------------
-- Routine:	dns_rrecdata()
--
-- Purpose:	This function parses data from an RREC.  The data is broken
--		out into various pieces, depending on the RREC type.
--
--		An "answer" list is passed in with these fields:
--			answer['type'] - Type of RREC data.
--			answer['len']  - Length of RREC data in bytes.
--			answer['data'] - The RREC data itself.
--
--		The returned list will depend on the RREC type:
--
--			NSEC3:
--				hashalg	  - hash algorithm
--				flags	  - flags
--				iters	  - iterations
--				saltlen	  - length of salt field
--				salt	  - salt field
--				hashlen	  - length of next-owner field
--				nextowner - next hashed owner name
--				bitmaps	  - type bitmaps
--
--		See the appropriate RFC for additional details of the fields.
--
function dns_rrecdata(pkt, hdrind, answer)
	local atype = answer['type']		-- Type of RREC data.
	local len   = answer['len']		-- Length of RREC data in bytes.
	local data  = answer['data']		-- The RREC data itself.

	local dtab  = {}			-- Hashed RREC data.
	local bitlen  = len * 8			-- Data length in bits.

	if(atype == QTYPE_A) then

		--
		-- The RREC data is an IPv4 address.
		-- We don't need to do anything with it, since it's already
		-- in the binary format.
		--

	elseif(atype == QTYPE_NSEC3) then
		local bind				-- Byte index.

		--
		-- range() calls with bind use bind as-is.
		-- bitfield() calls with bind must multiply bind by 8.
		--

		dtab['hashalg']	  = data:bitfield(  0,  8)
		dtab['flags']	  = data:bitfield(  8,  8)
		dtab['iters']	  = data:bitfield( 16, 16)
		dtab['saltlen']	  = data:bitfield( 32,  8)

		dtab['salt']	  = data:range(5, dtab['saltlen'])

		bind = 5 + dtab['saltlen']
		dtab['hashlen']	  = data:bitfield((bind * 8),  8)
		bind = bind + 1
		dtab['nextowner'] = data:range(bind, dtab['hashlen'])

		bind = bind + dtab['hashlen']
		dtab['bitmaps']	  = data:range(bind)

	elseif(atype == QTYPE_RRSIG) then

		local domain = ''		-- Domain under construction.
		local dnsdata = data		-- Buffer holding name.
		local ind = 18			-- Index into buffer.
		local offsets = {}		-- Name compression offsets.

		dtab['type']	  = data:bitfield(  0, 16)
		dtab['flags']	  = data:bitfield( 16,  8)
		dtab['iters']	  = data:bitfield( 23,  8)
		dtab['origttl']	  = data:bitfield( 32, 32)
		dtab['sigexpire'] = data:bitfield( 64, 32)
		dtab['sigincept'] = data:bitfield( 96, 32)
		dtab['keytag']	  = data:bitfield(128, 16)


print("\n")
print("\tdns_rrsigdata - RRSIG:")
print(string.format("--------------->  type      - 0x%04x   %d", dtab['type'], dtab['type']))
print(string.format("--------------->  flags     - 0x%02x   %d", dtab['flags'], dtab['flags']))
print(string.format("--------------->  iters     - 0x%02x   %d", dtab['iters'], dtab['iters']))
print(string.format("--------------->  origttl   - 0x%08x   %d", dtab['origttl'], dtab['origttl']))
print(string.format("--------------->  sigexpire - 0x%08x   %d", dtab['sigexpire'], dtab['sigexpire']))
print(string.format("--------------->  sigincept - 0x%08x   %d", dtab['sigincept'], dtab['sigincept']))
print(string.format("--------------->  keytag    - 0x%04x   %d", dtab['keytag'], dtab['keytag']))

		--
		-- Build the signer's domain name from the buffer.
		--
		while(42) do
			local len	-- Name length.

			--
			-- Get length of name element.
			--
			len = dnsdata:range(ind, 1):uint()

			--
			-- Move the index past the name-element length.
			--
			ind = ind + 1

			--
			-- Drop out if at the end of this name element.
			--
			if(len == 0) then
				break
			end

			--
			-- Get the name element and add it to domain.
			--
print(string.format("\t\t\t\tind - 0x%0x  %d\tlen - 0x%0x  %d", ind, ind, len, len))
			atom = dnsdata:range(ind, len):string()
print(string.format("\t\t\t\t\tdomain - <%s>\tatom - <%s>", domain, atom))
			domain = domain .. atom .. '.'

			--
			-- Add this atom to the end of each saved name in
			-- the offsets table.
			--
			for i in pairs(offsets) do
				offsets[(hdrind + i)] = offsets[i] .. "." .. atom
			end

			--
			-- Save this name element in the offsets table.
			--
			offsets[ind - 1] = atom

			--
			-- Move to the end of this name.
			--
			ind = ind + len

		end


-- . offsets index for RRSIG signers aren't properly done; the index numbers
--   are referring to the local data index, not the packet index
-- . it *looks* like RRSIGs are now parsed, but unsure about signature
-- . ns rrec 3 in test data still finding unknown name offset that's unrelated
--   to the rrsig data


		--
		-- Strip off the root domain's dot and save the name.
		-- We'll also add this name's offset table to the packet's
		-- table.
		--
		dtab['signername'] = string.gsub(domain, '%.+$', '')
print("\n\nthe offsets are broken here!!!  the list offsets only refer to\nindex into *local* table!!!\n\n")
		dns_addoffsets(pkt, offsets)

		--
		-- Get the signature.
		--
		dtab['signature'] = data:range(ind, (len - ind))
print(string.format("--------------->  siglen    - %d", (len - ind)))

print(string.format("--------------->  signer    - <%s>", dtab['signername']))
print(string.format("--------------->  signature - %s", dtab['signature']))

print("\n")

	end

	return(dtab)
end


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
function dns_getanswer(pkt, rrecdata, ind, nsrrflag)
-- {

	local offsets = {}
	local UNKNOWN_OFFSET = '<<<unknown name offset>>>'

	local startind = ind	-- Copy of starting index.

	local len		-- Name length.
	local domain = ''	-- Domain in answer.
	local answer = {}	-- Answer table for each rrec.

local rrecstart
local f
rrecstart = 0x2a + ind
f = string.format("---> %d:  dns_getanswer(%d, 0x%0x)\t\trecord start - 0x%02x", pkt['pinfo'].packetnum, ind, ind, rrecstart)
print(f)

	--
	-- Grab each piece of the domain name and add it to our name buffer.
	-- We'll handle both inline names and names that are stored with
	-- DNS compression.
	--
	while(42) do
		local len	-- Name length.
print("---> " .. pkt['pinfo'].packetnum .. ":\t\t\t\t\tnew element")

-- print(string.format("------> %d:\t\t\t\t\t\tind 0 - %d, 0x%0x", pkt['pinfo'].packetnum, ind, ind))
		--
		-- Get the length of the name element.
		--
		len = rrecdata:range(ind, 1):uint()

		--
		-- Stop looking at name elements if at the end of the list.
		--
		if(len == 0) then
			break
		end

-- print(string.format("------> %d:\t\t\t\t\t\tind 1 - %d, 0x%0x", pkt['pinfo'].packetnum, ind, ind))
		--
		-- If this is a compressed name, we'll look it up in the table
		-- of known offsets.  Otherwise, we'll just grab the entry.
		--
		if(len == 0xc0) then
			local bitind	-- Bit index for offset.
			local offset	-- Name offset for compression.

			--
			-- This is a compressed name, so we'll get the
			-- name using the offset reference.
			--
			-- Get the bit position of the name offset.
			--
			bitind = (ind * 8) + 2

			offset  = rrecdata:bitfield(bitind, 14)
local f
f = string.format("---> %d:  compressed element", pkt['pinfo'].packetnum)
print(f)
f = string.format("------> %d:  offset - %d\t0x%02x\tpacket loc - 0x%02x", pkt['pinfo'].packetnum, offset, offset, (0x2a + offset))
print(f)

print("offsets table:")
-- for k in pairs(offsets) do
local wooves = pkt['dns'].offsets
for k in pairs(wooves) do
print(string.format("\t%d 0x%02x:\t<%s>", k, k, wooves[k]))
end
print("end of offsets table")
-- print(string.format("------> %d:\t\t\t\t\t\tind 2 - %d, 0x%0x", pkt['pinfo'].packetnum, ind, ind))

			--
			-- Get the name element.
			--
			--	WARNING:  If an RREC can reference an offset
			--		  in itself, then this won't work.
			--		  I don't know if it's legal for an
			--		  RREC to self-reference.
			--		  We'll find out...
			--
--			atom = offsets[offset]
			atom = pkt['dns'].offsets[offset]
			if(atom == nil) then

local unkstr
unkstr = string.format("------> %d:  unknown offset - %d\t0x%02x\t\t\t0x%02x", pkt['pinfo'].packetnum, offset, offset, (0x2a + offset))
print(unkstr)

				atom = UNKNOWN_OFFSET
else
print("---> " .. pkt['pinfo'].packetnum .. ":\treferenced atom - <" .. atom .. ">")

			end

			--
			-- Move past the compression index.
			--
-- print(string.format("------> %d:\t\t\t\t\t\tind 3 - %d, 0x%0x", pkt['pinfo'].packetnum, ind, ind))
			ind = ind + 2
-- print(string.format("------> %d:\t\t\t\t\t\tind 4 - %d, 0x%0x", pkt['pinfo'].packetnum, ind, ind))

		else

-- print(string.format("---> %d:  element len - %d\t0x%02x", pkt['pinfo'].packetnum,len,len))

-- print(string.format("------> %d:\t\t\t\t\t\tind 5 - %d, 0x%0x", pkt['pinfo'].packetnum, ind, ind))
			--
			-- This isn't a compressed name, so we'll build the
			-- name from the data itself.
			--
			-- Move past the length to the name.
			--
			ind = ind + 1

-- print(string.format("------> %d:\t\t\t\t\t\tind 6 - %d, 0x%0x", pkt['pinfo'].packetnum, ind, ind))
			--
			-- Get the name element.
			--
print("---> " .. pkt['pinfo'].packetnum .. ":  ind - " .. ind .. "\tlen - " .. len .. "\tdomain - <" .. domain .. ">")
			atom = rrecdata:range(ind, len):string()
print("---> " .. pkt['pinfo'].packetnum .. ":\tatom - <" .. atom .. ">")

			--
			-- Move to the end of this name.
			--
-- print(string.format("------> %d:\t\t\t\t\t\tind 7 - %d, 0x%0x", pkt['pinfo'].packetnum, ind, ind))
			ind = ind + len
-- print(string.format("------> %d:\t\t\t\t\t\tind 8 - %d, 0x%0x", pkt['pinfo'].packetnum, ind, ind))

		end

		--
		-- Add the name element to the domain.
		--
--		local ret
--		ret = string.match(atom, "%.$")
-- print("---------------> atom - <" .. atom .. ">\t" .. tostring(ret) .. "\n")
--		if(ret == nil) then
		if(string.match(atom, "%.$") == nil) then
			domain = domain .. atom .. '.'
		else
			domain = domain .. atom
		end

		--
		-- Add this atom to the end of each name in the offsets table.
		--
		for i in pairs(offsets) do
			offsets[i] = offsets[i] .. "." .. atom
		end

		--
		-- Save this name element in the local offsets table.
		--
		offsets[ind - 1] = atom

	end

-- print(string.format("------> %d:\t\t\t\t\t\tind 10 - %d, 0x%0x", pkt['pinfo'].packetnum, ind, ind))


	--
	-- Fold the local offsets table into the packet's offset table.
	--
	dns_addoffsets(pkt, offsets)

--
-- RREC data must be parsed to get names for compression table.
--

-- 
-- It appears that the problem is with saving offset names when the names are
-- partially given as a name and partially given as a label.  The correct
-- offset doesn't get saved into the offsets table.
-- 



	--
	-- Strip off the root domain's dot.
	--
	domain = string.gsub(domain, '%.+$', '')

	if(offsets[startind] == nil) then
		offsets[startind] = domain
local ot
ot = string.format("-----> adding <%s> to offset %d   0x%x", domain, startind, startind)
print(ot)
else
local ot
ot = string.format("-----> NOT adding <%s> to offset %d   0x%x", domain, startind, startind)
print(ot)
	end

	--
	-- Use the root domain if there wasn't anything found.
	--
	if(domain == '') then
		domain = '.'
--		ind = ind + 1
	end

print("------> " .. pkt['pinfo'].packetnum .. ":  final domain - " .. domain .. ">")

	--
	-- Save the domain name and query type in the answer.
	--
	answer['name'] = domain

-- print(string.format("------> %d:\t\t\t\t\t\tind 11 - %d, 0x%0x", pkt['pinfo'].packetnum, ind, ind))

-- print("------> " .. pkt['pinfo'].packetnum .. ":  getting  query type\tind - " .. ind .. "\n")
	answer['type']  = rrecdata:range(ind, 2):uint()
print("------> " .. pkt['pinfo'].packetnum .. ":  query type\t" .. answer['type'] .. "\t" .. querytypes[answer['type']])

-- trying to find why some NS rrecs aren't being properly handled.
-- packet 99 and packet 144 in walnutdump are sometimes not working.
-- it seems that the index is sometimes off by 1.

	--
	-- Get the rest of the resource record and add the fields to the answer
	-- table.  If any query types have special answer formats, they'll be
	-- recognized here.
	-- We'll also move the index pointer past this answer.
	--
	if(answer['type'] == QTYPE_OPT) then

print("------> " .. pkt['pinfo'].packetnum .. ":  getting rest of OPT rrec\n")
		answer['class'] = ''
		answer['ttl']	= ''
		answer['len']	= ''
		answer['data']	= rrecdata:range((ind + 2), 8)

		ind = ind + 2 + 8

-- print(string.format("------> %d:\t\t\t\t\t\tind 12 - %d, 0x%0x", pkt['pinfo'].packetnum, ind, ind))

	else
		local tmpdata			-- Temporary data holder.

print("------> " .. pkt['pinfo'].packetnum .. ":  non-OPT rrec - " .. answer['type'] .. "\t" .. querytypes[answer['type']] .. "\n")
-- if(nsrrflag == 1) then ind = ind + 1 end

		answer['class'] = rrecdata:range((ind + 2), 2):uint()
		answer['ttl']	= rrecdata:range((ind + 4), 4):uint()
		answer['len']	= rrecdata:range((ind + 8), 2):uint()

-- print("------> " .. pkt['pinfo'].packetnum .. ":  rrecdata:range(" .. (ind + 10) .. ", " .. answer['len'] .. ")")

local out
local qstr
local qtyp
qtyp = answer['type']
qstr = querytypes[qtyp]
out = string.format("------------> %d:  domain  - %s", pkt['pinfo'].packetnum, domain)
print(out)
out = string.format("------------> %d:  type    - %d\t0x%02x\t%s", pkt['pinfo'].packetnum, qtyp, qtyp, qstr)
print(out)
out = string.format("------------> %d:  class   - %d\t0x%02x", pkt['pinfo'].packetnum, answer['class'], answer['class'])
print(out)
out = string.format("------------> %d:  ttl     - %d\t0x%04x", pkt['pinfo'].packetnum, answer['ttl'], answer['ttl'])
print(out)
out = string.format("------------> %d:  len     - %d\t0x%02x", pkt['pinfo'].packetnum, answer['len'], answer['len'])
print(out)

		ind = ind + 10
		answer['data'] = rrecdata:range(ind, answer['len'])
		answer['data'] = dns_rrecdata(pkt, ind, answer)

-- print(string.format("------> %d:\t\t\t\t\t\tind 13 - %d, 0x%0x", pkt['pinfo'].packetnum, ind, ind))
		ind = ind + answer['len']
-- print(string.format("------> %d:\t\t\t\t\t\tind 14 - %d, 0x%0x", pkt['pinfo'].packetnum, ind, ind))

	end

	--
	-- Return the answer to our caller.
	--
local f
f = string.format("------> %d:  returning from dns_getanswer(%d, 0x%0x)\n", pkt['pinfo'].packetnum, ind, ind)
print(f)
	return answer, ind

end

-- }

-- offsets



----------------------------------------------------------------------
-- Routine:	dns.parse()
--
-- Purpose:	This function saves the required fields from the DNS portion
--		of the packet.
--
function dns.parse(pkt,tvb)

	local len			-- General length field.
	local offsets = {}		-- Local table of offsets/domains.

	local queries = {}		-- List of queries.

	local dnsdata			-- DNS portion (hdr and data) of packet.
	local dnslen			-- Length of DNS portion of the packet.

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
	dnslen = len

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
	pkt['dns'].offsets = {}

	--
	-- Get a reference to the DNS portion of the packet and set a byte
	-- index to point after the DNS header.
	--
	dnsdata = tvbr
	ind = DNS_HDR_LEN

	--
	-- Build each query into a domain name and put it on the queries list.
	--
	if(pkt['dns'].qdcount > 1) then
		print("\n")
		print("WARNING:  This packet is likely to break on name compression.")
		print("          This is due to multiple queries in a single DNS packet.")
		print("\n")
	end

	--
	-- Build each query into a domain name and put it on the queries list.
	--
	cnt = pkt['dns'].qdcount
	while(cnt > 0) do

		local query = {}	-- Query table for each query.
		local domain = ''	-- Domain under construction.
		local qtype		-- Query type.
		local qclass		-- Query class.
		local eltcnt = 0	-- Count of name elements.

		--
		-- Grab each piece of the domain name and add it to our
		-- name buffer.
		--
		while(42) do
			local len	-- Name length.

			--
			-- Get length of name element.
			--
			len = dnsdata:range(ind, 1):uint()

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
			-- Increment the count of name elements.
			--
			eltcnt = eltcnt + 1

			--
			-- Get the name element and add it to domain.
			--
			atom = dnsdata:range(ind, len):string()
			domain = domain .. atom .. '.'

			--
			-- Add this atom to the end of each saved name in
			-- the offsets table.
			--
			--	WARNING:  This assumes that there's only
			--		  ever one query in a packet.
			--		  This will break if multiple queries
			--		  are ever found in a single packet.
			--
			for i in pairs(offsets) do
				offsets[i] = offsets[i] .. "." .. atom
			end

			--
			-- Save this name element in the offsets table.
			--
--			offsets[(DNS_HDR_LEN + ind - 1)] = atom
offsets[ind - 1] = atom

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
		qtype  = dnsdata:range(ind, 2):uint()
		qclass = dnsdata:range((ind + 2), 2):uint()

		--
		-- Strip off the root domain's dot.
		--
			domain = string.gsub(domain, '%.+$', '')

		--
		-- Add the query fields to the query table.
		--
		query['name']  = domain
		query['type']  = qtype
		query['class'] = qclass
		query['nameelts'] = eltcnt

		--
		-- Save the query to our list of queries.
		--
		table.insert(queries, query)

local f
f = string.format("---> %d:  query - <%s>\t%d\t%d\t%d", pkt['pinfo'].packetnum, domain, qtype, qclass, eltcnt)
print(f)

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
		local answers = {}			-- List of answers.

local anscnt = 0
		while(cnt > 0) do
			local ans			-- Answer rrec.

print("------------------------------------> ANSWER " .. anscnt)
anscnt = anscnt + 1
			ans, ind = dns_getanswer(pkt, dnsdata, ind, 0)
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
		local answers = {}			-- List of answers.

local nsrcnt = 0
		while(cnt > 0) do
			local ans			-- Answer rrec.

print("------------------------------------> NS RREC " .. nsrcnt)
nsrcnt = nsrcnt + 1
			ans, ind = dns_getanswer(pkt, dnsdata, ind, 1)
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
		local answers = {}			-- List of answers.

local addcnt = 0
		while(cnt > 0) do
			local ans			-- Answer rrec.

print("------------------------------------> ADDL RREC " .. addcnt)
addcnt = addcnt + 1
			ans, ind = dns_getanswer(pkt, dnsdata, ind, 0)
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
	loggit("\ttransid    - " .. tostring(pkt['dns'].transid) ..  "\t(" .. out .. ")\n")

	out = (((pkt['dns'].qrcode) == DNSQR_QUERY) and 'query') or 'response'
	loggit("\tqrcode     - " .. tostring(pkt['dns'].qrcode) ..  "\t\t(" .. out .. ")\n")
	--
	-- Translate the numeric opcode into a string.
	--
	out = "(reserved!)"
	if(pkt['dns'].opcode == DNSOP_QUERY) then
		out = "(standard query -- QUERY)"
	elseif(pkt['dns'].opcode == DNSOP_IQUERY) then
		out = "(inverse query -- IQUERY)"
	elseif(pkt['dns'].opcode == DNSOP_STATUS) then
		out = "(server status request -- STATUS)"
	end

	loggit("\topcode     - " .. tostring(pkt['dns'].opcode) ..  "\t\t" .. out .. "\n")

	loggit("\taaflag     - " .. tostring(pkt['dns'].aaflag) ..  "\n")

	loggit("\ttcflag     - " .. tostring(pkt['dns'].tcflag) ..  "\n")

	loggit("\trdflag     - " .. tostring(pkt['dns'].rdflag) ..  "\n")

	loggit("\traflag     - " .. tostring(pkt['dns'].raflag) ..  "\n")

	--
	-- Translate the numeric rcode into a string.
	--
	out = "(reserved)"
	if(pkt['dns'].rcode == DNSRCODE_NOERR) then
		out = "(no error)"
	elseif(pkt['dns'].rcode == DNSRCODE_FMTERR) then
		out = "(format error)"
	elseif(pkt['dns'].rcode == DNSRCODE_SERVERFAIL) then
		out = "(server error)"
	elseif(pkt['dns'].rcode == DNSRCODE_NAMEERR) then
		out = "(name error)"
	elseif(pkt['dns'].rcode == DNSRCODE_NOTIMPL) then
		out = "(not-implemented error)"
	elseif(pkt['dns'].rcode == DNSRCODE_REFUSED) then
		out = "(refused)"
	end
	local rcodestr = string.format("%0x", pkt['dns'].rcode)
	loggit("\trcode      - " .. rcodestr ..  "\t\t" .. out .. "\n")

	loggit("\tqdcount    - " .. tostring(pkt['dns'].qdcount) ..  "\n")
	loggit("\tancount    - " .. tostring(pkt['dns'].ancount) ..  "\n")
	loggit("\tnscount    - " .. tostring(pkt['dns'].nscount) ..  "\n")
	loggit("\tarcount    - " .. tostring(pkt['dns'].arcount) ..  "\n")
	loggit("\n")

	--
	-- Display the list of questions.
	--
	if(pkt['dns'].qdcount > 0) then
		loggit("\tquestions:\n")

		for ind, qry in ipairs(pkt['dns'].queries) do
			qcl = dns.qclass2str(qry['class'])

			qtstr = querytypes[qry['type']]
			if(qtstr == nil) then
				qtstr = tostring(qry['type'])
			end

			loggit("\t\t" .. qry['name'] .. "\t" .. qtstr .. "\t" .. qcl .. "\n")
		end
	else
		loggit("\tno questions\n")
	end

	--
	-- Display the list of answers.
	--
	if(pkt['dns'].ancount > 0) then
		loggit("\n")
		loggit("\tanswers:\n")

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
		loggit("\tno answers\n")
	end

	--
	-- Display the list of NS rrecs.
	--
	if(pkt['dns'].nscount > 0) then
		loggit("\n")
		loggit("\tns rrecs:\n")

		for ind, nsrr in ipairs(pkt['dns'].nsrrecs) do
			qcl = dns.qclass2str(nsrr['class'])

			qtstr = querytypes[nsrr['type']]
			if(qtstr == nil) then
				qtstr = tostring(nsrr['type'])
			end

--			loggit("\t\t" .. nsrr['name'] .. "\t" .. qtstr .. "\t" .. qcl .. "\t" .. tostring(nsrr['data']) .. "\n")
			loggit("\t\t" .. nsrr['name'] .. "\t" .. qtstr .. "\t" .. qcl .. "\n")
		end
	else
		loggit("\n")
		loggit("\tno ns rrecs\n")
	end

	--
	-- Display the list of additional rrecs.
	--
	if(pkt['dns'].arcount > 0) then
		loggit("\n")
		loggit("\tadditional rrecs:\n")

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
		loggit("\tno additional rrecs\n")
	end

	loggit("\n")

end

--------------------------------------------------------------------------------
--------------------------------------------------------------------------------
--------------------------------------------------------------------------------

------------------------------------------------------------------------------


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

out = string.format(srcfmt .. dstfmt .. "%-4s\t%7.5f\n", tostring(val.src), tostring(val.dst), tostring(val.port), val.reltime)
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
--		packet-flows divides the packets into sets that hold
--		the packets flowing between a particular pair of
--		hosts.  The packets are stored in a table that is
--		implicitly sorted by the elapsed time from the start
--		of packet capture.
--
--		Wireshark gathers lots of other data into pinfo, but
--		few of those fields are being used by dns-flows.
--		Maybe we'll make use of these extra data in the future.
--
function tap.packet(pinfo,tvb)

	local srcprt		-- Source port.
	local dstprt		-- Destination port.

	local pkt		-- Saved info for this packet.

	--
	-- Keep track of the total number of packets we've seen.
	--
	packetcnt = packetcnt + 1

--
-- For debugging, only look at packet numbers 87 - 148.
--
-- if((pinfo.number < 87) or (pinfo.number > 148)) then
-- if(pinfo.number == 88) then
-- 	print("\n\n\nexitting on packet 88\n\n\n")
-- 	os.exit(0)
-- end
-- if((pinfo.number < 87) or (pinfo.number > 88)) then
-- 	return
-- end

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
	-- Keep track of the total number of DNS packets we've seen.
	--
	dnspacketcnt = dnspacketcnt + 1

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
	table.insert(packets, pkt)

	--
	-- Add this packet to our address-based list of parsed packets.
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
	if(logether == true) then ether.log(pkt)	end
	if(logip    == true) then ip.log(pkt)		end
	if(logtcp   == true) then tcp.log(pkt)		end
	if(logudp   == true) then udp.log(pkt)		end
	if(logdns   == true) then dns.log(pkt)		end

end


----------------------------------------------------------------------
-- Routine:	tap.draw()
--
-- Purpose:	This function reports the results of the packet recording.
--
function tap.draw(t)

	print("")
	print("-------------------------------------------------------------------------------")
	print("")

	--
	-- Display the DNS flows.
	--
	if(op_dnsflows == true) then

		if(#collector == 0) then
			print("nothing in op_dnsflows\n")
		else
			print("dns flows:")
		end


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

			loggit("\n----------------------------------------------------------\n")

			loggit("Originator || Target:  " .. tostring(srcdst) .. "\n\n")
			loggit("Packets:\n")

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

			loggit(out)

			--
			-- Build the packet lines and display them.
			--
			for pnum, val  in pairs(pkt) do

out = string.format(srcfmt .. dstfmt .. "%-4s\t%7.5f\n", tostring(val['pinfo'].srcaddr), tostring(val['pinfo'].dstaddr), tostring(val['pinfo'].dstport), val['pinfo'].reltime)
				loggit(out)
			end

		end

	else
		print("no DNS flows\n")
	end


	--
	-- Check name elements in DNS queries.
	--
	if(op_nameelts == true) then
		if(#packets == 0) then
			print("empty packets table for name elements\n")
		else
			print("name elements in DNS packets:")
		end

		for ind, pkt in ipairs(packets) do

			if(pkt['dns'].qrcode == DNSQR_QUERY) then
				local qtab = pkt['dns'].queries[1]
				if(qtab['nameelts'] > 3) then

local out
out = string.format("%d:  %d\t%-16s  %-16s  %-4s  %8.5f\t%d/%d/%d/%d",ind, pkt['pinfo'].packetnum, tostring(pkt['pinfo'].srcaddr), tostring(pkt['pinfo'].dstaddr), tostring(pkt['pinfo'].dstport), pkt['pinfo'].reltime, pkt['dns'].qdcount, pkt['dns'].ancount, pkt['dns'].nscount, pkt['dns'].arcount)
--					print(out)

--				query['name']		domain name
--				query['type']		query type
--				query['class']		query class
--				query['nameelts']	elements in domain name

				for key in pairs(pkt['dns'].queries) do
					local qtab = pkt['dns'].queries[key]
					out = string.format("\t%s\t%s\t%s\t%d", qtab['name'], qtab['type'], qtab['class'], qtab['nameelts'])
					print(out)
			end
			print("")

				end
			end

		end
		if(#packets ~= 0) then
			print("done")
		end

	else
		print("no name elements in DNS queries")
	end

end

----------------------------------------------------------------------
-- Routine:	tap.reset()
--
-- Purpose:	This function will be called whenever a reset is
--		needed; e.g., when reloading the capture file.
--
function tap.reset()

end

