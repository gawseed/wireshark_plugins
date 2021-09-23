--
-- pcap-summarizer.lua
--
--	This script is a plugin for tshark.  It collects a set of data from
--	each packet and saves some of it as needed.  Once all the packets
--	have been handled, the collected data are summarized and displayed.
--
--	The important routines in this file are:
--
--		tap.packet()	Called once for each packet.  This is where
--				the data are collected.
--
--		tap.draw()	Called after all packets are examined.  This
--				is where the data are displayed.
--
--	These routines are the heart of a *shark plugin.
--
--	Rudimentary, useful info about *shark plugins/taps is available here:
--		https://wiki.wireshark.org/Lua/Taps
--
--
--	When adding a new summary to this file, three new routines must be
--	added.  These are all grouped in different tables as a means of
--	organizing the routines.  The tables are:
--
--		data{} -	The routines in this table gather summary
--				data for display.
--				These routines are called by tap.packet().
--
--		show{} -	The routines in this table display the data
--				to an interactive user.
--				These routines are called by tap.draw().
--
--		log{} -		The routines in this table write the data to
--				a user-specified summary file.  Summary files
--				are intended to be read by other programs,
--				not necessarily by a user.
--				These routines are called by the corresponding
--				show{} routines.
--
--	Many of the current summaries use the same name for each particular 
--	summarization in the three tables.
--
--	To see examples of these routines, look at data.protocounts(),
--	show.protocounts(), and log.protocounts.
--
--
--	There are a bunch of networking-related values defined at the top
--	of the file.  These aren't used in the early versions of this script,
--	but will be used later.
--
--
--	This script was created for the GAWSEED project, part of the CHASE
--	program.
--
--
--	Questions:
--		- data.protocounts(srcport, destport) increments use counts
--		  for the source and destination ports of a packet.  If the
--		  two ports are the same (e.g., port 22) should it increment
--		  the SSH port once or twice?
--
--
-- Revision History
--	1.0	Initial revision.					190212
--	1.1	Give the number of packets seen in a set of		190212
--		"well-known" protocols.
--	1.2	Give the number of unique source addresses and		190213
--		destination addresses seen.
--		Give the number of packets with a particular source
--		address or destination address.
--	1.3	Give the number of unique srcaddr/dest port pairs	190213
--		to have been contacted.
--	1.4	Give the number of packets in a conversation.		190215
--	1.5	Give the number of low-to-low port conversations	190218
--		and high-to-high port conversations.
--	1.6	Added initialization routine, -save option recognized.	190218
--	1.7	Added logging of summary data to a user-specified file.	190218
--	1.8	Changed field separator to '|' for saved files.		190219
--		Renamed program to pcap-summarizer.			190219
--	1.9	Add list of packets in a CIDR address prefix size.	190223
--	1.10	Allow display of time-series of CIDR address prefixes.	190225
--		The -timedir and -slotlen options were also added.
--	1.11	Added DNS query-type strings for standardized display.	190226
--

--******************************************************************************

--
--	The following summaries are provided by this script:
--		- total count of packets
--		- number of packets seen in a set of "well-known" protocols
--		- number of unique source addresses seen
--		- number of unique destination addresses seen
--		- number of packets with a particular source address
--		- number of packets with a particular destination address
--		- number of packets sent by a particular source address
--		  to a particular destination port
--		- number of packets in a conversation
--		- number of low-to-low port conversations
--		- number of high-to-high port conversations
--		- number of packets in each CIDR address prefix of a
--		  specified length
--		- build time-series CSV files of packets in each CIDR address
--		  prefix
--

--******************************************************************************

--
-- Version information.
--
NAME   = "pcap-summarizer"
VERSNUM   = 1.11
VERS   = NAME .. " version: " .. VERSNUM

local argv = {...}				-- Arguments to the tap.

local tapinfo = {
	version	    = VERSNUM,
	author	    = "Wayne Morrison",
	description = "tshark plugin to summarize and display PCAP data, created for the GAWSEED project, part of the CHASE program."
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

----------------------------------------------------------
--
-- DNS info.
--


--
-- DNS Query types.
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
local QTYPE_AAAA	= 28		-- IPv6 Address.
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
  
 
local DNS_HDR_LEN	= 12		-- DNS header size.

--
-- The smallest possible DNS query field size.  This has to be at least a
-- label length octet, label character, label null terminator, 2-bytes type
-- and 2-bytes class.
--
local MIN_QUERY_LEN = 7


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

 
--------------------------------------------------------------------
--
-- Logging and debugging stuff.
--
--		(None of this is in current use.  Maybe delete it.)
--

local debug = 0					-- Flag for *some* logging.

local logpackets = 0                            -- Flag to log packet contents
						-- after parsing.

local LOGFILE = "/tmp/z.pcap-summary"		-- General log file.

local SAVELOG = "/tmp/pf.log"			-- Log file for saving flows.

--------------------------------------------------------------------
--
-- Global data needed by the tap.
--

local packetcnt	= 0			-- Number of packets we've seen.

local rootdot	= 1			-- Add root '.' to FQDNs.

local ts_first	= nil			-- Earliest timestamp in pcap.
local ts_last	= nil			-- Latest timestamp in pcap.

local ips	= {}			-- Hash of src/dest counters.
local prots	= {}			-- Hash of protocol counters.

--
-- Table of protocol-use counts.
--
local protocounts = {}
	protocounts[PORT_FTP]		= 0
	protocounts[PORT_SSH]		= 0
	protocounts[PORT_TELNET]	= 0
	protocounts[PORT_SMTP]		= 0
	protocounts[PORT_TIME]		= 0
	protocounts[PORT_NAME]		= 0
	protocounts[PORT_WHOIS]		= 0
	protocounts[PORT_DNS]		= 0
	protocounts[PORT_TFTP]		= 0
	protocounts[PORT_HTTP]		= 0
	protocounts[PORT_POP2]		= 0
	protocounts[PORT_POP3]		= 0
	protocounts[PORT_SFTP]		= 0
	protocounts[PORT_NTP]		= 0
	protocounts[PORT_IMAP]		= 0
	protocounts[PORT_SNMP]		= 0
	protocounts[PORT_SNMPTRAP]	= 0
	protocounts[PORT_BGP]		= 0
	protocounts[PORT_IMAP3]		= 0
	protocounts[PORT_LDAP]		= 0
	protocounts[PORT_HTTPS]		= 0
	protocounts[PORT_SYSLOG]	= 0
	protocounts[PORT_LDAPS]		= 0
	protocounts[PORT_FTPSDATA]	= 0
	protocounts[PORT_FTPS]		= 0
	protocounts[PORT_TELNETS]	= 0
	protocounts[PORT_IMAPS]		= 0
	protocounts[PORT_POP3S]		= 0
	protocounts[PORT_SSDP]		= 0

local srccount = 0		-- Count of unique sources.
local dstcount = 0		-- Count of unique destinations.

local srccounts	= {}		-- Table of source-address counts.
local dstcounts	= {}		-- Table of destination-address counts.

local srcdports	= {}		-- Table of srceaddr/destport counts.

local convocounts = {}		-- Table of conversations.

local lowlowcounts = {}		-- Table of low-to-low port conversations.
local highhighcounts = {}	-- Table of high-to-high port conversations.

local srcprefixcounts = {}	-- Table of source-address-prefix counts.
local dstprefixcounts = {}	-- Table of destination-address-prefix counts.

local srcprefixtimes = {}	-- Table of source-address-prefix times.
local dstprefixtimes = {}	-- Table of destination-address-prefix times.

local timeind	   = 0		-- Table index for time-based data.
local nexttimeslot = 0		-- Next time slot to watch for.

local slotlength   = 60		-- Number of seconds in each time slot.
local MIN_TIMESLOT = 10		-- Minimum time-slot length.

--
-- This collects information about packets transferred between a
-- pair of hosts.
--			This is not currently used.
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

local outfn	= nil			-- Output filename.
local sumfd	= nil			-- Output file descriptor.

local starttime = nil			-- Starting timestamp.
local endtime	= nil			-- Ending timestamp.

local prefix	= nil			-- Address prefix.

local timedir	= nil			-- Directory for time-series CSV files.


--------------------------------------------------------------------
-- Routine:	getepoch()
--
-- Purpose:	This function converts a time string to an epoch value.
--		The epoch value is returned on success.
--		Nil is returned if there's a problem or if the time
--		string is improperly formatted.
--		The time string must be in this general format:
--
--			date,time
--
--		More specifically:
--
--			month:day:year,hour:minute
--
--		These are valid examples:
--
--			1/9/14,16:15
--			1/9/2014,16:15
--
--		The seconds value will be ignored if it is included.
--		If the year value is a two-digit number, 2000 will be
--		added to it.
--
function getepoch(timestr)

	local mm				-- Month value.
	local dd				-- Day value.
	local yy				-- Year value.
	local h					-- Hour value.
	local m					-- Minute value.
	local s					-- Second value.

	local timetab				-- Table of time values.
	local epoch				-- Constructed epoch time.

	--
	-- Convert the time string to the time atoms.
	--
	mm, dd, yy, h, m = string.match(timestr,"(%d+)/(%d+)/(%d+),(%d+):(%d+)")

	--
	-- Return nil if there was a problem.
	--
	if(mm == nil) then
		return nil
	end

	--
	-- If a two-digit year was given, we'll bump it into this century.
	--
	if((tonumber(yy) >= 0) and (tonumber(yy) < 100)) then
		yy = tonumber(yy) + 2000
	end

	--
	-- Build the time table.
	--
	timetab =
	{
		month = mm,
		day = dd,
		year = yy,
		hour = h,
		min = m,
		sec = 0
	}

	--
	-- Convert the time table to the epoch number.
	--
	epoch = os.time(timetab)

	return epoch
end

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
	-- Create the tap itself.
	--
	tap = Listener.new()

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
				outfn = string.sub(arg, string.find(arg, "-save=") + 6)
			end

		--
		-- If we found -start, we'll get the starting timestamp.
		--
		elseif(string.sub(arg, 0, 6) == "-start") then

			if(string.sub(arg, 0, 7) ~= "-start=") then
				print("-start must include start timestamp; e.g., -start=2/14/19,8:00")
				errs = errs + 1
			else
				starttime = string.sub(arg, string.find(arg, "-start=") + 7)
				starttime = getepoch(starttime)
				if(starttime == nil) then
					print("invalid start timestamp given")
					errs = errs + 1
				end
			end

		--
		-- If we found -end, we'll get the ending timestamp.
		--
		elseif(string.sub(arg, 0, 4) == "-end") then

			if(string.sub(arg, 0, 5) ~= "-end=") then
				print("-end must include end timestamp; e.g., -end=2/14/19,18:00")
				errs = errs + 1
			else
				endtime = string.sub(arg, string.find(arg, "-end=") + 5)
				endtime = getepoch(endtime)
				if(endtime == nil) then
					print("invalid end timestamp given")
					errs = errs + 1
				end
			end

		--
		-- If we found -cidr, we'll get the CIDR address prefix.
		--
		elseif(string.sub(arg, 0, 5) == "-cidr") then

			if(string.sub(arg, 0, 7) ~= "-cidr=/") then
				print("-cidr must include prefix size; e.g., -cidr=/24")
				errs = errs + 1
			else
				prefix = string.sub(arg, string.find(arg, "-cidr=/") + 7)
				prefix = tonumber(prefix)
				if((prefix < 8) or (prefix > 24)) then
					print("invalid prefix size given")
					errs = errs + 1
				end
			end

		--
		-- If we found -timedir, we'll get the time-data directory.
		--
		elseif(string.sub(arg, 0, 8) == "-timedir") then

			if(string.sub(arg, 0, 9) ~= "-timedir=") then
				print("-timedir must include directory name; e.g., -timedir=chrono-dir")
				errs = errs + 1
			else
				timedir = string.sub(arg, string.find(arg, "-timedir=") + 9)
			end

		--
		-- If we found -slotlen, we'll get the seconds in a time slot.
		--
		elseif(string.sub(arg, 0, 8) == "-slotlen") then

			if(string.sub(arg, 0, 9) ~= "-slotlen=") then
				print("-slotlen must include time-slot length; e.g., -slotlen=180")
				errs = errs + 1
			else
				slotlength = string.sub(arg, string.find(arg, "-slotlen=") + 9)
				slotlength = tonumber(slotlength)

				if(slotlength < MIN_TIMESLOT) then
					print("invalid time-slot length given")
					errs = errs + 1
				end
			end

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

end

--
-- Initialize the tap and module.
--
inittap()


--******************************************************************************
-- Utility routines for the tap.
--

--------------------------------------------------------------------
-- Routine:	loggit()
--
-- Purpose:	This function displays and/or logs the data.
--
--		Output to save files are slightly different than terminal
--		output:
--			- lines are prefixed with the earliest timestamp in
--			  the pcap file
--
function loggit(logflag,str)

	--
	-- If an output file was named, open the file.
	--
	if(logflag == 1) then
		if(outfn ~= nil) then
			local outstr = tostring(ts_first) .. "|" .. str .. "\n"

			sumfd:write(outstr)
		end

		return
	end

	print(str)
end


--******************************************************************************
-- The routines in this section collect the statistics of packet data
-- taken from a pcap file.
--

data = {}			-- Table for grouping data-collection functions.

--------------------------------------------------------------------
-- Routine:	data.protocounts()
--
-- Purpose:	Increment the protocol counts for a set of well-known ports.
--
function data.protocounts(srcprt, dstprt)

	--
	-- Init and/or bump the source-port count.
	--
	if(protocounts[srcprt] == nil) then
		protocounts[srcprt] = 0
	end

	protocounts[srcprt] = protocounts[srcprt] + 1


	--
	-- Init and/or bump the destination-port count.
	--
	if(protocounts[dstprt] == nil) then
		protocounts[dstprt] = 0
	end

	protocounts[dstprt] = protocounts[dstprt] + 1

end


--------------------------------------------------------------------
-- Routine:	data.addrcounts()
--
-- Purpose:	Increment the use counts for the source and destination
--		addresses.
--
function data.addrcounts(srcaddr, dstaddr)

	--
	-- Init and/or bump the port-address count.
	--
	if(srccounts[srcaddr] == nil) then
		srccounts[srcaddr] = 0
		srccount = srccount + 1
	end

	srccounts[srcaddr] = srccounts[srcaddr] + 1 


	--
	-- Init and/or bump the destination-address count.
	--
	if(dstcounts[dstaddr] == nil) then
		dstcounts[dstaddr] = 0
		dstcount = dstcount + 1
	end

	dstcounts[dstaddr] = dstcounts[dstaddr] + 1 

end


--------------------------------------------------------------------
-- Routine:	data.srcdport()
--
-- Purpose:	Increment the use counts for a particular source address
--		talking to a particular destination port.
--
function data.srcdport(srcaddr, dstport)

	--
	-- Init the source-address list.
	--
	if(srcdports[srcaddr] == nil) then
		srcdports[srcaddr] = {}
	end

	--
	-- Init the list's entry for this destination port.
	--
	if(srcdports[srcaddr][dstport] == nil) then
		srcdports[srcaddr][dstport] = 0
	end

	--
	-- Increment the count for this source addr/destination port.
	--
	srcdports[srcaddr][dstport] = srcdports[srcaddr][dstport] + 1

end


--------------------------------------------------------------------
-- Routine:	data.convocount()
--
-- Purpose:	Set the counts for packets in a conversation.  In this
--		context, a conversation is a set of packets sent between
--		two particular hosts using a particular set of ports.
--
function data.convocount(srcaddr, dstaddr, srcprt, dstprt)

	local convkey				-- Key to the convocounts table.

	--
	-- Build the conversation string.  This will be the key to the
	-- conversation table.  If one side has a Well-Known Port (port
	-- number < 1024), we'll assume that's the destination.
	--
	if(dstprt < 1024) then
		convkey = srcaddr .. "_" .. srcprt .. "-" .. dstaddr .. "_" .. dstprt
	else
		convkey = dstaddr .. "_" .. dstprt .. "-" .. srcaddr .. "_" .. srcprt

	end

	--
	-- Initialize this conversation's counter.
	--
	if(convocounts[convkey] == nil) then
		convocounts[convkey] = 0
	end

	--
	-- Increment the count for this conversation.
	--
	convocounts[convkey] = convocounts[convkey] + 1

end


--------------------------------------------------------------------
-- Routine:	data.lowhighcount()
--
-- Purpose:	Set the counts for packets in low-to-low port conversations
--		and high-to-high port conversations.  In this context, a
--		conversation is a set of packets sent between two particular
--		hosts using a particular set of ports.
--
function data.lowhighcount(srcaddr, dstaddr, srcprt, dstprt)

	local convkey				-- Key to the convocounts table.

	--
	-- Ignore packets that have only one of the source or destination
	-- ports within the range of Well-Known Ports.
	--
	if(((srcprt <= WKPORT_HIGH) and (dstprt > WKPORT_HIGH))	 or
	   ((dstprt <= WKPORT_HIGH) and (srcprt > WKPORT_HIGH))) then
		return
	end

	--
	-- Build the conversation string.  This will be the key to the
	-- conversation table.  Choosing arbitrarily, the lowest port
	-- number will be used as the source.
	--
	if(srcprt < dstprt) then
		convkey = srcaddr .. "_" .. srcprt .. "-" .. dstaddr .. "_" .. dstprt
	else
		convkey = dstaddr .. "_" .. dstprt .. "-" .. srcaddr .. "_" .. srcprt

	end

	--
	-- Increment the count for this low-to-low or high-to-high conversation.
	-- The counter will be initialized if this is the first we've seen it.
	--
	if((srcprt <= WKPORT_HIGH) and (dstprt <= WKPORT_HIGH)) then

		if(lowlowcounts[convkey] == nil) then
			lowlowcounts[convkey] = 0
		end

		lowlowcounts[convkey] = lowlowcounts[convkey] + 1

	elseif((srcprt >= DYNPORT_LOW) and (dstprt >= DYNPORT_LOW)) then
		if(highhighcounts[convkey] == nil) then
			highhighcounts[convkey] = 0
		end

		highhighcounts[convkey] = highhighcounts[convkey] + 1

	else
		--
		-- Ignoring the middle range of registered ports for now.
		-- We might add stats for this in the fullness of time.
		--
	end

end


--------------------------------------------------------------------
-- Routine:	ipv4toint()
--
-- Purpose:	Convert an IPv4 address string to an integer.
--
function ipv4toint(addr)

	local octet1				-- Address octet 1.
	local octet2				-- Address octet 2.
	local octet3				-- Address octet 3.
	local octet4				-- Address octet 4.
	local addrint				-- Integer form of address.

	octet1, octet2, octet3, octet4 = string.match(addr, "(%d+).(%d+).(%d+).(%d+)")

	if((octet1 == nil) or (octet2 == nil) or
	   (octet3 == nil) or (octet4 == nil))
	then
		return nil
	end

	addrint = (octet1 * (2^24)) +
		  (octet2 * (2^16)) +
		  (octet3 * (2^8)) +
		   octet4

	return addrint

end


--------------------------------------------------------------------
-- Routine:	inttoipv4()
--
-- Purpose:	Convert an IPv4 integer to a dotted-address string.
--
function inttoipv4(addr)

	local octet1			-- Address octet 1.
	local octet2			-- Address octet 2.
	local octet3			-- Address octet 3.
	local octet4			-- Address octet 4.
	local addrstr			-- Dotted string form of address.

--	octet1, octet2, octet3, octet4 = string.match(addr, "(%d+).(%d+).(%d+).(%d+)")

	octet1 = bit32.band(addr, 0xff000000)
	octet1 = bit32.rshift(octet1, 24)

	octet2 = bit32.band(addr, 0x00ff0000)
	octet2 = bit32.rshift(octet2, 16)

	octet3 = bit32.band(addr, 0x0000ff00)
	octet3 = bit32.rshift(octet3, 8)

	octet4 = bit32.band(addr, 0x000000ff)

	addrstr = string.format("%d.%d.%d.%d", octet1, octet2, octet3, octet4)

	return addrstr

end


--------------------------------------------------------------------
-- Routine:	ipv4prefix()
--
-- Purpose:	Mask out all but the mask bits in an IPv4 address.
--
function ipv4prefix(addr, mask)

	local shifter				-- Bit-shift value.
	local addrprefix			-- Masked address prefix.

	--
	-- Skip all the math if we're just returning the whole address.
	--
	if(mask == 32) then
		return addr
	end

	shifter = (2 ^ mask) - 1

	shifter = bit32.lshift(shifter, (32 - mask))

	addrprefix = bit32.band(addr, shifter)

	return addrprefix

end


--------------------------------------------------------------------
-- Routine:	data.prefixcounts()
--
-- Purpose:	Set the count for packets sent from each address prefix.
--
function data.prefixcounts(addr, srcflag)

	local addrnum				-- Integer form of address.
	local pfxa				-- Prefix of address.

	--
	-- Don't do anything if no address prefix length was given.
	--
	if(prefix == nil) then
		return
	end

	--
	-- Convert the address string to an integer, skipping any
	-- untranslatable addresses.
	--
	addrnum = ipv4toint(addr)
	if(addrnum == nil) then
		return
	end

	--
	-- Get the user-specified prefix of the address.
	--
	pfxa = ipv4prefix(addrnum, prefix)

	--
	-- Bump the prefix's count in the appropriate table.
	--
	if(srcflag == 1) then
		if(srcprefixcounts[pfxa] == nil) then
			srcprefixcounts[pfxa] = 0
		end
		srcprefixcounts[pfxa] = srcprefixcounts[pfxa] + 1 
	else
		if(dstprefixcounts[pfxa] == nil) then
			dstprefixcounts[pfxa] = 0
		end
		dstprefixcounts[pfxa] = dstprefixcounts[pfxa] + 1 
	end

end


--------------------------------------------------------------------
-- Routine:	data.prefixtimes()
--
-- Purpose:	Set the time counts for packets sent from each address prefix.
--
function data.prefixtimes(addr, pkttime, srcflag)

	local addrnum				-- Integer form of address.
	local pfxa				-- Prefix of address.

	--
	-- Don't do anything if no address prefix length was given.
	--
	if(prefix == nil) then
		return
	end

	--
	-- We're only handling IPv4 addresses for now.
	--
	if(string.find(addr, ":") ~= nil) then
		return
	end

	--
	-- Strip off the fractional part of the packet's absolute time.
	--
	pkttime = string.gsub(pkttime, "%.%d+", "")
	pkttime = tonumber(pkttime)

	--
	-- Initialize (or adjust) the beginning of the next timeslot 
	-- and the time index.
	--
	if(nexttimeslot == 0) then
		nexttimeslot = pkttime + slotlength
		timeind = 1
	else
		if(pkttime >= nexttimeslot) then
			nexttimeslot = nexttimeslot + slotlength
			timeind = timeind + 1
		end
	end

	--
	-- Convert the address string to an integer, skipping any
	-- untranslatable addresses.
	--
	addrnum = ipv4toint(addr)
	if(addrnum == nil) then
		return
	end

	--
	-- Get the user-specified prefix of the address.
	--
	pfxa = ipv4prefix(addrnum, prefix)

	--
	-- Bump the prefix's count in the appropriate table.
	-- We'll have to make sure the address' table and the time-index
	-- slot within that table are all set up.
	--
	if(srcflag == 1) then

		if(srcprefixtimes[pfxa] == nil) then
			srcprefixtimes[pfxa] = {}
		end

		if(srcprefixtimes[pfxa][timeind] == nil) then
			srcprefixtimes[pfxa][timeind] = 0
		end

		srcprefixtimes[pfxa][timeind] = srcprefixtimes[pfxa][timeind] + 1 

	else

		if(dstprefixtimes[pfxa] == nil) then
			dstprefixtimes[pfxa] = {}
		end

		if(dstprefixtimes[pfxa][timeind] == nil) then
			dstprefixtimes[pfxa][timeind] = 0
		end

		dstprefixtimes[pfxa][timeind] = dstprefixtimes[pfxa][timeind] + 1 
	end

end


--******************************************************************************
-- The routines in this section display the statistics and summarizations
-- of packet data gathered from a pcap file.

show = {}			-- Table for grouping display functions.

--------------------------------------------------------------------
-- Routine:	show.totalpkts()
--
-- Purpose:	Show the total number of packets seen.
--
function show.totalpkts()

	--
	-- Display the total counts of packets seen.
	--
	loggit(0,"total packets examined:  " .. packetcnt)
	loggit(0,"")

	log.totalpkts()
end


--------------------------------------------------------------------
-- Routine:	show.protocounts()
--
-- Purpose:	Show the counts of protocol usage for each of the well-known
--		protocols.  If any packets were seen for a protocol, then the
--		percentage of the total packet count will also be given.
--
function show.protocounts()

	loggit(0,"protocol counts:")

	for ind in pairs(portindices) do
		local outstr
		local val

		--
		-- Get the (ordered) index for this port, and use that
		-- to get the protocol's packet count.
		--
		ind = portindices[ind]
		protocnt = protocounts[ind]

		outstr = "\t" .. ports[ind] .. ":\t"

		--
		-- Maybe add an extra tab for nicer spacing.
		--
		if(string.len(outstr) < 10) then
			outstr = outstr .. "\t"
		end

			outstr = outstr .. "\t"

		outstr = outstr .. protocnt

		--
		-- If there were packets for this protocol, we'll also
		-- include the percentage of the total this protocol had.
		--
		if(protocnt > 0) then
			local pcnt = (protocnt / packetcnt) * 100
			outstr = outstr .. string.format("\t%5.1f%%", pcnt)
		end

		loggit(0,outstr)
	end

	loggit(0,"")

	log.protocounts()
end

--------------------------------------------------------------------
-- Routine:	show.addrcounts()
--
-- Purpose:	Show the counts of protocol usage for each of the well-known
--		protocols.  If any packets were seen for a protocol, then the
--		percentage of the total packet count will also be given.
--
function show.addrcounts()
	local maxlen				-- Maximum address length.

	--
	-- Find the longest source address.
	--
	maxlen = -1
	for ind, val in pairs(srccounts) do
		local ilen = string.len(ind)

		if(ilen > maxlen ) then
			maxlen = ilen
		end
	end
	maxlen = maxlen + 3

	loggit(0,"unique source addresses:  " .. srccount .. "\n")

	--
	-- List the packet counts for each source address.
	--
	loggit(0,"source-address counts:")
	for ind, val in pairs(srccounts) do
		local outstr

		outstr = ind .. ":  "

		if(string.len(outstr) < maxlen) then
			outstr = outstr .. string.rep(' ', (maxlen - string.len(outstr)))
		end

		outstr = outstr .. val

		loggit(0,"\t" .. outstr)

	end
	loggit(0,"")

	--
	-- Find the longest destination address.
	--
	maxlen = -1
	for ind, val in pairs(dstcounts) do
		local ilen = string.len(ind)

		if(ilen > maxlen ) then
			maxlen = ilen
		end
	end
	maxlen = maxlen + 3

	loggit(0,"unique destination addresses:  " .. dstcount .. "\n")

	--
	-- List the packet counts for each destination address.
	--
	loggit(0,"destination-address counts:")
	for ind, val in pairs(dstcounts) do
		local outstr

		outstr = ind .. ":  "

		if(string.len(outstr) < maxlen) then
			outstr = outstr .. string.rep(' ', (maxlen - string.len(outstr)))
		end

		outstr = outstr .. val

		loggit(0,"\t" .. outstr)

	end

	loggit(0,"")

	log.addrcounts()

end


--------------------------------------------------------------------
-- Routine:	show.srcdport()
--
-- Purpose:	Display the use counts for a particular source address
--		talking to a particular destination port.
--
function show.srcdport()

	loggit(0,"source address/destination port counts:")
	for src, dports in pairs(srcdports) do
		local cnt = 0

		loggit(0,"\tsource " .. src .. ":")

		for ind in pairs(portindices) do
			local outstr
			local val

			--
			-- Get the (ordered) index for this port, and use that
			-- to get the source's use of this protocol.
			--
			ind = portindices[ind]

			if(dports[ind] ~= nil) then

-- loggit(0,"\t\t\t\t------> ind - <" .. ind .. ">")
-- loggit(0,"\t\t\t\t------> dports[" .. ind .. "] - <" .. dports[ind] .. ">")
				protocnt = dports[ind]

				outstr = "\t\t" .. ports[ind] .. ":\t"

				--
				-- Maybe add an extra tab for nicer spacing.
				--
				if(string.len(outstr) < 10) then
					outstr = outstr .. "\t"
				end

					outstr = outstr .. "\t"

-- loggit(0,"\t\t\t\t------> protocnt - <" .. protocnt .. ">")
				outstr = outstr .. protocnt

				loggit(0,outstr)

				cnt = cnt + 1

			end
		end

		if(cnt == 0) then
			loggit(0,"\t\t(no well-known protocols contacted)")
		end

		loggit(0,"")

	end

	log.srcdport()

end


--------------------------------------------------------------------
-- Routine:	show.convocount()
--
-- Purpose:	Show the packets counts for all the conversations.
--		A conversation in this context is a set of packets sent
--		between two particular hosts using a particular set of ports.
--
function show.convocount()

	loggit(0,"packets counts in conversations:")
	for ckey, conv in pairs(convocounts) do

		ckey = string.gsub(ckey ,"_(%w+)","(%1)", 2);
		ckey = string.gsub(ckey,"-", "\t")

		loggit(0,"\t" .. ckey .. ":\t\t" .. conv)

	end

	loggit(0,"")

	log.convocount()
end


--------------------------------------------------------------------
-- Routine:	show.lowhighcount()
--
-- Purpose:	Show the packets counts for all low-to-low port and
--		high-to-high port conversations.
--
function show.lowhighcount()

	local cnt = 0

	loggit(0,"packets counts in low-to-low port conversations:")
	for ckey, conv in pairs(lowlowcounts) do

		ckey = string.gsub(ckey ,"_(%w+)","(%1)", 2);
		ckey = string.gsub(ckey,"-", "\t")

		loggit(0,"\t" .. ckey .. ":\t\t" .. conv)

		cnt = cnt + 1

	end

	if(cnt == 0) then
		loggit(0,"\t\t(no low-to-low port conversations)")
	end

	---------------------

	cnt = 0
	loggit(0,"packets counts in high-to-high port conversations:")
	for ckey, conv in pairs(highhighcounts) do

		ckey = string.gsub(ckey ,"_(%w+)","(%1)", 2);
		ckey = string.gsub(ckey,"-", "\t")

		loggit(0,"\t" .. ckey .. ":\t\t" .. conv)

		cnt = cnt + 1

	end

	if(cnt == 0) then
		loggit(0,"\t\t(no high-to-high port conversations)")
	end

	loggit(0,"")

	log.lowhighcount()
end


--------------------------------------------------------------------
-- Routine:	show.prefixcounts()
--
-- Purpose:	Show the packets counts for all the address prefixes.
--
function show.prefixcounts()

	local addrorder = {}				-- Ordering array.

	--
	-- Build and sort an ordering array of the source prefixes.
	--
	for addr in pairs(srcprefixcounts) do
		table.insert(addrorder, addr)
	end
	table.sort(addrorder)

	--
	-- Show the source-prefix counts.
	--
	loggit(0,"packet counts by source-address prefix:")
	for ind, addr in ipairs(addrorder) do
		local addrstr
		local out

		addrstr = inttoipv4(addr)
		out = string.format("\t%-15s\t%d", addrstr, srcprefixcounts[addr])
		loggit(0,out)
	end
	loggit(0,"")

	--
	-- Build and sort an ordering array of the destination prefixes.
	--
	addrorder = {}
	for addr in pairs(dstprefixcounts) do
		table.insert(addrorder, addr)
	end
	table.sort(addrorder)

	--
	-- Show the destination-prefix counts.
	--
	loggit(0,"packet counts by destination-address prefix:")
	for ind, addr in ipairs(addrorder) do
		local addrstr
		local out

		addrstr = inttoipv4(addr)
		out = string.format("\t%-15s\t%d", addrstr, dstprefixcounts[addr])
		loggit(0,out)
	end
	loggit(0,"")

	--
	-- Log the prefix counts.
	--
	log.prefixcounts()

end


--------------------------------------------------------------------
-- Routine:	show.prefixtimes()
--
-- Purpose:	Create a set of CSV files for the address prefix time counts.
--		These are time-series files, one per address prefix.
--
--		I'm sure there's a good way to refactor this into a shorter
--		routine, but this will do for now.
--
function show.prefixtimes()

	local addrorder = {}				-- Ordering array.

	--
	-- Build and sort an ordering array of the source prefixes.
	--
	for addr in pairs(srcprefixtimes) do
		table.insert(addrorder, addr)
	end
	table.sort(addrorder)

	--
	-- Save the time-series data for the address-prefix packet counts
	-- into a set of CSV files.
	--
	loggit(0,"time-series packet counts by source-address prefix:")
	for ind, addr in ipairs(addrorder) do
		local addrstr		-- String version of address prefix.
		local out		-- Output line to be built.
		local outfn		-- Output CSV file's name.

		--
		-- Convert the integer form of the address prefix to a
		-- dotted-quad version.
		--
		addrstr = inttoipv4(addr)

		out = addrstr .. ","

		--
		-- Build a CSV line for this address prefix's counts.
		--
		for tind = 1, timeind do
			--
			-- Append this time slot's value to the output line.
			--
			if(srcprefixtimes[addr][tind] ~= nil) then
				out = out .. srcprefixtimes[addr][tind]
			end

			--
			-- Append the field separator.
			--
			out = out .. ","

		end

		--
		-- Build the filename for the CSV file.
		--
		outfn = "time-series-src-" .. addrstr .. ".csv"
		if(timedir ~= nil) then
			outfn = timedir .. "/" .. outfn
		end

		--
		-- Write this address prefix's data to a single-line CSV file.
		--
		csvfd = io.open(outfn, "w")
		csvfd:write(out .. "\n")
		io.close(csvfd)

		out = string.format("%-16s saved in %s", addrstr, outfn)
		loggit(0,"\t" .. out) 

	end

	loggit(0,"")


	--
	-- Reset the ordering array.
	--
	addrorder = {}

	--
	-- Build and sort an ordering array of the destination prefixes.
	--
	for addr in pairs(dstprefixtimes) do
		table.insert(addrorder, addr)
	end
	table.sort(addrorder)

	--
	-- Save the time-series data for the address-prefix packet counts
	-- into a set of CSV files.
	--
	loggit(0,"time-series packet counts by destination-address prefix:")
	for ind, addr in ipairs(addrorder) do
		local addrstr		-- String version of address prefix.
		local out		-- Output line to be built.
		local outfn		-- Output CSV file's name.

		--
		-- Convert the integer form of the address prefix to a
		-- dotted-quad version.
		--
		addrstr = inttoipv4(addr)

		out = addrstr .. ","

		--
		-- Build a CSV line for this address prefix's counts.
		--
		for tind = 1, timeind do
			--
			-- Append this time slot's value to the output line.
			--
			if(dstprefixtimes[addr][tind] ~= nil) then
				out = out .. dstprefixtimes[addr][tind]
			end

			--
			-- Append the field separator.
			--
			out = out .. ","

		end

		--
		-- Build the filename for the CSV file.
		--
		outfn = "time-series-dst-" .. addrstr .. ".csv"
		if(timedir ~= nil) then
			outfn = timedir .. "/" .. outfn
		end

		--
		-- Write this address prefix's data to a single-line CSV file.
		--
		csvfd = io.open(outfn, "w")
		csvfd:write(out .. "\n")
		io.close(csvfd)

		out = string.format("%-16s saved in %s", addrstr, outfn)
		loggit(0,"\t" .. out) 

	end

	loggit(0,"")

end


--******************************************************************************
-- The routines in this section display the statistics and summarizations
-- of packet data gathered from a pcap file.

log = {}			-- Table for grouping display functions.

--------------------------------------------------------------------
-- Routine:	log.totalpkts()
--
-- Purpose:	Log the total number of packets seen.
--
function log.totalpkts()

	--
	-- Display the total counts of packets seen.
	--
	loggit(1,"total-packets|" .. packetcnt)

end


--------------------------------------------------------------------
-- Routine:	log.protocounts()
--
-- Purpose:	Log the counts of protocol usage for each of the well-known
--		protocols.  If any packets were seen for a protocol, then the
--		percentage of the total packet count will also be given.
--
function log.protocounts()

	for ind in pairs(portindices) do
		local outstr
		local val

		--
		-- Get the (ordered) index for this port, and use that
		-- to get the protocol's packet count.
		--
		ind = portindices[ind]
		protocnt = protocounts[ind]

		outstr = "protocnts|" .. ports[ind] .. "|" .. protocnt

		--
		-- Include the percentage of the total this protocol had.
		--
		local pcnt = (protocnt / packetcnt) * 100
		outstr = outstr .. string.format("|%1.1f%%", pcnt)

		loggit(1,outstr)
	end

end


--------------------------------------------------------------------
-- Routine:	log.addrcounts()
--
-- Purpose:	Log the counts of protocol usage for each of the well-known
--		protocols.  If any packets were seen for a protocol, then the
--		percentage of the total packet count will also be given.
--
function log.addrcounts()

	loggit(1,"unique source addresses|" .. srccount)

	--
	-- List the packet counts for each source address.
	--
	for ind, val in pairs(srccounts) do
		local outstr

		outstr = "source-address counts|" .. ind .. "|" .. val

		loggit(1,outstr)

	end


	loggit(1,"unique destination addresses|" .. dstcount)

	--
	-- List the packet counts for each destination address.
	--
	for ind, val in pairs(dstcounts) do
		local outstr

		outstr = "destination-address counts|" .. ind .. "|" .. val

		loggit(1,outstr)

	end

end


--------------------------------------------------------------------
-- Routine:	log.srcdport()
--
-- Purpose:	Log the use counts for a particular source address
--		talking to a particular destination port.
--
function log.srcdport()

	for src, dports in pairs(srcdports) do
		local cnt = 0

		for ind in pairs(portindices) do
			local outstr
			local val

			--
			-- Get the (ordered) index for this port, and use that
			-- to get the source's use of this protocol.
			--
			ind = portindices[ind]

			if(dports[ind] ~= nil) then

				outstr = "srcaddr/dport counts|" .. src .. "|" .. ports[ind] .. "|" .. dports[ind]

				loggit(1,outstr)

				cnt = cnt + 1

			end
		end

		if(cnt == 0) then
			outstr = "srcaddr/dport counts|" .. src .. "|" .. "no wkprots"
			loggit(1,outstr)
		end

	end

end


--------------------------------------------------------------------
-- Routine:	log.convocount()
--
-- Purpose:	Log the packets counts for all the conversations.
--
function log.convocount()

	for ckey, conv in pairs(convocounts) do

		ckey = string.gsub(ckey ,"_(%w+)","(%1)", 2);

		loggit(1,"conv packets counts|" ..  ckey .. "|" .. conv)

	end

end


--------------------------------------------------------------------
-- Routine:	log.lowhighcount()
--
-- Purpose:	Log the packets counts for all low-to-low port and
--		high-to-high port conversations.
--
function log.lowhighcount()

	local cnt = 0

	for ckey, conv in pairs(lowlowcounts) do

		ckey = string.gsub(ckey ,"_(%w+)","(%1)", 2);

		loggit(1,"low-to-low port packet counts|" .. ckey .. "|" .. conv)

		cnt = cnt + 1

	end

	if(cnt == 0) then
		loggit(1,"low-to-low port packet counts| |" .. "no low-to-low port convs")
	end

	---------------------

	cnt = 0
	for ckey, conv in pairs(highhighcounts) do

		ckey = string.gsub(ckey ,"_(%w+)","(%1)", 2);

		loggit(1,"high-to-high port packet counts|" .. ckey .. "|" .. conv)

		cnt = cnt + 1

	end

	if(cnt == 0) then
		loggit(1,"high-to-high port packet counts| |" .. "no high-to-high port convs")
	end

end


--------------------------------------------------------------------
-- Routine:	log.prefixcounts()
--
-- Purpose:	Log the packets counts for all the address prefixes.
--
function log.prefixcounts()

	for addr, cnt in pairs(srcprefixcounts) do

		local addrstr = inttoipv4(addr)

		loggit(1,"source-address-prefix counts|" ..  addrstr .. "|" .. cnt)

	end

	for addr, cnt in pairs(dstprefixcounts) do

		local addrstr = inttoipv4(addr)

		loggit(1,"destination-address-prefix counts|" ..  addrstr .. "|" .. cnt)

	end

end


--******************************************************************************
-- The routines in this section are the hooks used to get this tap executed
-- by tshark.

--------------------------------------------------------------------
-- Routine:	tap.packet()
--
-- Purpose:	This function will be called once for each packet.
--		Filter-specific handling occurs on the data.
--		the data.
--
--		The following statistics are gathered:
--			- count of total number of packets seen
--
function tap.packet(pinfo, tvb, tapinfo)

	local srcprt					-- Source port.
	local dstprt					-- Destination port.

	--
	-- If the caller specified a starting or ending timestamp, we
	-- won't include packets before or after those timestamps.
	--
	if(starttime ~= nil) then
		if(pinfo.abs_ts < starttime) then
			return
		end
	end
	if(endtime ~= nil) then
		if(pinfo.abs_ts > endtime) then
			return
		end
	end

	--
	-- Save the earliest and latest times in this pcap file.
	-- If ts_first is nil then neither timestamp has been set yet,
	-- and so we set both timestamps at once.  Otherwise, we'll
	-- check each individually.
	--
	if(ts_first == nil) then
		ts_first = pinfo.abs_ts
		ts_last	 = pinfo.abs_ts
	else
		if(pinfo.abs_ts < ts_first) then
			ts_first = pinfo.abs_ts
		end
		if(pinfo.abs_ts > ts_last) then
			ts_last = pinfo.abs_ts
		end
	end

	--
	-- Get some shorthand variables.
	--
	srcaddr = tostring(pinfo.src)
	dstaddr = tostring(pinfo.dst)
	srcprt = pinfo.src_port
	dstprt = pinfo.dst_port

	--
	-- Bump the total packet count.
	--
	packetcnt = packetcnt + 1

	--
	-- Set the protocol counts for a set of well-known ports.
	--
	data.protocounts(srcprt, dstprt)

	--
	-- Set the host counts for the source and destination addresses.
	--
	data.addrcounts(srcaddr, dstaddr)

	--
	-- Set the counts for the source addr/destination port.
	--
	data.srcdport(srcaddr, dstprt)

	--
	-- Set the counts for packets in a conversation.
	--
	data.convocount(srcaddr, dstaddr, srcprt, dstprt)

	--
	-- Set the counts for packets in a low-port or high-port conversation.
	--
	data.lowhighcount(srcaddr, dstaddr, srcprt, dstprt)

	--
	-- Set the count for packets sent from each address prefix.
	--
	data.prefixcounts(srcaddr, 1)
	data.prefixcounts(dstaddr, 0)

	--
	-- Set the time-based counts for packets sent from each address prefix.
	--
	data.prefixtimes(srcaddr, pinfo.abs_ts, 1)
	data.prefixtimes(dstaddr, pinfo.abs_ts, 0)

end


--------------------------------------------------------------------
-- Routine:	tap.draw()
--
-- Purpose:	This function massages the data gathered in tap.packet()
--		and displays the results.  This routine is called after
--		all packets are handled.
--
--		The actual output code has been moved into separate routines
--		to allow for easier reorganization and comprehension.
--
function tap.draw(t)

	local tsf = os.date("%D %T", tostring(ts_first))
	local tsl = os.date("%D %T", tostring(ts_last))

	loggit(0,"absolute time of earliest packet:  " .. ts_first .. "\t" .. tsf)
	loggit(0,"absolute time of latest packet:    " .. ts_last .. "\t" .. tsl)
	loggit(0,"\n")

	loggit(1,"info|abstime earliest packet|" .. ts_first .. "|" .. tsf)
	loggit(1,"info|abstime latest packet|" .. ts_last .. "|" .. tsl)

	show.totalpkts()

	show.protocounts()

	show.addrcounts()

	show.srcdport()

	show.convocount()

	show.lowhighcount()

	show.prefixcounts()

	show.prefixtimes()

	io.close(sumfd)

end


--------------------------------------------------------------------
-- Routine:	tap.reset()
--
-- Purpose:	This function will be called whenever a reset is
--		needed, e.g. when reloading the capture file.
--
function tap.reset()

	--
	-- Reset our counts.
	--
	packetcnt = 0

	--
	-- Reset our tables.
	--
	ips	= {}
	prots	= {}

end


--******************************************************************************


