--
-- pcap-ntp.lua
--
--	This script is a plugin tap for tshark.  It collects information from
--	NTP packets.
--
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
--				e.g., ('ethernet', 'ip', 'udp', 'ntp')
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
--			pkt['ip'].fragoff	fragment offset
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
--		pkt['ntp']		table of NTP header fields
--			pkt['ntp'].flags	NTP flags (broken out below)
--			pkt['ntp'].stratum	stratum
--			pkt['ntp'].poll		poll exponent
--			pkt['ntp'].precision	precision exponent
--			pkt['ntp'].delay	root delay
--			pkt['ntp'].dispersion	root dispersion
--			pkt['ntp'].refid	reference ID
--			pkt['ntp'].reftstmp	reference timestamp
--			pkt['ntp'].origintstmp	origin timestamp
--			pkt['ntp'].recvtstmp	receive timestamp
--			pkt['ntp'].xmittstmp	transmit timestamp
--
--			The flags field is broken out into convenience fields:
--				pkt['ntp'].leap		leap indicator
--				pkt['ntp'].version	protocol version number
--				pkt['ntp'].mode		mode
--
--			See RFC 5905 for details about NTP fields.
--
--
--
-- Revision History
--	1.0 Initial revision.					190514
--

--******************************************************************************

--
-- Version information.
--
NAME	= "pcap-ntp"
VERSNUM	= 1.0
VERS	= NAME .. " version: " .. VERSNUM

local argv = {...}				-- Arguments to the tap.

local tapinfo = {
	version	    = VERSNUM,
	author	    = "Wayne Morrison",
	description = NAME .. ":  tshark plugin to summarize and display NTP packets from PCAP data, created for the GAWSEED project, part of the CHASE program."
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
-- NTP info.
--

--
-- Mode values for NTP packets.
--

NTP_MODE_RESERVED	= 0		-- Reserved.
NTP_MODE_SYMACTIVE	= 1		-- Symmetric active.
NTP_MODE_SYMPASSIVE	= 2		-- Symmetric passive.
NTP_MODE_CLIENT		= 3		-- Client.
NTP_MODE_SERVER		= 4		-- Server.
NTP_MODE_BROADCAST	= 5		-- Broadcast.
NTP_MODE_NTP_CTL	= 6		-- NTP control message.
NTP_MODE_PRIVATE	= 7		-- Reserved for private use.

--
-- Leap-indicator values for NTP packets.
--
NTP_LEAP_OKAY	 = 0			-- No warning.
NTP_LEAP_LAST61	 = 1			-- Last minute of day has 61 seconds.
NTP_LEAP_LAST59	 = 2			-- Last minute of day has 59 seconds.
NTP_LEAP_UNKNOWN = 3			-- Clock unsynchronized.

NTP_STRATUM_INVALID = 0		-- Unspecified or invalid.
NTP_STRATUM_PRIMARY = 1		-- Primary server (eg, equipped w/ GPS receiver)
NTP_STRATUM_SEC_MIN = 2		-- Minimum secondary server (via NTP).
NTP_STRATUM_SEC_MAX = 15	-- Maximum secondary server (via NTP).
NTP_STRATUM_UNSYNCH = 16	-- Unsynchronized.
NTP_STRATUM_RES_MIN = 17	-- Minimum reserved value.
NTP_STRATUM_RES_MAX = 255	-- Maximum reserved value.

 
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

local LOGFILE = "/tmp/z.ntp-log"		-- General log file.


local SAVELOG = "/tmp/ntpflows.log"		-- Log file for saving flows.

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
local logntp = false

--------------------------------------------------------------------
--
-- Global data needed by the tap.
--

local packetcnt		= 0		-- Number of packets we've seen.
local ntppacketcnt	= 0		-- Number of NTP packets we've seen.

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
				print("-save must include output file; e.g., -plog=ip,ntp")
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
					if(pv == 'ntp') then logntp = true end
				end
			end

		--
		-- If we found -ntpflows, we'll get the logging argument
		--
		elseif(string.sub(arg, 0, 9) == "-ntpflows") then
			op_ntpflows = false

			print("\n\n-ntpflows option doesn't do anything sensible yet.  It might be deleted eventually.\nKeeping now for reference\n\n")

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
-- This section contains routine specific for handling NTP packets.
--
-- Interfaces:
--	ntp.parse(pkt, tvb)	Parses the NTP header portion of a tvb buffer
--				and adds the fields to a pkt table.
--
--	ntp.log(pkt)		Logs the parsed fields from an NTP header.
--
--	ntp.leap2str(leap)		Translate a leap value to a string.
--
--	ntp.mode2str(mode)		Translate a mode value to a string.
--
--	ntp.stratum2str(stratum)	Translate a stratum value to a string.
--
--	ntp.refid2ipaddr(refid)		Translate a reference id to IPv4 addr.
--

ntp = {}				-- Table for grouping NTP functions.


----------------------------------------------------------------------
-- Routine:	ntp.parse()
--
-- Purpose:	This function saves the required fields from the NTP portion
--		of the packet.
--
function ntp.parse(pkt,tvb)

	--
	-- We'll only handle NTP packets here.
	--
	if((pkt['pinfo'].srcport ~= PORT_NTP)	and
	   (pkt['pinfo'].srcport ~= "ntp")	and
	   (pkt['pinfo'].dstport ~= PORT_NTP)	and
	   (pkt['pinfo'].dstport ~= "ntp"))	then
		return
	end

	--
	-- Get the NTP part of the packet.
	--
	tvbr = tvb:range(pkt.hdrindex)

	--
	-- Save the NTP fields.
	--
	pkt['ntp']	   = {}
	pkt['ntp'].flags	= tvbr:range(0,1):uint()
	pkt['ntp'].stratum 	= tvbr:range(1,1):uint()
	pkt['ntp'].poll 	= tvbr:range(2,1):uint()
	pkt['ntp'].precision	= tvbr:range(3,1):uint()
	pkt['ntp'].delay	= tvbr:range(4,4):uint()
	pkt['ntp'].dispersion	= tvbr:range(8,4):uint()
	pkt['ntp'].refid	= tvbr:range(12,4):uint()
	pkt['ntp'].reftstmp	= tvbr:range(16,8):uint64()
	pkt['ntp'].origintstmp	= tvbr:range(24,8):uint64()
	pkt['ntp'].recvtstmp	= tvbr:range(32,8):uint64()
	pkt['ntp'].xmittstmp	= tvbr:range(40,8):uint64()


	--
	-- This is how we can get the pieces of the NTP timestamps.
	-- The seconds count uses 1/1/1900 00:00:00 as the epoch, rather
	-- than the more familiar Unix epoch.  To get the time we're
	-- more used to using, we've got to subtract 2208988800 from
	-- the seconds count.
	-- See RFC 5905 section 6 for more info about NTP timestamps.
	--
--	pkt['ntp'].ref_tsecs = tvbr:bitfield(128, 32)
--	pkt['ntp'].ref_tfrac = tvbr:bitfield(160, 32)


	--
	-- Break the flags into convenient, bite-size chunks.
	--
	pkt['ntp'].leap		= tvbr:bitfield(0, 2)
	pkt['ntp'].version	= tvbr:bitfield(2, 3)
	pkt['ntp'].mode		= tvbr:bitfield(5, 3)

	--
	-- Mark the packet as having parsed NTP fields.
	--
	if(pkt.protocols == nil) then
		pkt.protocols = {}
	end
	table.insert(pkt.protocols, 'ntp')

end


----------------------------------------------------------------------
-- Routine:	ntp.leap2str()
--
-- Purpose:	This function translates an NTP leap indicator flag value
--		into a string.  The text string is then returned to the caller.
--
--		Examples:
--			- 0  -> okay
--			- 1  -> last minute 61 seconds
--			- 2  -> last minute 59 seconds
--			- 3  -> clock unsynchronized
--
function ntp.leap2str(leap)

	local lstr				-- Leap flag string.

	if((leap == nil) or (leap == '')) then
		lstr = string.format("UNKNOWN NTP leap indicator - no leap given")
		return lstr
	end

	if((leap < NTP_LEAP_OKAY) or (leap > NTP_LEAP_UNKNOWN)) then
		lstr = string.format("NTP leap indicator out of range -- %d", leap)
		return lstr
	end

	if(leap == NTP_LEAP_OKAY) then
		lstr = 'okay'
	elseif(leap == NTP_LEAP_LAST59) then
		lstr = 'last minute 59 seconds'
	elseif(leap == NTP_LEAP_LAST61) then
		lstr = 'last minute 61 seconds'
	elseif(leap == NTP_LEAP_UNKNOWN) then
		lstr = 'clock unsynchronized'
	else
		lstr = string.format("UNKNOWN NTP leap - %d", leap)
	end

	return lstr
end


----------------------------------------------------------------------
-- Routine:	ntp.mode2str()
--
-- Purpose:	This function translates an NTP mode flag value into a text
--		string.  The text string is then returned to the caller.
--
--		Examples:
--			- 1  -> symmetric active
--			- 3  -> client
--			- 4  -> server
--
function ntp.mode2str(mode)

	local mstr				-- Mode flag string.

	if((mode == nil) or (mode == '')) then
		mstr = string.format("UNKNOWN NTP mode - no mode given")
		return mstr
	end

	if((mode < NTP_MODE_RESERVED) or (mode > NTP_MODE_PRIVATE)) then
		mstr = string.format("NTP mode out of range -- %d", mode)
		return mstr
	end

	if(mode == NTP_MODE_RESERVED) then
		mstr = 'reserved'
	elseif(mode == NTP_MODE_SYMACTIVE) then
		mstr = 'symmetric active'
	elseif(mode == NTP_MODE_SYMPASSIVE) then
		mstr = 'symmetric passive'
	elseif(mode == NTP_MODE_CLIENT) then
		mstr = 'client'
	elseif(mode == NTP_MODE_SERVER) then
		mstr = 'server'
	elseif(mode == NTP_MODE_BROADCAST) then
		mstr = 'broadcast'
	elseif(mode == NTP_MODE_NTP_CTL) then
		mstr = 'NTP control message'
	elseif(mode == NTP_MODE_PRIVATE) then
		mstr = 'private'
	else
		mstr = string.format("UNKNOWN NTP mode - %d", mode)
	end

	return mstr
end


----------------------------------------------------------------------
-- Routine:	ntp.refid2ipaddr()
--
-- Purpose:	This function translates an NTP reference id value into an
--		IPv4 address string.  The text string is then returned to
--		the caller.
--
function ntp.refid2ipaddr(refid)

	local octet1			-- Address octet 1.
	local octet2			-- Address octet 2.
	local octet3			-- Address octet 3.
	local octet4			-- Address octet 4.
	local addrstr			-- Dotted string form of address.

--	octet1, octet2, octet3, octet4 = string.match(refid, "(%d+).(%d+).(%d+).(%d+)")

	octet1 = bit32.band(refid, 0xff000000)
	octet1 = bit32.rshift(octet1, 24)

	octet2 = bit32.band(refid, 0x00ff0000)
	octet2 = bit32.rshift(octet2, 16)

	octet3 = bit32.band(refid, 0x0000ff00)
	octet3 = bit32.rshift(octet3, 8)

	octet4 = bit32.band(refid, 0x000000ff)

	addrstr = string.format("%d.%d.%d.%d", octet1, octet2, octet3, octet4)

	return addrstr

end


----------------------------------------------------------------------
-- Routine:	ntp.stratum2str()
--
-- Purpose:	This function translates an NTP stratum value into a
--		string.  The text string is then returned to the caller.
--
--		Examples:
--			- 0  -> okay
--			- 1  -> last minute 61 seconds
--			- 2  -> last minute 59 seconds
--			- 3  -> clock unsynchronized
--
function ntp.stratum2str(stratum)

	local sstr				-- Stratum string.

	if((stratum == nil) or (stratum == '')) then
		sstr = string.format("UNKNOWN NTP stratum - no stratum given")
		return sstr
	end

	if((stratum < NTP_STRATUM_INVALID) or (stratum > NTP_STRATUM_RES_MAX)) then
		sstr = string.format("NTP stratum out of range -- %d", stratum)
		return sstr
	end

	if(stratum == NTP_STRATUM_INVALID) then
		sstr = 'unspecified or invalid'
	elseif(stratum == NTP_STRATUM_PRIMARY) then
		sstr = 'primary server'
	elseif((stratum >= NTP_STRATUM_SEC_MIN) and (stratum <= NTP_STRATUM_SEC_MAX)) then
		sstr = 'secondary server'
	elseif(stratum == NTP_STRATUM_UNSYNCH) then
		sstr = 'unsynchronized'
	elseif((stratum >= NTP_STRATUM_RES_MIN) and (stratum <= NTP_STRATUM_RES_MAX)) then
		sstr = 'reserved'
	else
		sstr = string.format("UNKNOWN NTP stratum - %d", stratum)

	end

	return sstr
end


----------------------------------------------------------------------
-- Routine:	ntp.log()
--
-- Purpose:	This function logs the saved contents of a NTP header.
--
function ntp.log(pkt)

	local srcdst			-- Source/destination string.
	local qtstr			-- Query-type string.

	--
	-- Ensure we weren't called for a non-NTP packet.
	--
	if(pkt['ntp'] == nil) then
		loggit("ntp.log() called for non-NTP packet\n")
		return
	end

	--
	-- Build a source/destination address string.
	--
	srcdst = tostring(pkt['pinfo'].srcaddr) ..  " || " ..  tostring(pkt['pinfo'].dstaddr)
	loggit(srcdst .. "\n")

	loggit("NTP fields:\n")

	out = string.format("0x%02x", pkt['ntp'].flags)
	loggit("\tflags           - " .. out .. "\n")

	loggit("\t\tleap          - " .. ntp.leap2str(pkt['ntp'].leap) .. "    (" .. string.format("%01x", pkt['ntp'].leap) .. ")" .. "\n")
	loggit("\t\tversion       - " ..  string.format("%d", pkt['ntp'].version) .. "\n")
	loggit("\t\tmode          - " .. ntp.mode2str(pkt['ntp'].mode) .. "    (" .. string.format("%01x", pkt['ntp'].mode) .. ")" .. "\n")

	loggit("\tstratum         - " .. ntp.stratum2str(pkt['ntp'].stratum) .. "    (" .. pkt['ntp'].stratum .. ")" .. "\n")

	loggit("\tpoll            - " .. pkt['ntp'].poll .. "\n")
	loggit("\tprecision       - " .. string.format("%d   (0x%0x)\n", pkt['ntp'].precision, pkt['ntp'].precision))

	loggit("\troot delay      - " .. string.format("0x%04x\n", pkt['ntp'].delay))
	loggit("\tdispersion      - " .. string.format("0x%04x\n", pkt['ntp'].dispersion))

	loggit("\treference id    - " .. pkt['ntp'].refid .. "\n")

	loggit("\treference tstmp - " .. pkt['ntp'].reftstmp .. "\n")
	loggit("\torigin tstmp    - " .. pkt['ntp'].origintstmp .. "\n")
	loggit("\treceive tstmp   - " .. pkt['ntp'].recvtstmp .. "\n")
	loggit("\ttransmit tstmp  - " .. pkt['ntp'].xmittstmp .. "\n")

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
	log:write("\n\nSaving NTP-Flow data\n")

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

	log:write("\nfinished writing NTP Flow save file \"" ..  newfile .. "\"\n")
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
--		few of those fields are being used by the NTP parser.
--
function tap.packet(pinfo,tvb)

	local srcprt		-- Source port.
	local dstprt		-- Destination port.

	local pkt		-- Saved info for this packet.

	--
	-- Keep track of the total number of packets we've seen.
	--
	packetcnt = packetcnt + 1

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
	-- Filter out everything but NTP packets.
	--
	if((srcprt ~= PORT_NTP) and (dstprt ~= PORT_NTP))
	then
		return
	end

	--
	-- Keep track of the total number of NTP packets we've seen.
	--
	ntppacketcnt = ntppacketcnt + 1

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
	-- At long last, we come to the NTP data.
	--
	ntp.parse(pkt, tvb)


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
	if(logntp   == true) then ntp.log(pkt)		end

end


----------------------------------------------------------------------
-- Routine:	tap.draw()
--
-- Purpose:	This function reports the results of the packet recording.
--
function tap.draw(t)

	--
	-- Display the NTP flows.
	--
	if(op_ntpflows == true) then

		--
		-- Write each ntp-flow's info to the NTP Flow window.
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
	end

	print ""
	print "NTP packets:"
	print "packet number\tmode\t\tflags\tstratum\tpoll\tprecision"
	for ind, pkt in ipairs(packets) do
		local out

		out = string.format("\t%d:\t%s\t\t%01x\t%01x\t%01x\t%01x\t%s", ind, ntp.mode2str(pkt['ntp'].mode), pkt['ntp'].leap, pkt['ntp'].stratum, pkt['ntp'].poll, pkt['ntp'].precision, ntp.refid2ipaddr(pkt['ntp'].refid))

--		out = string.format("\t%d:", ind)
--
--		for key, val in pairs(ntp) do
--			out = string.format("%s\t\t%s - <%s>", out, key, val)
--		end
--
--		out = string.format("%s\n", out)
--
--		out = string.format("\t%d:  %s", ind, pkt. ntp)

		print(out)

	end

	print "end packets\n"

end

----------------------------------------------------------------------
-- Routine:	tap.reset()
--
-- Purpose:	This function will be called whenever a reset is
--		needed; e.g., when reloading the capture file.
--
function tap.reset()

end

