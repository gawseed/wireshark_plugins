--
-- packet-flows.lua
--
--	This script is a plugin for Wireshark and tshark.  It displays a
--	set of the packet flows between a pair of hosts.  Each port used
--	in the communication is included, along with the elapsed time from
--	the beginning of the packet capture until that particular packet
--	was sent.
--
--	This program will register a menu item in the Tools/GAWSEED menu.
--
--	Some debugging info may be written to a script-specific log file.
--	The filename is defined in the LOGFILE directory.  Set it as desired.
--
-- Revision History
--	1.0 Initival revision.					190120
--

--
-- Version information.
--
NAME   = "packet-flows";
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

local debug = 0					-- Flag for *some* logging.

local LOGFILE = "/tmp/save.packet-flows"	-- General log file.

local SAVELOG = "/tmp/pf.log"			-- Log file for saving flows.

if(debug ~= 0) then
	local loggy = io.open(LOGFILE,"a")
	if loggy ~= nil then
		loggy:write("\npacket-flows.lua:  down in\n\n")
		io.close(loggy)
	end                
end                

------------------------------------------------------------------------------

local function menuable_tap()

	local pktwind = nil			-- Window for packet flows.

	local tap = Listener.new()		-- The network tap.

	local ips = {}				-- Hash of src/dest counters.
	local prots = {}			-- Hash of protocol counters.

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

		log = io.open("/tmp/pf.log","a")
		log:write("\n\nSaving Packet-Flow data\n")

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

		log:write("\nfinished writing Packet Flow save file \"" ..  newfile .. "\"\n")

		io.close(log)

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
	--		few of those fields are being used by packet-flows.
	--		Maybe we'll make use of this extra data in the future.
	--
	function tap.packet(pinfo,tvb)

		local srcdst		-- Table key.
		local srcdstports	-- Addressing info.
		local pr		-- Current count for src or dest port.

		local srcprt		-- Source port.
		local dstprt		-- Destination port.

		local logger		-- I/O object for logging.

		--
		-- Build the table key.  This consists of the source IP
		-- address and the destination IP address.
		--
		srcdst = tostring(pinfo.src) ..  " || " ..  tostring(pinfo.dst)

		--
		-- Build a string with the connection info.  This consists of
		-- the source IP address, the source port, the destination IP
		-- address and the destination port -- all with various
		-- separators.
		--
		srcdstports = tostring(pinfo.src)		 	     ..
				 "("	.. tostring(pinfo.src_port)   .. ")" ..
				 " || "	.. tostring(pinfo.dst)		     ..
				 "("	.. tostring(pinfo.dst_port)   .. ")"

		--
		-- Get the current count for this source/dest pair.
		--
		paircnt = ips[srcdst] or 0

		--
		-- Get the source port.
		--
		srcprt = pinfo.src_port

		--
		-- Get the destination port.
		--
		dstprt = pinfo.dst_port

		--
		-- Filter out the ports we don't care about; turned off
		-- by default.
		-- (This was just done for testing, but is left here in
		-- case it's useful in future.)
		--
		local nofiltering = nil
		if(nofiltering ~= nil) then
			if(((srcprt ~= 993) and (dstprt ~= 993)) and
			   ((srcprt ~= 53) and (srcprt ~= 53)))
			then
				return
			end
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
		-- Get the current count for the destination port.
		--
--		pr = prots[tostring(pinfo.src_port)] or 0
		pr = prots[tostring(pinfo.dst_port)] or 0

		--
		-- Find the appropriate source/destination group, even if
		-- this is a destination's response.  If there's already a
		-- collector table for dst/src, we'll use it.  If not, we
		-- can safely assume that src/dst should be used.
		--
		addrs = tostring(pinfo.dst) ..  " || " ..  tostring(pinfo.src)
		if(collector[addrs] == nil) then
			addrs = srcdst
		end

		--
		-- Bump the source/dest counter and squirrel it away.
		-- We aren't doing anything with this right now.
		--
		ips[addrs] = paircnt + 1

		--
		-- Record the count of protocol uses.
		-- We aren't doing anything with this right now.
		--
--		prots[tostring(pinfo.src_port)] = pr + 1
		prots[tostring(pinfo.dst_port)] = pr + 1

		--
		-- Initialize a list if the source/destination collector
		-- entry doesn't exist yet.
		--
		if(collector[addrs] == nil) then
			collector[addrs] = {}
		end

		--
		-- Save a few pieces of data from the packet.
		--
		pkt = {}
		pkt.src     = pinfo.src
		pkt.dst     = pinfo.dst
		pkt.port    = dstprt
		pkt.reltime = pinfo.rel_ts
		table.insert(collector[addrs], pkt)

		--
		-- Log some of the packet contents.
		--
		logger = io.open(LOGFILE,"a")
		if logger ~= nil then

			logger:write("\n----------------------------\n")

--			logger:write("src - <" .. tostring(pinfo.src) .. ">\t\tport - <" .. tostring(pinfo.src_port) .. ">\n")
--			logger:write("dst - <" .. tostring(pinfo.dst) .. ">\t\tport - <" .. tostring(pinfo.dst_port) .. ">\n")

			logger:write("src - <" .. tostring(pinfo.src) .. ">\t\tport - <" .. ports[pinfo.src_port] .. ">\n")
			logger:write("dst - <" .. tostring(pinfo.dst) .. ">\t\tport - <" .. ports[pinfo.dst_port] .. ">\n")

			logger:write("pnum - ", pinfo.number, "\trelative time - ", pinfo.rel_ts, "\n")

			logger:write("\ntvb - <" .. tostring(tvb) .. ">\n")

			io.close(logger)

		end

	end

	----------------------------------------------------------------------
	-- Routine:	tap.streamsaver()
	--
	-- Purpose:	This function initiates the saving of the packet
	--		streams to a file.  It creates a dialog box, passing
	--		it a reference to dlgsaver().  That routine gets and
	--		validates a filename for the new file, then saves the
	--		flow data to it.
	--
	function streamsaver(t)

		new_dialog("Packet Flows Saved", dlgsaver, "Enter Save File")

	end

	----------------------------------------------------------------------
	-- Routine:	tap.draw()
	--
	-- Purpose:	This function updates packet-flow's window with
	--		new data.  It is called once every few seconds.
	--
	function tap.draw(t)

		--
		-- Create the Packet Flows window if it hasn't been created.
		-- We'll also arrange to call remove() when window is closed.
		--
		if(pktwind == nil) then
			pktwind = TextWindow.new("Packet Flows")

			pktwind:set_atclose(remove)

			pktwind:add_button("Save Data", streamsaver)
		end

		--
		-- Clear the window contents.
		--
		pktwind:clear()

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

			pktwind:append("\n----------------------------------------------------------\n")

			pktwind:append("Originator || Target:  " .. tostring(srcdst) .. "\n\n")
			pktwind:append("Packets:\n")

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

			pktwind:append(out)

			--
			-- Build the packet lines and display them.
			--
			for pnum, val  in pairs(pkt) do

out = string.format(srcfmt .. dstfmt .. "%-4s\t%7.5f\n", tostring(val.src), tostring(val.dst), tostring(val.port), val.reltime)
				pktwind:append(out)
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

		if(pktwind ~= nil) then
			pktwind:clear()
		end

		ips = {}

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
register_menu("GAWSEED/Packet Flows", menuable_tap, MENU_TOOLS_UNSORTED)


