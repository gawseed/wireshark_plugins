
Wireshark Plugins -- Lua Source

INTRODUCTION
============

This directory contains plugins for Wireshark that are written in Lua.

As currently set up, most of these plugins will live in the user's Wireshark
directory, which is ~/.wireshark.  We may want to have a system-level
directory for plugins; that shouldn't be difficult to put together.

On MacOS, the system-level directory for Wireshark is:

	/Applications/Wireshark.app/Contents/Resources/share/wireshark


		WARNING!!!!!!	Be sure to read and heed the warning
				in the init.lua description.


Once the files are installed in their proper places, Wireshark should be
restarted.  The new plugins are available in the GAWSEED submenu of the
TOOLS menu.


Caveat:  This is still early days for this code.  Don't expect miracles.  Yet.


HACKATHON Feb, 2018
===================

Several scripts were added for the project Hackathon in February, 2018.
These are:

	pcapsummary	Front-end for running the pcap-summarizer.lua PCAP
			summarizer in tshark.
			This script can be used as a model for using a
			specific set of files that will be used frequently.

	pcapsumm-times	Front-end for running the pcap-summarizer.lua PCAP
			summarizer in tshark.
			This script is an extension of pcapsummary, adding
			-start and -end options.

	pcapsumm-opts	Front-end for running the pcap-summarizer.lua PCAP
			summarizer in tshark.
			This script is an extension of pcapsummary, adding
			the -cidr, -timedir, and -slotlen options.

	pcap-summarizer.lua	A PCAP summarizer.

	pcap-grand-summary	This script takes a set of PCAP summaries
				(as produced by pcapsummary) and summarizes
				them for one grand summary.

FILES
=====

One standard Wireshark file must be modified, and a new file added to the
system's Wireshark configuration.

	init.lua	This is a standard Wireshark file that is run when
			Wireshark starts.  A single change was made to this
			file to run another Lua file.  These lines were
			added to the end of the file:

				--
				-- Run script for GAWSEED project.
				--
				dofile(DATA_DIR .. "gawseed.lua")

			WARNING:  The init.lua checked in here is from
				  Wireshark version 2.9.0 for MacOS.
				  It might not be a good idea to copy it
				  blindly over your own local init.lua.
				  It is meant as a reference for seeing
				  how the GAWSEED changes fit into the
				  rest of the file.

	gawseed.lua	This new script runs a set of scripts in the user's
			private Wireshark directory.  It is assumed they
			will be for the GAWSEED project, but they may be
			anything.


The rest of the files will live in the user's private Wireshark directory.

	gawseed.conf	This is the configuration file for GAWSEED-related
			plugins.  At present, It is only used to load LUA
			files into Wireshark.

			Comment lines start with either a near-universal
			pound sign ("#") or the Lua-standard double-dashes
			("--").

			The other lines are load lines, which look like
			"load file.lua".

			The gawseed.conf included here is a very simple
			version.

	packet-flows.lua
			This plugin will take the packets from a PCAP file
			and divide them into time-based packets flows between
			two hosts.

			This plugin is pretty generic and was more of a means
			of learning about Wireshark's plugin development.



New files as of 5/14/19:


	pcap-ntp.lua	Parser for NTP packets, for us with tshark.

	ntp-info	Front-end script for running pcap-ntp.lua.



