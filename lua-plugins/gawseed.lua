--
-- gawseed.lua	
--	This script will run a set of GAWSEED-specific UA scripts for
--	Wireshark.  It consults a config file in the user's ~/.wireshark
--	directory, and runs the scripts listed therein.
--
--	This is an initial version of this, so not much validation or
--	checking is performed on the scripts listed in the config file.
--	Care must be taken to protect those scripts and only list scripts
--	known to be safe.
--
-- This program will register a menu that will open a window with a count of
-- occurrences of every address in the capture.
--

local GAWLOG = "/tmp/z"				-- The GAWSEED log file.

local GAWCONFFILE = "/gawseed.conf"		-- The GAWSEED config file.

----------------------------------------------------------------------
-- Routine:	fexists()
--
-- Purpose:	This routine returns a boolean indicating if the specified
--		file exists.  It checks this by trying to open the file for
--		reading.
--
--		This doesn't *exactly* check for file existence.  However,
--		this script (almost exactly) was recommended by the creator
--		of Lua.
--
local function fexists(fname)

	local f = io.open(fname,"r")

	if(f ~= nil) then
		io.close(f)
		return true
	end

	return false
end


----------------------------------------------------------------------
-- Routine:	gawseed_main()
--
local function gawseed_main()

	local glog				-- GAWSEED log file.
	local loaders = {}			-- List of files to load.
	local loadcnt = 0			-- Count of loader files.

	--
	-- Open our log file.
	--
	glog = io.open(GAWLOG,"a")
	glog:write("initializing GAWSEED-specific code\n\n")

	--
	-- Get a shorthand to the user's .wireshark directory.
	--
	USER_DIR = Dir.personal_config_path()..package.config:sub(1,1)

	--
	-- Build the name of the user's GAWSEED configuration file.
	--
	gawconf = USER_DIR .. GAWCONFFILE
	glog:write("GAWSEED config file - " .. gawconf .. "\n\n")

	--
	-- If the GAWSEED config file doesn't exist, we'll return now.
	--
	if(fexists(gawconf) == false) then
		glog:write("gawconf (" .. gawconf .. ") does not exist\n")
		io.close(glog)

		return
	end

	--
	-- Read and handle the GAWSEED config file.
	--
--	glog:write("config:\n")
	for line in io.lines(gawconf) do

		local first = 0

--		glog:write("\t<" .. line .. ">\n")

		--
		-- Find the first non-whitespace character in the line.
		--
		nonws = string.find(line, "%S")

		--
		-- If the line isn't completely whitespace, we'll parse it
		-- to find:
		--		- comment lines
		--		- load lines
		--
		if(nonws ~= nil) then

			--
			-- Strip off initial spaces.
			--
			line = string.sub(line, nonws, -1)

			--
			-- Look for a comment line.
			--
			if(string.find(line, "^[-][-]") or
			   string.find(line, "^#")) then

				--
				-- Do nothing.
				--
				line = line

			else

				_,_,cmd,args = string.find(line, "(%S+)%s+(.*)")

				if(cmd == nil) then
					cmd = "<none>"
				end

				if(args == nil) then
					args = "<none>"
				end

				if(cmd == "load") then

					loadcnt = loadcnt + 1
					loaders[loadcnt] = args

				else

					glog:write("\t\tunknown cmd \"" .. cmd .. "\"\n")

				end

			end

		else
			--
			-- We're ignoring blank lines.
			--

		end

	end

	--
	-- If any GAWSEED load modules were specified, we'll g'head and
	-- load them now.
	--
	if(loadcnt > 0) then

		for ind in ipairs(loaders) do

			ldfile = USER_DIR .. loaders[ind]

			glog:write("loading \"" .. ldfile .. "\"\n")

			dofile(ldfile)

		end

	end

	glog:write("GAWSEED-specific initializing complete\n\n")
	io.close(glog)
end

--
-- Set up the GAWSEED-specific things.
--
gawseed_main()

