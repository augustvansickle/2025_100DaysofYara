rule MAL_PE64_CobaltStrikeBeaconEXE_5a1f60003793dad17d116893de62b2258d83b636f17f813dfbf93299ff7c2c74 {

meta:
author = "august"
description = "PE64 Cobalt Strike Beacon EXE 5a1f60003793dad17d116893de62b2258d83b636f17f813dfbf93299ff7c2c74"

strings:

	$a1 = "Wow64DisableWow64FsRedirection" 
	$a2 = "This program must be run under Win32" 
	$a3 = "/VERYSILENT" 
	$a4 = "/SILENT" 
	$a5 = "name="JR.Inno.Setup"" 
	$a6 = "This program must be run under Win32"
	$h1 = { 7c 3c 41 00 5c 3c 41 00 }

condition:

	(2 of ($a1, $a2, $a3, $a4, $a5, $a6, $h1))
	
}

    