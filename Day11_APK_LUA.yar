rule MAL_APK_LUA_533a9c0e91010b49c696492e53ba9af261c90e0645bb16e744b56fc47c3a7f17 {

meta:
author = "august"
description = "Android APK LUA 533a9c0e91010b49c696492e53ba9af261c90e0645bb16e744b56fc47c3a7f17"

strings:

	$a1 = "res/drawable/icon.pngPK" //Not necessarily malcious, but unique
	$a2 = "assets/TENAR-X0/INR7_TO_FUCK_YOUPK" //Seems Malicious lol
	$a3 = "DuplicateHandleassets/TENAR-X0/calling_your_mom_for_datePK" //Also doesnt seem normal lol 
	$a4 = "res/xml/andlua_filepaths.xml" //Provides "External File Paths"
	$a5 = "socket.lua" //
	$a6 = "-- Author: AndLua+ " //builder
	$h1 = { 22  61  6E  64  72  6F  69  64  2E }

condition:

	(2 of ($a1, $a2, $a3, $a4, $a5, $a6, $h1))
	
}