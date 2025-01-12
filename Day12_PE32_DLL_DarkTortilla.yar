import "pe"
rule MAL_PE32_DLL_DARKTORTILLAS_2bdf5181395313ddd75e8eb091ee06db85b2b7779cd97abc0b899c769ab96737 {

meta:
author = "august"
description = "PE32 DLL Tag:DarkTortilla 2bdf5181395313ddd75e8eb091ee06db85b2b7779cd97abc0b899c769ab96737"

strings:

	$a1 = "%WatchDogBytes%" 
	$a2 = "%StartupPersist%" 
	$a3 = "%InjectionPersist%" 
	$a4 = "set_AntiSandBoxie" 
	$a5 = "MofInagitap.dll" 
	$a6 = "%StartupFolder%" 
	$h1 = { 84  8D  48  D9  87  B8  96  62  6B }

condition:

	(2 of ($a1, $a2, $a3, $a4, $a5, $a6, $h1))
	
}