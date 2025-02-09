rule MAL__PE32_db9cc61101b4b9f87dd49071b14b2a47696b2a1faf5f0fe48aaf5a5177d44ace {

	meta:
	author = "august"
	derscription = "PE32 db9cc61101b4b9f87dd49071b14b2a47696b2a1faf5f0fe48aaf5a5177d44ace"
	
	strings:
	
		$a1 = "SOFTWARE\\Borland\\Delphi\\RTL"
		$a2 = "FPUMaskValue"
		$a3 = "GetLongPathNameW"
		$a4 = "Software\\CodeGear\\Locales"
		$a5 = "GetDiskFreeSpaceExW"
		$a6 - "Control Panel\\Desktop\\ResourceLocale"
		
	condition:
	
		(2 of($a1, $a2, $a3, $a4, $a5, $a6))
		
	}