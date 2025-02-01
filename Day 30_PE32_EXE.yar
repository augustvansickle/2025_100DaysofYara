rule MAL__PE32_GuLoaderInstaller_EXE_dfb9d2234149f933add8bb7682094fa32430f41f34061b077776cecaa0a7ce16 {

	meta:
	author = "august"
	derscription = "PE32 EXE GuLoaderInstaller dfb9d2234149f933add8bb7682094fa32430f41f34061b077776cecaa0a7ce16"
	
	strings:
	
		$a1 = "http://nsis.sf.net/NSIS_Error"
		$a2 = "CoTaskMemFree"
		$a3 = "OpenProcessToken"
		$a4 = "AdjustTokenPrivileges"
		$a5 = "RegCreateKeyExW"
		$a6 - "ShellExecuteW"
		$h1 = { 1a 0a 46 4f c3 cf df 83 }
		
	condition:
	
		(2 of($a1, $a2, $a3, $a4, $a5, $a6, $h1))
		
	}