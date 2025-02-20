rule MAL__PE32_58c658ce7e6aa0191b25261fe17b2a31142144fcd087db156989edd31cf05cd8 {

	meta:
	author = "august"
	description = "PE32 58c658ce7e6aa0191b25261fe17b2a31142144fcd087db156989edd31cf05cd8"
	
	strings:
	
		$a1 = "EpisodP.exe"
		$a2 = "VS_VERSION_INFO"
		$a3 = "PADPADP"
		$a4 = "Form1"
		$a5 = "$this.Icon"
		$a6 - "AskProject.Properties.Resources"
		
	condition:
	
		(2 of($a1, $a2, $a3, $a4, $a5, $a6))
		
	}