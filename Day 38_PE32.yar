rule MAL__PE32_f30ee6a3501cd62913db891d82a01d004bb3a528e269a3c49564ffd73251733c {

	meta:
	author = "august"
	derscription = "PE32 f30ee6a3501cd62913db891d82a01d004bb3a528e269a3c49564ffd73251733c"
	
	strings:
	
		$a1 = "AntiDisplayDownvirusProDisplayDownduct|ADisplayDownntiSpyDisplayDownWareProdDisplayDownuct|FirewaDisplayDownllProdDisplayDownuct"
		$a2 = "FromBase64"
		$a3 = "DownloadData"
		$a4 = "EncryptedData"
		$a5 = "set_CertificateValidationMode"
		$a6 - "GetImageBase"
		
	condition:
	
		(2 of($a1, $a2, $a3, $a4, $a5, $a6))
		
	}