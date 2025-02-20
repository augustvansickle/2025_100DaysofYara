rule MAL__PE32_ea49feb2417b506b1095ff67b609628df2d18d02ad68e1161cdf0608796923e6 {

	meta:
	author = "august"
	description = "PE32 ea49feb2417b506b1095ff67b609628df2d18d02ad68e1161cdf0608796923e6"
	
	strings:
	
		$a1 = "mysql"
		$a2 = "$E:\Cliente 3\Bin\Painel\libmysql.dll"
		$a3 = "@Lu30884639"
		$a4 = "deusumars@gmail.com10"
		$a5 = "*https://pki.codegic.com/crls/CodegicCA.crl0"
		$a6 - ",https://pki.codegic.com/crls/CodegicRoot.crl0"
		
	condition:
	
		(2 of($a1, $a2, $a3, $a4, $a5, $a6))
		
	}