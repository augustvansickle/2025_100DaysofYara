import "pe"

rule MAL_PE32_StormKittyStealer7388bd02332034dd82ec77ada93a9dc74ddf184ce5dafa5796a6404137285eed {

meta:
author = "august"
description = "PE32 7388bd02332034dd82ec77ada93a9dc74ddf184ce5dafa5796a6404137285eed"

strings:

	$a1 = "processhacker" 
	$a2 = "https://raw.githubusercontent.com/LimerBoy/StormKitty/master/StormKitty/stub/packages/DotNetZip.1.13.8/lib/net40/DotNetZip.dll" 
	$a3 = "\\FileZilla"
	$a4 = "/C chcp 65001 && netsh wlan show profile | findstr All"
	$a5 = "https://api.telegram.org/file/bot"
	$a6 = "https://pastebin.com/raw/7B75u64B"
	$h1 = { 00  65  00  74  00  3D  00  7B  00 }

condition:

	(2 of ($a1, $a2, $a3, $a4, $a5, $a6, $h1))
	
}