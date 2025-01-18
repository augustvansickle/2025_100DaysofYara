import "pe"
rule MAL_PE32_EXE_RedLine_6439c8e94bd2398ad15bd8cbf86a9ca9528cecf77506357e894a359880282724 {

meta:
author = "august"
description = "PE32 EXE Redline 6439c8e94bd2398ad15bd8cbf86a9ca9528cecf77506357e894a359880282724"

strings:

	$a1 = "http://wap.5184.com/NCEE_WAP/controller/examEnquiry/performExamEnquiryWithoutAuthForGZ?categoryCode=CE_1&examReferenceNo={0}&bir" 
	$a2 = "C:\Program Files (x86)\VideoLAN\VLC\vlc.exe" 
	$a3 = "get_Urls" 
	$a4 = "AsyncCallback"
	$a5 = { BeginOutputReadLine }
	$h1 = { 75 ff 42 65 72 ff 6c 75 }
	$h2 = { 72 8d 06 00 70 a2 25 1f }

condition:

	(2 of ($a1, $a2, $a3, $a4, $a5, $h1, $h2))
	
}