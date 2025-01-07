rule MAL_VBA_Ransomware_32f31b35179bbff9ca9dd21b43bfc3e585baafedde523bd3e4869400ab0362cb {

meta:
author = "august"
description = "VMA Payload to Deliver Ransomware 32f31b35179bbff9ca9dd21b43bfc3e585baafedde523bd3e4869400ab0362cb"

strings:

	$a1 = "netsh advfirewall firewall delet rule name=all\"" //designed to delete firewall rules
	$a2 = "wevtutil -cl \"\"Windows PowerShell" //use of LOLBIN wevtutil to clear logs"
	$a3 = "\"\\scripts\\disk.vbs"
	$a4 = "SELECT * FROM Win32_DiskPartition WHERE PrimaryPartition = TRUE and DiskIndex = 0" //querying for disk partitions (this is ransomware delivery)
	$a5 = "reg add \"\"HKLM\\SOFTWARE\\Policies\\Microsoft\\FVE\"\" /v EnableBDEWithNoTPM /t REG_DWORD /d 1 /f" //bitlocker on systems without TPM
	$a6 = "For Each Os in GetObject(\"winmgmts:\").ExecQuery(\"SELECT * FROM Win32_OperatingSystem\")\r\n\t\t\t\t\t\t\tos.Win32Shutdown(6)\r\n\t\t\t\t\t\t\tWScript.Sleep 6000000" //binary queries bitlocker and then forces a system shutdown with a sleep time
	$h1 = { 70 20 36 30 30 30 30 }

condition:

	(2 of ($a1, $a2, $a3, $a4, $a5, $a6, $h1))
	
}