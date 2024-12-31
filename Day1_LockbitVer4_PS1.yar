import "pe"

rule MAL_RANSOM_Lockbit_Ver4_LBB_PS1 {

meta:
author = "august"
description = "Rule to detect PS1 file that loads win64 Lockbit4 PE"

strings:

$a1 = "[ref].Assembly.GetType('System.Management.Automation.Amsi' + 'Utils')" ascii wide
$a2 = "$ps86Args = @('-ex bypass', '-nonI', $psFile)"
$a3 = "Start-Process $ps86 $ps86Args -Window hidden"
$h1 = { 42 08 79 50 75 87 95 85}

condition:

$a1 and $a2 and $a3 and #h1 == 2

}