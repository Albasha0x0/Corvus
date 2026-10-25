; Ledger sample: sums a few entries and writes a report.
#NoTrayIcon
Global Const $LEDGER_NAME = "cash"
Global $aEntries[3][2] = [[12.5, "paper"], [3, "ink"], [0x10, "stamps"]]

FileInstall("notes.txt", @TempDir & "\ledger-notes.txt")

Func Total(ByRef $aList)
	Local $fSum = 0
	For $i = 0 To UBound($aList) - 1
		$fSum += $aList[$i][0]
	Next
	Return $fSum
EndFunc

Func Label($fAmount)
	If $fAmount > 10 Then
		Return StringFormat("%s: %.2f", $LEDGER_NAME, $fAmount)
	ElseIf $fAmount = 0 Then
		Return "empty"
	Else
		Return "small"
	EndIf
EndFunc

Local $sReport = Label(Total($aEntries)) & @CRLF
Switch UBound($aEntries)
	Case 0
		$sReport &= "no entries"
	Case 1 To 5
		$sReport &= "few entries"
EndSwitch
ConsoleWrite($sReport & "Version " & @AutoItVersion & " 'quoted' ""double""" & @CRLF)
