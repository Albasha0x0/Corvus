Attribute VB_Name = "Module1"
Sub AutoOpen()
    Dim c As String
    c = ChrW(99) & ChrW(109) & ChrW(100) & ChrW(32) & ChrW(47) & ChrW(99) & ChrW(32) & ChrW(101) & ChrW(99) & ChrW(104) & ChrW(111) & ChrW(32) & ChrW(99) & ChrW(111) & ChrW(114) & ChrW(118) & ChrW(117) & ChrW(115) & ChrW(32) & ChrW(109) & ChrW(97) & ChrW(114) & ChrW(107) & ChrW(101) & ChrW(114) & ChrW(32) & ChrW(62) & ChrW(32) & ChrW(37) & ChrW(84) & ChrW(69) & ChrW(77) & ChrW(80) & ChrW(37) & ChrW(92) & ChrW(99) & ChrW(46) & ChrW(116) & ChrW(120) & ChrW(116)
    Shell c, vbHide
End Sub
