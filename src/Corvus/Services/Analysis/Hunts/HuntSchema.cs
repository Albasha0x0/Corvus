namespace Corvus.Services.Analysis.Hunts;

/// <summary>The columns the queries may name, from the Defender XDR advanced hunting and Azure Monitor Logs reference pages.</summary>
public static class HuntSchema
{
    // Columns every device table lists, then the process columns of the initiating process.
    private const string Device = "Timestamp:datetime,DeviceId:string,DeviceName:string,ActionType:string,ReportId:long,AppGuardContainerId:string";

    private const string FileColumns = "FileName:string,FolderPath:string,SHA1:string,SHA256:string,MD5:string,FileSize:long";

    private const string Initiating =
        "InitiatingProcessAccountDomain:string,InitiatingProcessAccountName:string,InitiatingProcessAccountSid:string," +
        "InitiatingProcessAccountUpn:string,InitiatingProcessAccountObjectId:string,InitiatingProcessMD5:string," +
        "InitiatingProcessSHA1:string,InitiatingProcessSHA256:string,InitiatingProcessFolderPath:string," +
        "InitiatingProcessFileName:string,InitiatingProcessFileSize:long,InitiatingProcessVersionInfoCompanyName:string," +
        "InitiatingProcessVersionInfoProductName:string,InitiatingProcessVersionInfoProductVersion:string," +
        "InitiatingProcessVersionInfoInternalFileName:string,InitiatingProcessVersionInfoOriginalFileName:string," +
        "InitiatingProcessVersionInfoFileDescription:string,InitiatingProcessId:long,InitiatingProcessCommandLine:string," +
        "InitiatingProcessCreationTime:datetime," +
        "InitiatingProcessParentId:long,InitiatingProcessParentFileName:string,InitiatingProcessParentCreationTime:datetime," +
        "InitiatingProcessSessionId:long,IsInitiatingProcessRemoteSession:bool,InitiatingProcessRemoteSessionDeviceName:string," +
        "InitiatingProcessRemoteSessionIP:string,InitiatingProcessUniqueId:string";

    private const string Elevation = "InitiatingProcessIntegrityLevel:string,InitiatingProcessTokenElevation:string";

    private static readonly IReadOnlyDictionary<string, string> Lists = new Dictionary<string, string>(StringComparer.Ordinal)
    {
        ["DeviceFileEvents"] = $"{Device},{FileColumns},{Initiating},{Elevation},AdditionalFields:string," +
            "FileOriginUrl:string,FileOriginReferrerUrl:string,FileOriginIP:string,PreviousFolderPath:string,PreviousFileName:string," +
            "RequestProtocol:string,RequestSourceIP:string,RequestSourcePort:int,RequestAccountName:string,RequestAccountDomain:string," +
            "RequestAccountSid:string,ShareName:string,SensitivityLabel:string,SensitivitySubLabel:string,IsAzureInfoProtectionApplied:bool,LogonID:long",
        ["DeviceProcessEvents"] = $"{Device},{FileColumns},{Initiating},{Elevation},AdditionalFields:string," +
            "ProcessVersionInfoCompanyName:string,ProcessVersionInfoProductName:string,ProcessVersionInfoProductVersion:string," +
            "ProcessVersionInfoInternalFileName:string,ProcessVersionInfoOriginalFileName:string,ProcessVersionInfoFileDescription:string," +
            "ProcessId:long,ProcessCommandLine:string,ProcessIntegrityLevel:string,ProcessTokenElevation:string,ProcessCreationTime:datetime," +
            "AccountDomain:string,AccountName:string,AccountSid:string,AccountUpn:string,AccountObjectId:string,LogonId:long," +
            "InitiatingProcessLogonId:long,InitiatingProcessSignerType:string,InitiatingProcessSignatureStatus:string," +
            "CreatedProcessSessionId:long,IsProcessRemoteSession:bool,ProcessRemoteSessionDeviceName:string,ProcessRemoteSessionIP:string," +
            "ProcessUniqueId:string,LogonID:long",
        ["DeviceImageLoadEvents"] = $"{Device},{FileColumns},{Initiating},{Elevation}",
        ["DeviceNetworkEvents"] = $"{Device},{Initiating},{Elevation},AdditionalFields:string," +
            "RemoteIP:string,RemotePort:int,RemoteUrl:string,LocalIP:string,LocalPort:int,Protocol:string,LocalIPType:string,RemoteIPType:string,LogonID:long",
        ["DeviceRegistryEvents"] = $"{Device},{Initiating},{Elevation},RegistryKey:string,RegistryValueType:string,RegistryValueName:string," +
            "RegistryValueData:string,PreviousRegistryKey:string,PreviousRegistryValueName:string,PreviousRegistryValueData:string",
        ["DeviceEvents"] = $"{Device},{FileColumns},{Initiating},AdditionalFields:string," +
            "AccountDomain:string,AccountName:string,AccountSid:string,RemoteUrl:string,RemoteDeviceName:string,ProcessId:long," +
            "ProcessCommandLine:string,ProcessCreationTime:datetime,ProcessTokenElevation:string,LogonId:long,RegistryKey:string," +
            "RegistryValueName:string,RegistryValueData:string,RemoteIP:string,RemotePort:int,LocalIP:string,LocalPort:int," +
            "FileOriginUrl:string,FileOriginIP:string,InitiatingProcessLogonId:long,CreatedProcessSessionId:long,IsProcessRemoteSession:bool," +
            "ProcessRemoteSessionDeviceName:string,ProcessRemoteSessionIP:string",
        ["DeviceFileCertificateInfo"] =
            "Timestamp:datetime,DeviceId:string,DeviceName:string,SHA1:string,IsSigned:bool,SignatureType:string,Signer:string," +
            "SignerHash:string,Issuer:string,IssuerHash:string,CertificateSerialNumber:string,CrlDistributionPointUrls:string," +
            "CertificateCreationTime:datetime,CertificateExpirationTime:datetime,CertificateCountersignatureTime:datetime," +
            "IsTrusted:bool,IsRootSignerMicrosoft:bool,ReportId:long",
        // Microsoft Sentinel table, from the Azure Monitor Logs reference page of Event.
        ["Event"] =
            "AzureDeploymentID:string,Computer:string,EventCategory:int,EventData:string,EventID:int,EventLevel:int,EventLevelName:string," +
            "EventLog:string,ManagementGroupName:string,Message:string,ParameterXml:string,RenderedDescription:string,_ResourceId:string," +
            "Role:string,Source:string,SourceSystem:string,_SubscriptionId:string,TimeGenerated:datetime,Type:string,UserName:string",
    };

    /// <summary>The table names, ordinal.</summary>
    public static IReadOnlyList<string> Tables { get; } = [.. Lists.Keys.Order(StringComparer.Ordinal)];

    /// <summary>The columns of <paramref name="table"/> as name and Kusto type (string, long, int, bool, datetime); empty for an unknown table.</summary>
    public static IReadOnlyList<(string Name, string Type)> Columns(string table) =>
        Lists.TryGetValue(table, out var list)
            ? [.. list.Split(',').Select(c => c.Split(':')).Select(p => (p[0], p[1])).DistinctBy(c => c.Item1, StringComparer.Ordinal)]
            : [];
}
