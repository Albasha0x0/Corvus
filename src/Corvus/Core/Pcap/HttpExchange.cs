using System.Globalization;

namespace Corvus.Core.Pcap;

/// <summary>One HTTP/2 or HTTP/3 request and its response as their field sections name them; unset fields keep their defaults.</summary>
internal class HttpExchange
{
    public string Method = "?", Path = "/", Authority = "", Scheme = "";
    public int Status;
    public string? Mime, Encoding;

    /// <summary>Takes the request pseudo-headers (and host) from the client's fields, status and content headers from the server's.</summary>
    public void Take(IEnumerable<(string Name, string Value)> fields, bool fromClient)
    {
        foreach (var (name, value) in fields)
        {
            if (fromClient)
            {
                switch (name)
                {
                    case ":method": Method = value; break;
                    case ":path": Path = value; break;
                    case ":authority": Authority = value; break;
                    case ":scheme": Scheme = value; break;
                    case "host" when Authority.Length == 0: Authority = value; break;
                }
            }
            else
            {
                switch (name)
                {
                    case ":status": _ = int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out Status); break;
                    case "content-type": Mime ??= value; break;
                    case "content-encoding": Encoding ??= value; break;
                }
            }
        }
    }
}
