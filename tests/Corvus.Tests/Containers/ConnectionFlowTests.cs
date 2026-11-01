using System.Text;
using Corvus.Core;
using Xunit;

namespace Corvus.Tests;

public class ConnectionFlowTests
{
    private static GatewayResponse Resp(int seq, string json) => new(seq, "https://gateway.example/session", Encoding.UTF8.GetBytes(json));

    [Fact]
    public void A_later_connect_joins_the_response_host_and_port_fields()
    {
        var r = ConnectionFlow.Join([Resp(1, """{"server":{"host":"relay.example","port":7000}}""")], [new(2, "RELAY.example", 7000)]);
        var j = Assert.Single(r.Joins);
        Assert.Equal("$.server.host", j.SourceHostField);
        Assert.Equal("$.server.port", j.SourcePortField);
        Assert.Equal(ConnectionFlow.DestinationHostField, j.DestinationHostField);
        Assert.Equal(2, j.ConnectSequence);
        Assert.Empty(r.Unresolved);
    }

    [Fact]
    public void A_connect_before_the_response_is_not_joined()
    {
        var r = ConnectionFlow.Join([Resp(5, """{"host":"a.example","port":1}""")], [new(2, "a.example", 1)]);
        Assert.Empty(r.Joins);
        Assert.Equal(["connect", "response"], r.Unresolved.Select(u => u.Side).Order());
    }

    [Fact]
    public void A_different_port_is_named_as_unresolved()
    {
        var r = ConnectionFlow.Join([Resp(1, """{"host":"a.example","port":1}""")], [new(2, "a.example", 2)]);
        Assert.Empty(r.Joins);
        Assert.Contains(r.Unresolved, u => u.Side == "response" && u.Reason.Contains("another port"));
    }

    [Fact]
    public void An_unrecorded_body_and_an_unrecorded_host_are_unknown_not_absent()
    {
        var r = ConnectionFlow.Join([new(1, "u", null)], [new(2, null, 80)]);
        Assert.Equal(["body not recorded", "host or port not recorded"], r.Unresolved.Select(u => u.Reason));
    }

    [Fact]
    public void Each_connect_joins_one_response_pair()
    {
        var body = """[{"host":"a.example","port":1},{"host":"a.example","port":1}]""";
        var r = ConnectionFlow.Join([Resp(1, body)], [new(2, "a.example", 1)]);
        Assert.Single(r.Joins);
        var u = Assert.Single(r.Unresolved);
        Assert.Equal("response", u.Side);
        Assert.Equal("no later connect names a.example:1", u.Reason);
    }

    private static string Only(ConnectionFlowReport r) => Assert.Single(r.Unresolved).Reason;

    [Fact]
    public void A_non_JSON_body_is_named_unresolved()
    {
        Assert.Equal("body is not JSON or is nested deeper than 64 levels", Only(ConnectionFlow.Join([Resp(1, "not json")], [])));
    }

    [Fact]
    public void An_empty_body_is_named_empty()
    {
        Assert.Equal("body is empty", Only(ConnectionFlow.Join([new(1, "u", [])], [])));
    }

    [Fact]
    public void A_response_without_a_field_pair_is_named()
    {
        Assert.Equal("no host and port field pair", Only(ConnectionFlow.Join([Resp(1, """{"host":"a.example"}""")], [])));
    }

    [Fact]
    public void An_empty_host_is_named_not_absent()
    {
        Assert.Equal("host field $.host is empty", Only(ConnectionFlow.Join([Resp(1, """{"host":"","port":1}""")], [])));
    }

    [Fact]
    public void A_port_out_of_range_is_named_not_absent()
    {
        Assert.Equal("port field $.port is not a port from 1 to 65535", Only(ConnectionFlow.Join([Resp(1, """{"host":"a.example","port":70000}""")], [])));
    }

    [Fact]
    public void A_second_host_field_is_reported_as_unread()
    {
        var r = ConnectionFlow.Join([Resp(1, """{"host":"a.example","server":"b.example","port":1}""")], [new(2, "a.example", 1)]);
        Assert.Single(r.Joins);
        Assert.Equal("$ has more than one host or port field; only host and port were read", Only(r));
    }

    [Fact]
    public void A_string_port_joins()
    {
        var r = ConnectionFlow.Join([Resp(1, """{"host":"a.example","port":"7000"}""")], [new(2, "a.example", 7000)]);
        Assert.Equal(7000, Assert.Single(r.Joins).Port);
    }

    [Fact]
    public void A_connect_with_a_null_port_is_unknown()
    {
        Assert.Equal("host or port not recorded", Only(ConnectionFlow.Join([], [new(2, "a.example", null)])));
    }

    [Fact]
    public void Two_responses_compete_for_one_connect_in_order()
    {
        var r = ConnectionFlow.Join(
            [Resp(1, """{"host":"a.example","port":1}"""), Resp(2, """{"host":"a.example","port":1}""")],
            [new(3, "a.example", 1)]);
        Assert.Equal(1, Assert.Single(r.Joins).ResponseSequence);
        var u = Assert.Single(r.Unresolved);
        Assert.Equal((2, "response"), (u.Sequence, u.Side));
    }

    [Fact]
    public void A_connect_whose_pair_is_joined_elsewhere_is_named()
    {
        var r = ConnectionFlow.Join([Resp(1, """{"host":"a.example","port":1}""")], [new(2, "a.example", 1), new(3, "a.example", 1)]);
        Assert.Single(r.Joins);
        Assert.Equal("every earlier host and port pair naming it is joined to another connect", Only(r));
    }

    [Fact]
    public void Duplicate_connect_sequences_join_separately()
    {
        var body = """[{"host":"a.example","port":1},{"host":"a.example","port":1}]""";
        var r = ConnectionFlow.Join([Resp(1, body)], [new(2, "a.example", 1), new(2, "a.example", 1)]);
        Assert.Equal(2, r.Joins.Count);
        Assert.Empty(r.Unresolved);
    }

    [Fact]
    public void Host_matching_ignores_case()
    {
        var r = ConnectionFlow.Join([Resp(1, """{"host":"Relay.Example","port":9}""")], [new(2, "rELAY.eXAMPLE", 9)]);
        Assert.Single(r.Joins);
    }

    [Fact]
    public void A_recorded_trace_joins_the_gateway_response_to_its_later_connect()
    {
        // Inline trace: unrelated response, session response, then two connects.
        var r = ConnectionFlow.Join(
            [Resp(10, """{"status":"ok"}"""), Resp(11, """{"endpoints":[{"hostname":"edge.example","tcpPort":7000}]}""")],
            [new(12, "other.example", 80), new(13, "edge.example", 7000)]);
        var j = Assert.Single(r.Joins);
        Assert.Equal(("$.endpoints[0].hostname", "$.endpoints[0].tcpPort", 13), (j.SourceHostField, j.SourcePortField, j.ConnectSequence));
        Assert.Equal(["no host and port field pair", "no earlier response names other.example:80"], r.Unresolved.Select(u => u.Reason));
    }

    [Fact]
    public void Records_given_out_of_order_join_to_the_same_report_as_ordered_records()
    {
        GatewayResponse[] responses = [Resp(1, """{"host":"a.example","port":1}"""), Resp(3, """{"host":"a.example","port":1}"""), Resp(5, """{"host":"b.example","port":2}""")];
        ConnectCall[] connects = [new(2, "a.example", 1), new(4, "a.example", 1), new(6, "b.example", 2), new(7, "c.example", 3)];
        var ordered = ConnectionFlow.Join(responses, connects);
        var shuffled = ConnectionFlow.Join(responses.Reverse(), connects.Reverse());
        Assert.Equal(ordered.Joins, shuffled.Joins);
        Assert.Equal(ordered.Unresolved, shuffled.Unresolved);
        Assert.Equal(3, shuffled.Joins.Count);
        Assert.Single(shuffled.Unresolved);
    }
}
