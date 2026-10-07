namespace Fixture.Game;

// Attribute arguments of every encodable kind: arrays, object, Type, enum.
[AttributeUsage(AttributeTargets.All, AllowMultiple = true)]
public sealed class TagsAttribute : Attribute
{
    public TagsAttribute(int[]? ids, object extra, Type kind, Team team) { }
    public string[]? Names { get; set; }
}

[Tags(new[] { 1, 2, 3 }, 5, typeof(Vec2), Team.Blue, Names = new[] { "a", "b" })]
public class Tagged
{
    [Tags(null, new[] { 0x3A7 }, typeof(int), (Team)7)]
    public void Marked() { }
}
