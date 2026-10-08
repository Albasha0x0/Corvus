using Fixture.Model;

namespace Consumer;

/// <summary>Uses TestFixture from another assembly: cross-assembly and virtual-dispatch references.</summary>
public class Branch
{
    public void Bill(IChargeable target) => target.Charge(5);

    public int Total(Entity entity) => entity.Score();

    public Account Open() => new("opened");

    public bool TryBuy(Shop shop) => shop.Buy("pen");

    public string NameOf(Entity entity) => entity.Name;
}

public class Archive : Entity
{
    public override void Tick(float dt) { }
}
