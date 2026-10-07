using Fixture.Game;

namespace Consumer;

/// <summary>Uses TestFixture from another assembly: cross-assembly and virtual-dispatch references.</summary>
public class Arena
{
    public void Hit(IDamageable target) => target.TakeDamage(5);

    public int Total(Entity entity) => entity.Score();

    public Player Spawn() => new("spawned");

    public bool TryBuy(Shop shop) => shop.Buy("sword");

    public string NameOf(Entity entity) => entity.Name;
}

public class Minion : Entity
{
    public override void Tick(float dt) { }
}
