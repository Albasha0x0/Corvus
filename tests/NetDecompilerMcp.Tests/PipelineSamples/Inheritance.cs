// A .NET Framework program for the pipeline round trip (PipelineRoundTripTests): a deep class hierarchy with
// virtual, abstract, sealed and hidden members, base calls, interface (re)implementation and type tests; its output depends only on its code.
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;

namespace Inheritance
{
    interface IDescribe { string Describe(); }
    interface IScore { int Score { get; } int Bonus(int level); }
    interface IReset { void Reset(); }

    abstract class Entity : IDescribe
    {
        protected readonly List<string> trace;
        protected int weight;

        protected Entity(List<string> trace, int weight)
        {
            this.trace = trace;
            this.weight = weight;
            // virtual call from the constructor: dispatches to the most derived override before its fields are set
            trace.Add("Entity.ctor sees Kind=" + Kind + " Init=" + InitValue());
        }

        public abstract string Kind { get; }
        protected virtual int InitValue() { return weight; }
        public virtual int Cost(int units) { return units * weight; }
        public string Describe() { return Kind + "/" + weight; }
        public string Label() { return "Entity.Label"; }

        public override string ToString() { return "<" + Kind + " w=" + weight + ">"; }

        public override bool Equals(object obj)
        {
            var other = obj as Entity;
            return other != null && other.GetType() == GetType() && other.weight == weight && other.Kind == Kind;
        }

        public override int GetHashCode()
        {
            // deterministic: does not depend on string.GetHashCode
            int h = 17;
            foreach (char c in Kind) h = unchecked(h * 31 + c);
            return unchecked(h * 31 + weight);
        }
    }

    class Vehicle : Entity, IScore
    {
        protected int wheels = 4;
        public Vehicle(List<string> t, int w) : base(t, w) { trace.Add("Vehicle.ctor wheels=" + wheels); }
        public override string Kind { get { return "vehicle"; } }
        public override int Cost(int units) { return base.Cost(units) + wheels; }
        public virtual int Score { get { return weight * 2; } }
        public int Bonus(int level) { return Score + level; }
        public new string Label() { return "Vehicle.Label"; }
    }

    class Car : Vehicle, IReset
    {
        int odometer;
        public Car(List<string> t, int w) : base(t, w) { odometer = 1000; trace.Add("Car.ctor odometer=" + odometer); }
        public override string Kind { get { return "car"; } }
        protected override int InitValue() { return odometer + 1; } // odometer is still 0 when called from Entity.ctor
        public override int Cost(int units) { return base.Cost(units) * 2; }
        public override int Score { get { return base.Score + odometer / 100; } }
        public void Reset() { odometer = 0; }
        public int Odometer { get { return odometer; } }
    }

    class SportsCar : Car, IScore
    {
        public SportsCar(List<string> t, int w) : base(t, w) { wheels = 4; }
        public override string Kind { get { return "sports"; } }
        public sealed override int Cost(int units) { return base.Cost(units) + 50; }
        // interface re-implementation: IScore.Bonus now maps here, not to Vehicle.Bonus
        public new int Bonus(int level) { return Score * level; }
        int IScore.Score { get { return -1; } } // explicit implementation shadows the class member through the interface
    }

    class RaceCar : SportsCar, IDescribe
    {
        readonly string team;
        public RaceCar(List<string> t, int w, string team) : base(t, w) { this.team = team; }
        public override string Kind { get { return "race"; } }
        public override int Score { get { return base.Score * 3; } }
        string IDescribe.Describe() { return "RaceCar[" + team + "] " + base.Describe(); }
        public new string Label() { return "RaceCar.Label"; }
    }

    sealed class Prototype : RaceCar, IReset
    {
        int resets;
        public Prototype(List<string> t, int w) : base(t, w, "lab") { }
        public override string Kind { get { return "proto"; } }
        void IReset.Reset() { resets++; Reset(); }
        public int Resets { get { return resets; } }
        public override string ToString() { return "Proto(" + base.ToString() + ", resets=" + resets + ")"; }
    }

    abstract class Shape
    {
        public abstract double Area();
        public virtual string Name() { return "shape"; }
        public string Summary() { return Name() + ":" + Area().ToString("0.##", CultureInfo.InvariantCulture); }
    }

    class Poly : Shape
    {
        protected readonly int sides, len;
        public Poly(int sides, int len) { this.sides = sides; this.len = len; }
        public override double Area() { return sides * len; }
        public override string Name() { return "poly" + sides; }
    }

    class Quad : Poly
    {
        public Quad(int len) : base(4, len) { }
        public override double Area() { return len * len; }
    }

    class Square : Quad
    {
        public Square(int len) : base(len) { }
        public sealed override string Name() { return "square"; }
    }

    static class Program
    {
        static void Main()
        {
            var trace = new List<string>();
            var items = new List<Entity>
            {
                new Vehicle(trace, 10),
                new Car(trace, 12),
                new SportsCar(trace, 8),
                new RaceCar(trace, 6, "red"),
                new Prototype(trace, 5),
            };
            Console.WriteLine("-- construction");
            foreach (string s in trace) Console.WriteLine("  " + s);

            Console.WriteLine("-- virtual dispatch");
            foreach (Entity e in items)
            {
                var sb = new StringBuilder();
                sb.Append(e.ToString()).Append(" cost3=").Append(e.Cost(3));
                sb.Append(" desc=").Append(e.Describe()).Append(" idesc=").Append(((IDescribe)e).Describe());
                Console.WriteLine("  " + sb);
            }

            Console.WriteLine("-- interfaces through the hierarchy");
            foreach (Entity e in items)
            {
                var v = (Vehicle)e;
                IScore isc = v;
                Console.WriteLine("  " + e.Kind + " class.Score=" + v.Score + " iface.Score=" + isc.Score
                    + " class.Bonus(3)=" + v.Bonus(3) + " iface.Bonus(3)=" + isc.Bonus(3));
            }

            Console.WriteLine("-- hiding vs override");
            var race = (RaceCar)items[3];
            Entity asEntity = race; Vehicle asVehicle = race; SportsCar asSports = race;
            Console.WriteLine("  labels " + asEntity.Label() + " " + asVehicle.Label() + " " + asSports.Label() + " " + race.Label());
            Console.WriteLine("  bonus via Vehicle=" + asVehicle.Bonus(2) + " via SportsCar=" + asSports.Bonus(2) + " via RaceCar=" + race.Bonus(2));

            Console.WriteLine("-- reset");
            var car = (Car)items[1];
            var proto = (Prototype)items[4];
            Console.WriteLine("  before car=" + car.Odometer + " proto=" + proto.Odometer);
            foreach (Entity e in items)
            {
                IReset r = e as IReset;
                if (r != null) r.Reset();
            }
            ((IReset)proto).Reset();
            proto.Reset();
            Console.WriteLine("  after car=" + car.Odometer + " proto=" + proto.Odometer + " " + proto + " scores " + car.Score + "," + proto.Score);

            Console.WriteLine("-- is / as / casts");
            foreach (Entity e in items)
            {
                string tag;
                if (e is Prototype) tag = "prototype";
                else if (e is RaceCar rc) tag = "racecar " + ((IDescribe)rc).Describe();
                else if (e is SportsCar) tag = "sportscar";
                else if (e is IReset) tag = "resettable";
                else tag = "plain";
                Car asCar = e as Car;
                Console.WriteLine("  " + e.Kind + ": " + tag + " asCar=" + (asCar != null) + " isScore=" + (e is IScore));
            }
            int failures = 0;
            foreach (Entity e in items)
            {
                try { var sc = (SportsCar)e; failures += sc.Cost(1) * 0; }
                catch (InvalidCastException) { failures++; }
            }
            Console.WriteLine("  failed casts to SportsCar=" + failures);

            Console.WriteLine("-- equality and hashing");
            var t2 = new List<string>();
            var carA = new Car(t2, 12);
            var vehA = new Vehicle(t2, 12);
            Console.WriteLine("  car==carA " + items[1].Equals(carA) + " car==vehA " + items[1].Equals(vehA) + " op== " + (items[1] == (Entity)carA));
            var set = new HashSet<Entity>(items);
            Console.WriteLine("  set has carA=" + set.Contains(carA) + " has vehA=" + set.Contains(vehA) + " size=" + set.Count);
            foreach (Entity e in items) Console.WriteLine("  hash " + e.Kind + "=" + e.GetHashCode().ToString("X8", CultureInfo.InvariantCulture));

            Console.WriteLine("-- abstract shapes");
            Shape[] shapes = { new Poly(5, 3), new Quad(4), new Square(6) };
            double total = 0;
            foreach (Shape s in shapes)
            {
                total += s.Area();
                switch (s)
                {
                    case Square sq: Console.WriteLine("  square branch " + sq.Summary()); break;
                    case Quad q: Console.WriteLine("  quad branch " + q.Summary()); break;
                    default: Console.WriteLine("  default branch " + s.Summary()); break;
                }
            }
            Console.WriteLine("  total area=" + total.ToString("0.##", CultureInfo.InvariantCulture));

            int checksum = 0;
            for (int i = 0; i < items.Count; i++) checksum = checksum * 7 + items[i].Cost(i + 1) + ((IScore)items[i]).Bonus(i);
            Console.WriteLine("checksum=" + checksum);
        }
    }
}
