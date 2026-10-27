using System.Text.RegularExpressions;
using System.Xml.Linq;
using Corvus.Core;
using Corvus.Services.Analysis;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>XBF pages from the Windows App SDK's XAML compiler read back with view=xbf (opt-in: CORVUS_WINDOWS_APP_SDK names the package version).</summary>
[Trait("Speed", "Slow")]
public sealed partial class XbfCompilerTests(ITestOutputHelper output) : IDisposable
{
    /// <summary>The compiler's variable and the build properties that select it.</summary>
    private static readonly (string Variable, string[] Properties) Compiler = ("CORVUS_WINDOWS_APP_SDK",
        ["<UseWinUI>true</UseWinUI>", "<WindowsPackageType>None</WindowsPackageType>", "<UseXamlCompilerExecutable>true</UseXamlCompilerExecutable>",
         "<EnableMsixTooling>false</EnableMsixTooling>", "<Platforms>x64</Platforms>", "<RuntimeIdentifier>win-x64</RuntimeIdentifier>"]);

    private const string App = """
        <Application x:Class="XbfApp.App" xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml">
          <Application.Resources>
            <ResourceDictionary>
              <SolidColorBrush x:Key="Accent" Color="#FF0078D4" />
            </ResourceDictionary>
          </Application.Resources>
        </Application>
        """;

    private const string MainWindow = """
        <Window x:Class="XbfApp.MainWindow" xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml">
          <StackPanel Orientation="Vertical" Spacing="8">
            <TextBlock x:Name="Heading" Text="Hello" FontSize="24" />
            <Button x:Name="Save" Content="Save" Click="Save_Click" Background="{StaticResource Accent}" />
            <ListView ItemsSource="{x:Bind Items}" SelectionChanged="Items_SelectionChanged" />
            <TextBox Text="{Binding Name, Mode=TwoWay}" Width="200" Margin="4,8,4,8" />
          </StackPanel>
        </Window>
        """;

    private const string Shapes = """
        <Page x:Class="XbfApp.Shapes" xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
              xmlns:local="using:XbfApp" xmlns:contract7="http://schemas.microsoft.com/winfx/2006/xaml/presentation?IsApiContractPresent(Windows.Foundation.UniversalApiContract,7)">
          <Page.Resources>
            <x:String x:Key="Greeting">Hello there</x:String>
            <x:Double x:Key="Gap">12</x:Double>
            <SolidColorBrush x:Key="Ink" Color="DarkSlateBlue" />
            <Style x:Key="Big" TargetType="TextBlock">
              <Setter Property="FontSize" Value="32" />
              <Setter Property="Foreground" Value="{StaticResource Ink}" />
              <Setter Property="Margin">
                <Setter.Value>
                  <Thickness>1,2,3,4</Thickness>
                </Setter.Value>
              </Setter>
            </Style>
            <Style TargetType="Button">
              <Setter Property="CornerRadius" Value="4" />
              <Setter Property="Template">
                <Setter.Value>
                  <ControlTemplate TargetType="Button">
                    <Border Background="{TemplateBinding Background}" BorderBrush="{ThemeResource SystemControlForegroundBaseHighBrush}">
                      <VisualStateManager.VisualStateGroups>
                        <VisualStateGroup x:Name="CommonStates">
                          <VisualState x:Name="Normal" />
                          <VisualState x:Name="PointerOver">
                            <VisualState.Setters>
                              <Setter Target="Presenter.Opacity" Value="0.5" />
                            </VisualState.Setters>
                          </VisualState>
                        </VisualStateGroup>
                      </VisualStateManager.VisualStateGroups>
                      <ContentPresenter x:Name="Presenter" Content="{TemplateBinding Content}" HorizontalAlignment="Center" />
                    </Border>
                  </ControlTemplate>
                </Setter.Value>
              </Setter>
            </Style>
            <DataTemplate x:Key="Row" x:DataType="local:Item">
              <TextBlock Text="{x:Bind Name}" />
            </DataTemplate>
          </Page.Resources>
          <Grid x:Uid="Root">
            <Grid.RowDefinitions>
              <RowDefinition Height="Auto" />
              <RowDefinition Height="2*" />
              <RowDefinition Height="40" />
            </Grid.RowDefinitions>
            <TextBlock Style="{StaticResource Big}" Text="{StaticResource Greeting}" Grid.Row="0" />
            <ListView Grid.Row="1" ItemTemplate="{StaticResource Row}" ItemClick="List_ItemClick" IsItemClickEnabled="True" />
            <local:Badge Grid.Row="2" Count="3" Tapped="Badge_Tapped" />
            <Border x:Name="Lazy" x:Load="False" Grid.Row="2" Width="{StaticResource Gap}" />
            <contract7:TextBlock Text="Only with contract 7" />
            <TextBlock>
              <Run Text="Bold " FontWeight="Bold" /><Run>plain</Run>
            </TextBlock>
          </Grid>
        </Page>
        """;

    private const string Code = """
        using Microsoft.UI.Xaml;
        using Microsoft.UI.Xaml.Controls;
        using Microsoft.UI.Xaml.Input;
        namespace XbfApp;
        public partial class App : Application
        {
            public App() => InitializeComponent();
            protected override void OnLaunched(LaunchActivatedEventArgs args) => new MainWindow().Activate();
        }
        public sealed partial class MainWindow : Window
        {
            public string[] Items { get; } = ["a", "b"];
            public MainWindow() => InitializeComponent();
            private void Save_Click(object sender, RoutedEventArgs e) { }
            private void Items_SelectionChanged(object sender, SelectionChangedEventArgs e) { }
        }
        public sealed class Item { public string Name { get; set; } = ""; }
        public sealed class Badge : Control { public int Count { get; set; } }
        public sealed partial class Shapes : Page
        {
            public Shapes() => InitializeComponent();
            private void List_ItemClick(object sender, ItemClickEventArgs e) { }
            private void Badge_Tapped(object sender, TappedRoutedEventArgs e) { }
        }
        """;

    private readonly TempDir _dir = new();
    private readonly AssemblyWorkspace _workspace = new(new ServerOptions());

    public void Dispose()
    {
        _workspace.Dispose();
        _dir.Dispose();
    }

    [Fact]
    public void Compiled_pages_read_back_with_every_element_and_their_handlers()
    {
        if (Environment.GetEnvironmentVariable(Compiler.Variable) is not { Length: > 0 } version || !OperatingSystem.IsWindows()) return;
        var project = _dir.File("XbfApp");
        Directory.CreateDirectory(project);
        // Empty build props stop MSBuild from picking up a Directory.Build.props above the temp folder.
        File.WriteAllText(Path.Combine(project, "Directory.Build.props"), "<Project />");
        File.WriteAllText(Path.Combine(project, "Directory.Packages.props"), "<Project />");
        File.WriteAllText(Path.Combine(project, "XbfApp.csproj"), $"""
            <Project Sdk="Microsoft.NET.Sdk">
              <PropertyGroup><OutputType>WinExe</OutputType><TargetFramework>net9.0-windows10.0.22621.0</TargetFramework>{string.Concat(Compiler.Properties)}</PropertyGroup>
              <ItemGroup><PackageReference Include="Microsoft.WindowsAppSDK" Version="{version}" /></ItemGroup>
            </Project>
            """);
        var pages = new Dictionary<string, string> { ["App"] = App, ["MainWindow"] = MainWindow, ["Shapes"] = Shapes };
        foreach (var (name, xaml) in pages) File.WriteAllText(Path.Combine(project, name + ".xaml"), xaml);
        File.WriteAllText(Path.Combine(project, "Code.cs"), Code);
        var (exitCode, log) = Tools.Dotnet(project, ["build", "-c", "Release", "-o", _dir.File("out")]);
        Assert.True(exitCode == 0, $"dotnet build failed:\n{log}");

        var failures = new List<string>();
        foreach (var (name, source) in pages)
        {
            var xbf = Path.Combine(_dir.File("out"), name + ".xbf");
            var facts = Assert.IsType<XbfFileView.Facts>(new InspectionService(_workspace).Summarize(null, xbf, default, new FileViewOptions("xbf")).Views["xbf"].Detail);
            output.WriteLine($"{name}: XBF {facts.Version}, {facts.Elements} elements, {facts.Handlers.Count} handlers{Environment.NewLine}{facts.Xaml}");
            if (!facts.Complete) failures.Add($"{name}: partial: {string.Join("; ", facts.Notes ?? [])}");
            var expected = Elements(XDocument.Parse(source));
            var actual = Elements(XDocument.Parse(facts.Xaml!));
            if (!expected.SequenceEqual(actual)) failures.Add($"{name}: elements {string.Join(" ", actual)}; source {string.Join(" ", expected)}");
            var events = XDocument.Parse(source).Descendants().SelectMany(e => e.Attributes())
                .Where(a => a.Name.LocalName.Length > 0 && Handler().IsMatch(a.Value)).Select(a => $"{a.Name.LocalName}={a.Value}").Order(StringComparer.Ordinal).ToList();
            var resolved = facts.Handlers.Select(h => $"{h.Event}={h.Symbol[(h.Symbol.IndexOf("::", StringComparison.Ordinal) + 2)..h.Symbol.IndexOf('(')]}").Order(StringComparer.Ordinal).ToList();
            if (!events.SequenceEqual(resolved)) failures.Add($"{name}: handlers {string.Join(", ", resolved)}; source {string.Join(", ", events)}");
        }
        Assert.True(failures.Count == 0, string.Join("\n", failures));
    }

    /// <summary>The elements in document order by local name, property elements left out: what the source declares.</summary>
    private static List<string> Elements(XDocument doc) =>
        [.. doc.Descendants().Where(e => !e.Name.LocalName.Contains('.') && e.Name.LocalName != "ResourceDictionary").Select(e => e.Name.LocalName)];

    // Handler methods as the test's code-behind names them.
    [GeneratedRegex(@"^\w+_(Click|SelectionChanged|ItemClick|Tapped)$")]
    private static partial Regex Handler();
}
