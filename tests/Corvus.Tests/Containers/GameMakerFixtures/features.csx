// Adds two scripts, an object with a Create event, a texture page and a sound to a blank data file. FIXTURE_BYTECODE
// sets the bytecode version written; 17 also declares GameMaker Studio 2.
using System.IO;
using UndertaleModLib.Models;
using UndertaleModLib.Util;

string dir = Environment.GetEnvironmentVariable("FIXTURE_INPUT");
byte bytecode = byte.Parse(Environment.GetEnvironmentVariable("FIXTURE_BYTECODE"));
Data.GeneralInfo.BytecodeVersion = bytecode;
if (bytecode >= 17) Data.GeneralInfo.Major = 2;
Data.GeneralInfo.Name = Data.Strings.MakeString("Ledger");
Data.GeneralInfo.DisplayName = Data.Strings.MakeString("Ledger Fixture");
var obj = new UndertaleGameObject();
obj.Name = Data.Strings.MakeString("obj_counter");
Data.GameObjects.Add(obj);
UndertaleModLib.Compiler.CodeImportGroup group = new(Data) { AutoCreateAssets = true };
group.QueueReplace("gml_Script_ledger_total", "var total = 0;\nfor (var i = 0; i < argument_count; i++)\n    total += argument[i];\nreturn total;");
group.QueueReplace("gml_Script_ledger_label", "return \"ledger: \" + string(argument0);");
group.QueueReplace("gml_Object_obj_counter_Create_0", "count = 3;\nlabel = ledger_label(count);");
group.Import();
var audio = new UndertaleEmbeddedAudio();
audio.Data = File.ReadAllBytes(Path.Combine(dir, "tone.wav"));
Data.EmbeddedAudio.Add(audio);
var tex = new UndertaleEmbeddedTexture();
tex.TextureData.Image = GMImage.FromPng(File.ReadAllBytes(Path.Combine(dir, "page.png")));
Data.EmbeddedTextures.Add(tex);
