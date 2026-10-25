# Godot 3: writes the fixture files into a format 1 pack at the last command-line argument.
extends SceneTree

func _init():
	var out: String = OS.get_cmdline_args()[OS.get_cmdline_args().size() - 1]
	var src := OS.get_user_data_dir().plus_file("corvus-godot-input")
	Directory.new().make_dir_recursive(src)
	var files := {"config/settings.ini": "", "config/nested/notes.txt": "nested entry\n"}
	for i in 40:
		files["config/settings.ini"] += "[section]\nname=Ledger\ncount=3\n"
	var p := PCKPacker.new()
	p.pck_start(out)
	for name in files:
		var path: String = src.plus_file(name.replace("/", "_"))
		var f := File.new()
		f.open(path, File.WRITE)
		f.store_string(files[name])
		f.close()
		p.add_file("res://" + name, path)
	p.flush()
	quit()
