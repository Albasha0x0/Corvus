# Godot 4: writes the fixture files into a pack at the first user argument; a second argument is the 64-hex-digit
# key that encrypts the directory and the files.
extends SceneTree

func _init():
	var args := OS.get_cmdline_user_args()
	var out: String = args[0]
	var key: String = args[1] if args.size() > 1 else ""
	var src := OS.get_user_data_dir().path_join("corvus-godot-input")
	DirAccess.make_dir_recursive_absolute(src)
	var files := {"config/settings.ini": "[section]\nname=Ledger\ncount=3\n".repeat(40), "config/nested/notes.txt": "nested entry\n"}
	var p := PCKPacker.new()
	if key.is_empty():
		p.pck_start(out)
	else:
		p.pck_start(out, 32, key, true)
	for name in files:
		var path := src.path_join(name.replace("/", "_"))
		var f := FileAccess.open(path, FileAccess.WRITE)
		f.store_string(files[name])
		f.close()
		p.add_file("res://" + name, path, not key.is_empty())
	p.flush()
	quit()
