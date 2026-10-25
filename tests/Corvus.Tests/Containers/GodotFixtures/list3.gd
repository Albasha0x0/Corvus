# Godot 3: mounts the pack at the last command-line argument and prints FILE, path and MD5 for each file, or REFUSED.
extends SceneTree

func _walk(dir: String) -> void:
	var d := Directory.new()
	d.open(dir)
	d.list_dir_begin(true, false)
	var f := d.get_next()
	while f != "":
		var p := dir.plus_file(f) if dir != "res://" else "res://" + f
		if d.current_is_dir():
			_walk(p)
		else:
			var h := File.new()
			print("FILE\t", p.substr(6), "\t", h.get_md5(p))
		f = d.get_next()

func _init():
	var pck: String = OS.get_cmdline_args()[OS.get_cmdline_args().size() - 1]
	if not ProjectSettings.load_resource_pack(pck, false):
		print("REFUSED")
	else:
		_walk("res://")
	quit()
