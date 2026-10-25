# Godot 4: mounts the pack at the first user argument and prints FILE, path and MD5 for each file, or REFUSED.
extends SceneTree

func _walk(dir: String) -> void:
	var d := DirAccess.open(dir)
	d.include_hidden = true
	for f in d.get_files():
		var p := dir.path_join(f)
		print("FILE\t", p.substr(6), "\t", FileAccess.get_md5(p))
	for sub in d.get_directories():
		_walk(dir.path_join(sub))

func _init():
	var pck: String = OS.get_cmdline_user_args()[0]
	if not ProjectSettings.load_resource_pack(pck, false):
		print("REFUSED")
	else:
		_walk("res://")
	quit()
