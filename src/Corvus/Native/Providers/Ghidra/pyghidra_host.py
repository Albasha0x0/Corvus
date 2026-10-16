"""The Ghidra worker hosted by PyGhidra, so Python GhidraScripts run inside it.

PyGhidra runs Python only in a JVM it starts itself (JPype in this process): this host starts that JVM with Ghidra's
and the server's VM arguments, lets PyGhidra register its script runner, then starts the same boot class the plain
JVM starts. The worker's protocol stays on this process's stdin and stdout; nothing is printed here.

argv[1]: a JSON file: ghidra (install directory), java_home, vmargs (the server's, after Ghidra's), boot_jar.
"""
import json
import sys


def main():
    with open(sys.argv[1], encoding="utf-8") as f:
        config = json.load(f)
    from pyghidra.launcher import DeferredPyGhidraLauncher

    launcher = DeferredPyGhidraLauncher(install_dir=config["ghidra"])
    launcher.java_home = config["java_home"]
    launcher.add_vmargs(*config["vmargs"])
    launcher.add_classpaths(config["boot_jar"])
    # the JVM, Ghidra's class loader and PyGhidra's script runner; the worker initializes the application itself
    launcher.start()

    import jpype
    boot = jpype.JClass("corvus.ghidra.Boot", loader=jpype.java.lang.ClassLoader.getSystemClassLoader())
    boot().launch(launcher._layout, jpype.JArray(jpype.JString)([]))


if __name__ == "__main__":
    main()
