"""Hosts the Ghidra worker in PyGhidra's JVM so Python GhidraScripts run; argv[1]: JSON with ghidra, java_home, vmargs, boot_jar."""
# The protocol uses this process's stdin and stdout: nothing is printed here.
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
    # Starts the JVM, Ghidra's class loader and PyGhidra's script runner; the worker initializes the application.
    launcher.start()

    import jpype
    boot = jpype.JClass("corvus.ghidra.Boot", loader=jpype.java.lang.ClassLoader.getSystemClassLoader())
    boot().launch(launcher._layout, jpype.JArray(jpype.JString)([]))


if __name__ == "__main__":
    main()
