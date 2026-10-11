package corvus.ghidra;

import ghidra.GhidraApplicationLayout;
import ghidra.GhidraClassLoader;
import ghidra.GhidraLaunchable;

/**
 * Started by ghidra.Ghidra from the JVM class path. Adds the worker jar to Ghidra's class loader (a jar on the class
 * path cannot see Ghidra's module jars or extensions) and starts the worker.
 */
public class Boot implements GhidraLaunchable {
    @Override
    public void launch(GhidraApplicationLayout layout, String[] args) throws Exception {
        GhidraClassLoader loader = (GhidraClassLoader) ClassLoader.getSystemClassLoader();
        loader.addPath(System.getProperty("corvus.worker.jar"));
        GhidraLaunchable worker = (GhidraLaunchable) Class.forName("corvus.ghidra.Worker", true, loader).getDeclaredConstructor().newInstance();
        worker.launch(layout, args);
    }
}
