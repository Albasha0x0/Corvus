namespace Corvus.Core.Python;

/// <summary>The top-level module names of the Python standard library.</summary>
public static class PyStdlib
{
    // sys.stdlib_module_names of 3.12, the modules 3.12 and 3.13 removed, those 3.13 and 3.14 added, and the test
    // modules CPython builds.
    private static readonly HashSet<string> Names = new(StringComparer.Ordinal)
    {
        "__future__", "_abc", "_aix_support", "_android_support", "_apple_support", "_ast", "_asyncio", "_bisect",
        "_blake2", "_bootlocale", "_bz2", "_codecs", "_codecs_cn", "_codecs_hk", "_codecs_iso2022", "_codecs_jp",
        "_codecs_kr", "_codecs_tw", "_collections", "_collections_abc", "_colorize", "_compat_pickle", "_compression",
        "_contextvars", "_crypt", "_csv", "_ctypes", "_ctypes_test", "_curses", "_curses_panel", "_datetime", "_dbm",
        "_decimal", "_dummy_thread", "_elementtree", "_frozen_importlib", "_frozen_importlib_external", "_functools",
        "_gdbm", "_hashlib", "_heapq", "_imp", "_interpchannels", "_interpqueues", "_interpreters", "_io", "_ios_support",
        "_json", "_locale", "_lsprof", "_lzma", "_markupbase", "_md5", "_msi", "_multibytecodec", "_multiprocessing",
        "_opcode", "_opcode_metadata", "_operator", "_osx_support", "_overlapped", "_pickle", "_posixshmem",
        "_posixsubprocess", "_py_abc", "_pydatetime", "_pydecimal", "_pyio", "_pylong", "_pyrepl", "_queue", "_random",
        "_remote_debugging", "_scproxy", "_sha1", "_sha2", "_sha3", "_signal", "_sitebuiltins", "_socket", "_sqlite3",
        "_sre", "_ssl", "_stat", "_statistics", "_string", "_strptime", "_struct", "_suggestions", "_symtable",
        "_testbuffer", "_testcapi", "_testclinic", "_testimportmultiple", "_testinternalcapi", "_testlimitedcapi",
        "_testmultiphase", "_testsinglephase", "_thread", "_threading_local", "_tkinter", "_tokenize", "_tracemalloc",
        "_typing", "_uuid", "_warnings", "_weakref", "_weakrefset", "_winapi", "_wmi", "_xxinterpchannels",
        "_xxsubinterpreters", "_xxtestfuzz", "_zoneinfo", "_zstd", "abc", "aifc", "annotationlib", "antigravity",
        "argparse", "array", "ast", "asynchat", "asyncio", "asyncore", "atexit", "audioop", "base64", "bdb", "binascii",
        "binhex", "bisect", "builtins", "bz2", "cProfile", "calendar", "cgi", "cgitb", "chunk", "cmath", "cmd", "code",
        "codecs", "codeop", "collections", "colorsys", "compileall", "compression", "concurrent", "configparser",
        "contextlib", "contextvars", "copy", "copyreg", "crypt", "csv", "ctypes", "curses", "dataclasses", "datetime",
        "dbm", "decimal", "difflib", "dis", "distutils", "doctest", "dummy_threading", "email", "encodings", "ensurepip",
        "enum", "errno", "faulthandler", "fcntl", "filecmp", "fileinput", "fnmatch", "formatter", "fractions", "ftplib",
        "functools", "gc", "genericpath", "getopt", "getpass", "gettext", "glob", "graphlib", "grp", "gzip", "hashlib",
        "heapq", "hmac", "html", "http", "idlelib", "imaplib", "imghdr", "imp", "importlib", "inspect", "io", "ipaddress",
        "itertools", "json", "keyword", "lib2to3", "linecache", "locale", "logging", "lzma", "macpath", "mailbox",
        "mailcap", "marshal", "math", "mimetypes", "mmap", "modulefinder", "msilib", "msvcrt", "multiprocessing", "netrc",
        "nis", "nntplib", "nt", "ntpath", "nturl2path", "numbers", "opcode", "operator", "optparse", "os", "ossaudiodev",
        "parser", "pathlib", "pdb", "pickle", "pickletools", "pipes", "pkgutil", "platform", "plistlib", "poplib", "posix",
        "posixpath", "pprint", "profile", "pstats", "pty", "pwd", "py_compile", "pyclbr", "pydoc", "pydoc_data", "pyexpat",
        "queue", "quopri", "random", "re", "readline", "reprlib", "resource", "rlcompleter", "runpy", "sched", "secrets",
        "select", "selectors", "shelve", "shlex", "shutil", "signal", "site", "smtpd", "smtplib", "sndhdr", "socket",
        "socketserver", "spwd", "sqlite3", "sre_compile", "sre_constants", "sre_parse", "ssl", "stat", "statistics",
        "string", "stringprep", "struct", "subprocess", "sunau", "symbol", "symtable", "sys", "sysconfig", "syslog",
        "tabnanny", "tarfile", "telnetlib", "tempfile", "termios", "test", "textwrap", "this", "threading", "time",
        "timeit", "tkinter", "token", "tokenize", "tomllib", "trace", "traceback", "tracemalloc", "tty", "turtle",
        "turtledemo", "types", "typing", "unicodedata", "unittest", "urllib", "uu", "uuid", "venv", "warnings", "wave",
        "weakref", "webbrowser", "winreg", "winsound", "wsgiref", "xdrlib", "xml", "xmlrpc", "xxlimited", "xxlimited_35",
        "xxsubtype", "zipapp", "zipfile", "zipimport", "zlib", "zoneinfo"
    };

    /// <summary>Whether <paramref name="topLevel"/> (a module's first dotted part) names a standard library module.</summary>
    public static bool Contains(string topLevel) => Names.Contains(topLevel);
}
