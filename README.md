If you are not familiar with Windows PE, you can download the PE specification <a href="https://msdn.microsoft.com/en-us/library/windows/desktop/ms680547(v=vs.85).aspx">here</a>.

This tool is like the way a virus infects a PE file. It expands the last section of the PE, then writes a snippet of code which loads an external DLL, then jumps back to the original entry point of the program.

What if the PE is encrypted and will check its integrity when it starts? Generally an encrypted PE file will only has a minimal set of API like GetModuleHandle or LoadLibrary.

This tool implement GetProcAddress manually as part of the injection code, so it won’t need this API be existent in the IAT. If either GetModuleHandle or LoadLibrary exists, it injects some code to load a dynamic library, which is named monitor.dll. The self-check problem is left to the dynamic library. Doing the hacking inside a dynamic library is easier than do it in the PE file.

I provided the monitor library project which hooks the NtCreateFile API and intercepts the path. If the program tries to open its process file, it is very likely that it will checks the file integrity. In this case the path will be replaced with the backup file path.
