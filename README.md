### Basic x64dll=>WOW64process injector.

A simple proof of concept for injecting a 64-bit library into the wow64 process, based on usage undocumented ntdll!LdrLoadDll.
Includes an example dll with dependencies only on ntdll

### Build

Use Visual Studio 2019 or newer, there are no any external libs.
Use only Release configuration to build the injector, Debug build does not support C++ shellcodes

### Usage

**Help:** LdrLoadDll64to32.exe [target process id] [absolute path to dll library for inject]

**Example:** LdrLoadDll64to32.exe 1234 C:\Windows\System32\kernel32.dll
