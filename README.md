# SetEnv

SetEnv enables a process to modify the environment variables of its parent process.

> [!WARNING] 
> Setenv injects dll to its parent process. Is is expected to get flagged as threat by your antivirus software.

## Building

Compile `lib/setenv.c` and link with `User32.lib`.

<details open>
<summary>Visual Studio</summary>

Open `setenv.sln` and hit build.

</details>

<details open>
<summary>Clang</summary>

You can build without C Runtime Library.
```bat
mkdir build 
cd build
clang ..\lib\setenv.c -o setenv.dll -Oz -g -shared -lUser32 -lKernel32 -llibvcruntime -llibcmt -nostdlib -flto -fuse-ld=lld -Xlinker /ENTRY:seDllMainCRTStartup
```
Or with it.
```bat
mkdir build 
cd build
clang ..\lib\setenv.c -o setenv.dll -Oz -g -shared -lUser32
```

</details>

<details>
<summary>MSVC</summary>

You can build without C Runtime Library.
```bat
mkdir build 
cd build
cl /LD /W3 ..\lib\setenv.c /std:c11 user32.lib kernel32.lib libvcruntime.lib libcmt.lib /Os /Zi /link /NODEFAULTLIB /ENTRY:seDllMainCRTStartup
```

Or with it.

```bat
mkdir build 
cd build
cl /LD /W3 ..\lib\setenv.c /std:c11 user32.lib /Os /Zi
```

</details>

### Rust

Add the following to your Cargo.toml file:

```toml
[dependencies]
setenv = { git = "https://github.com/fraclysis/setenv.git", branch = "main", features = [
    "build-dll", # Requires clang in path 
] }
```

## Usage

Please see `setenv.h` for details.

```C
#include "setenv.h"
#include <stdio.h>
#include <string.h>

int main(void) {
    WCHAR name[] = L"SetEnv";
    WCHAR value[] = L"Hello from Setenv!";

    SeResult result = seSetParentProcessEnvironmentVariable(
        name, // Pointer to of name of the environment variable
        wcslen(name),
        value, // Pointer to start of value string
        wcslen(value) // If value is null must be 0
    );

    if (seIsError(result)) {
        fprintf(stderr, "%s (Os error: %#lx)\n", result.se_error, result.os_error);
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
```

## Debugging

You can debug with Visual Studio's built-in debugger with 
[Microsoft Child Process Debugging Power Tool](https://marketplace.visualstudio.com/items?itemName=vsdbgplat.MicrosoftChildProcessDebuggingPowerTool) extension. Be careful to debug the parent process rather than the process that is using SetEnv. Also do not forget to enable extension from `Debug->Other Debug Targets->Child Process Debugging Settings`