```C

                   ___  ___  ________   ___  ___  ________  ________  ___  __       
                  |\  \|\  \|\   ___  \|\  \|\  \|\   __  \|\   __  \|\  \|\  \     
                  \ \  \\\  \ \  \\ \  \ \  \\\  \ \  \|\  \ \  \|\  \ \  \/  /|_   
                   \ \  \\\  \ \  \\ \  \ \   __  \ \  \\\  \ \  \\\  \ \   ___  \  
                    \ \  \\\  \ \  \\ \  \ \  \ \  \ \  \\\  \ \  \\\  \ \  \\ \  \ 
                     \ \_______\ \__\\ \__\ \__\ \__\ \_______\ \_______\ \__\\ \__\
                      \|_______|\|__| \|__|\|__|\|__|\|_______|\|_______|\|__| \|__|

                                -------a base lib to unhook NTDLL------   

```

Unhook is a base lib aiming to show different techniques to unhook NTDLL & use a proper version of it.

> [!Note]
> Consider using NTFUNCTIONS (Syscalls) for stealth. I only use base WinApi function for demo.

## Techniques : 

- **Read from disk** : Read NTDLL from Disk.
- **Map from disk** : Map NTDLL from Disk.
- **Suspended process** : Retrieve NTDLL from a newly created process in SUSPENDED_MODE.

