# goPeep
Simple Portable Executable (PE) analyzer

## Background Info
Inspired by code in Black Hat Go
- makes use of "debug/pe" for some heavy lifting
- works on x86 and x64
- Gonna try and add ELF support when I have time

use the [Microsoft Docs](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format) to make sense of the values

## Usage
### Build
```
> go build goPeep.go
```
### Arguments
Uses os.Args for option parsing, so theres not really an argument name.. 
- PE file to analyzer
### Example
```
> goPeep.exe Firefox.exe
```
