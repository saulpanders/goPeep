# goPeep
Simple Portable Executable (PE) analyzer

## Background Info
Inspired by code in Black Hat Go
- makes use of "debug/pe" for some heavy lifting
- works on x86 and x64
- no DLL support (yet)

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
