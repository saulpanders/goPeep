/*
	@saulpanders
	goPeep.go: portable executable parser

	inspired by bhg,


	PE FILE FORMAT
	-------------------------
	|	Signature			|
	|	dosHeader			|
	|	PE Header ptr 0x3c	|
	-------------------------
	-------------------------
	|	DOS stub			|
	-------------------------
	-------------------------
	|	COFF file header 	|
	-------------------------
	-------------------------
	|	Standard fields		|	-	/	Optional Header 32-bit
	|	Windows Spec fields	|	|---
	|	Data Directories	|	-	\	Optional Header 64 bit
	-------------------------
	-------------------------
	|	Section table		|
	-------------------------

	notes:

	* 0x4D 0x5A (MZ) is signature
	* pointer at 0x3C points to string "0x50 0x45 0x00 0x00" (PE)
	* FileHeader is COFF Header has following structure:
		type FileHeader struct {
			Machine					uint16  ->> PE system architecture
			NumberOfSections		uint16 	->> # of sections defined in Section Table (to backdoor a PE w/ extra section, you gotta modify this val)
			TimeDateStamp			uint32
			PointerToSymbolTable	uint32
			NumberOfSymbols			uint32
			SizeOfOptionalHeader	uint16
			Characteristics			uint16
		}
	* optional header := provides important data to loader

*/

package main

import (
	"debug/pe"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"os"
)

func getWinNTDataDirectories() []string {
	return []string{
		"IMAGE_DIRECTORY_ENTRY_EXPORT",
		"IMAGE_DIRECTORY_ENTRY_IMPORT",
		"IMAGE_DIRECTORY_ENTRY_RESOURCE",
		"IMAGE_DIRECTORY_ENTRY_EXCEPTION",
		"IMAGE_DIRECTORY_ENTRY_SECURITY",
		"IMAGE_DIRECTORY_ENTRY_BASERELOC",
		"IMAGE_DIRECTORY_ENTRY_DEBUG",
		"IMAGE_DIRECTORY_ENTRY_COPYRIGHT",
		"IMAGE_DIRECTORY_ENTRY_GLOBALPTR",
		"IMAGE_DIRECTORY_ENTRY_TLS",
		"IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG",
		"IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT",
		"IMAGE_DIRECTORY_ENTRY_IAT",
		"IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT",
		"IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR",
		"IMAGE_NUMBEROF_DIRECTORY_ENTRIES",
	}
}

func check(err error) {
	if err != nil {
		log.Fatal(fmt.Sprintf("[!]Error:\r\n%s", err.Error()))
	}
}

func main() {
	//command line args
	if len(os.Args) != 2 {
		fmt.Println("Usage:	", os.Args[0], "<pe.exe>")
		os.Exit(1)
	}
	target := os.Args[1]
	f, err := os.Open(target)
	check(err)
	pefile, err := pe.NewFile(f)
	check(err)
	defer f.Close()
	defer pefile.Close()

	dosHeader := make([]byte, 96)
	sizeOffset := make([]byte, 4)

	//convert decimal to ASCII -> search for MZ
	_, err = f.Read(dosHeader)
	check(err)
	fmt.Println("[-----DOS Header / Stub-----]")
	fmt.Printf("[+] Magic Value: %s%s\n", string(dosHeader[0]), string(dosHeader[1]))

	//validate PE (i.e. check for "PE null null" at 0x3c)
	pe_sig_offset := int64(binary.LittleEndian.Uint32(dosHeader[0x3c:]))
	f.ReadAt(sizeOffset[:], pe_sig_offset)
	fmt.Println("[-----Signature Header-----]")
	fmt.Printf("[+] LFANEW Value: %s\n", string(sizeOffset))

	//create a reader to read COFF header
	sr := io.NewSectionReader(f, 0, 1<<63-1)
	_, err = sr.Seek(pe_sig_offset+4, os.SEEK_SET)
	check(err)
	binary.Read(sr, binary.LittleEndian, &pefile.FileHeader)
	//Print FileHeader(COFF)
	fmt.Println("[-----COFF File Header-----]")
	fmt.Printf("[+] Machine Architecture: %#x\n", pefile.FileHeader.Machine)
	fmt.Printf("[+] Number of Sections: %#x\n", pefile.FileHeader.NumberOfSections)
	fmt.Printf("[+] Size of Optional Header: %#x\n", pefile.FileHeader.SizeOfOptionalHeader)
	fmt.Printf("[+] Date-Time Stamp: %#x\n", pefile.FileHeader.TimeDateStamp)
	//Print Section Names
	fmt.Println("[-----Section Offsets-----]")
	fmt.Printf("[+] Number of Sections Field Offset: %#x\n", pe_sig_offset+6)
	//end of signature header (0x7c + coff[20 bytes] + Oh32(224 bytes))
	fmt.Printf("[+] Section Table Offset: %#x\n", pe_sig_offset+0xF8)

	//Parse Optional Header
	//get size of optional header
	var sizeofOptionalHeader32 = uint16(binary.Size(pe.OptionalHeader32{}))
	var sizeofOptionalHeader64 = uint16(binary.Size(pe.OptionalHeader64{}))
	var oh32 pe.OptionalHeader32
	var oh64 pe.OptionalHeader64

	//Read + parse OptionalHeader, DataDirectories
	switch pefile.FileHeader.SizeOfOptionalHeader {
	case sizeofOptionalHeader32:
		binary.Read(sr, binary.LittleEndian, &oh32)
		thirtytwo_optional(&oh32, pefile)
	case sizeofOptionalHeader64:
		binary.Read(sr, binary.LittleEndian, &oh64)
		sixtyfour_optional(&oh64, pefile)
	}

	fmt.Println("[-----Section Table-----]")
	for _, section := range pefile.Sections {
		fmt.Println("[+] --------------------")
		fmt.Printf("[+] Section Name: %s\n", section.Name)
		fmt.Printf("[+] Section Characteristics: %#x\n", section.Characteristics)
		fmt.Printf("[+] Section Virtual Size: %#x\n", section.VirtualSize)
		fmt.Printf("[+] Section Virtual Offset: %#x\n", section.VirtualAddress)
		fmt.Printf("[+] Section Raw Size: %#x\n", section.Size)
		fmt.Printf("[+] Section Raw Offset to Data: %#x\n", section.Offset)
		fmt.Printf("[+] Section Append Offset (Next Section): %#x\n", section.Offset+section.Size)

	}

}
func thirtytwo_optional(oh32 *pe.OptionalHeader32, pefile *pe.File) {
	fmt.Println("[-----Optional Header-----]")
	fmt.Printf("[+] Entry Point: %#x\n", (*oh32).AddressOfEntryPoint)
	fmt.Printf("[+] ImageBase: %#x\n", (*oh32).ImageBase)
	fmt.Printf("[+] Size of Image: %#x\n", (*oh32).SizeOfImage)
	fmt.Printf("[+] Sections Alignment: %#x\n", (*oh32).SectionAlignment)
	fmt.Printf("[+] File Alignment: %#x\n", (*oh32).FileAlignment)
	fmt.Printf("[+] Characteristics: %#x\n", (*pefile).FileHeader.Characteristics)
	fmt.Printf("[+] Size of Headers: %#x\n", (*oh32).SizeOfHeaders)
	fmt.Printf("[+] Checksum: %#x\n", (*oh32).CheckSum)
	fmt.Printf("[+] Machine: %#x\n", (*pefile).FileHeader.Machine)
	fmt.Printf("[+] Subsystem: %#x\n", (*oh32).Subsystem)
	fmt.Printf("[+] DLL Characteristics: %#x\n", (*oh32).DllCharacteristics)

	//print data directory
	fmt.Println("[-----Data Directory-----]")
	winnt_datadirs := getWinNTDataDirectories()
	for idx, directory := range (*oh32).DataDirectory {
		fmt.Printf("[!] Data Directory: %s\n", winnt_datadirs[idx])
		fmt.Printf("[+] Image Virtual Address: %#x\n", directory.VirtualAddress)
		fmt.Printf("[+] Image Size: %#x\n", directory.Size)
	}

}
func sixtyfour_optional(oh64 *pe.OptionalHeader64, pefile *pe.File) {
	fmt.Println("[-----Optional Header-----]")
	fmt.Printf("[+] Entry Point: %#x\n", (*oh64).AddressOfEntryPoint)
	fmt.Printf("[+] ImageBase: %#x\n", (*oh64).ImageBase)
	fmt.Printf("[+] Size of Image: %#x\n", (*oh64).SizeOfImage)
	fmt.Printf("[+] Sections Alignment: %#x\n", (*oh64).SectionAlignment)
	fmt.Printf("[+] File Alignment: %#x\n", (*oh64).FileAlignment)
	fmt.Printf("[+] Characteristics: %#x\n", (*pefile).FileHeader.Characteristics)
	fmt.Printf("[+] Size of Headers: %#x\n", (*oh64).SizeOfHeaders)
	fmt.Printf("[+] Checksum: %#x\n", (*oh64).CheckSum)
	fmt.Printf("[+] Machine: %#x\n", (*pefile).FileHeader.Machine)
	fmt.Printf("[+] Subsystem: %#x\n", (*oh64).Subsystem)
	fmt.Printf("[+] DLL Characteristics: %#x\n", (*oh64).DllCharacteristics)

	//print data directory 64
	fmt.Println("[-----Data Directory-----]")
	winnt_datadirs := getWinNTDataDirectories()
	for idx, directory := range (*oh64).DataDirectory {
		fmt.Printf("[!] Data Directory: %s\n", winnt_datadirs[idx])
		fmt.Printf("[+] Image Virtual Address: %#x\n", directory.VirtualAddress)
		fmt.Printf("[+] Image Size: %#x\n", directory.Size)
	}
}
