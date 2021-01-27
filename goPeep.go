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
	*

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

func check(err error) {
	if err != nil {
		log.Fatal(fmt.Sprintf("[!]Error:\r\n%s", err.Error()))
	}
}

func main() {
	f, err := os.Open("cmd.exe")
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

}
