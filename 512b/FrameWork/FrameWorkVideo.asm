
 ; *********************************************************************** ;
 ; You are free to use this framework for non commercial uses so long as   ;
 ; you publish any refinements you make and give me a greet                ;
 ; *********************************************************************** ;
 ; Assemble with FASM (https://flatassembler.net/)                         ;
 ; *********************************************************************** ;

 format binary as 'exe'
 org    0x00010000
 use32

 ImageBase       equ $$
 NumHashes       equ Gdi32-$$
 StretchDIBits   equ ebx+0x20
 PeekMessageA    equ ebx+0x28
 ExitProcess     equ ebx+0x30
 GetWindowRect   equ ebx+0x38
 GetTickCount    equ ebx+0x3C
 LoadLibraryA    equ ebx+0x44
 CreateWindowExA equ ebx+0x48
 GetDC           equ ebx+0x64

                 ; **************************************************** ;
                 ; Mostly hashes (3 bytes still free for use @1A + @1B) ;
                 ; **************************************************** ;
 MzHdr:          db 0x4D,0x5A,0xEB,0x27,0x50,0x45,0x00,0x00
                 db 0x4C,0x01,0x00,0x00,0x62,0x65,0x68,0xC5
                 db 0x5A,0x08,0xE1,0xF2,0x3E,0xD1,0x00,0xD4
                 db 0x00,0x00,0x02,0x00,0x0B,0x01
 Gdi32           db 'gdi32',0
 User32          db 'user32',0

                 ; ******************************************************* ;
                 ; Get Kernel32 ImageBase. Uses PEB method                 ;
                 ; includes insane data execution (eax = ImageBase)        ;
                 ; ******************************************************* ;
 BootStrap:      mov      edx, 0x00000000    ; BA 00 00 00 00 ; .SizeUninitializedData & EntryPoint
                 mov      edi, [fs:edx+0x30] ; 64 8B 7A 30    ; .BaseOfCode
                 mov      edi, [edi+0x0C]    ; 8B 7F 0C       ; .BaseOfData
                 mov      eax, $$            ; B8 00 00 01 00 ; .BaseOfData & ImageBase
                 add      al, 0x00           ; 04 00          ; .SectionAlignment
                 add      byte [ds:eax], al  ; 00 00          ;
                 add      al, 0x00           ; 04 00          ; .FileAlignment
                 add      byte [ds:eax], al  ; 00 00          ;
                 push     SizeStackClear     ; 6A 20          ; .MajorOsVersion
                 mov      edi, [edi+0x1C]    ; 8B 7F 1C       ; .MinorOsVersion & .MajorImageVersion
 base:           mov      esi, [edi+0x20]    ; 8B 77 20       ; .MajorImageVersion & MinorImageVersion
                 add      al, 0x00           ; 04 00          ; .MajorSubsystemVersion
                 mov      ebp, [edi+0x08]    ; 8B 6F 08       ; .MinorSubsystemVersion & .Win32Version
                 cmp      [esi+0x18], al     ; 38 46 18       ; .Win32VersionValue
                 push     esp                ; 54             ; .SizeOfImage
                 mov      edi, [edi]         ; 8B 3F          ;
                 pop      ebx                ; 5B             ;
                 jnz      base               ; 75 EF          ; .SizeOfHeaders
                 jmp      DataDirectory      ; EB 20          ;

                 ; ******************************************************* ;
                 ; Run Lengh Encode Stack Args                             ;
                 ; No need to push API args, just decompress to the stack  ;
                 ; Includes BITMAPINFO but requires stack pointer fixup    ;
                 ; ******************************************************* ;
 PackedStack:    db       0x60, 0x28  ; 60 28       ; .CheckSum            ; BitMapInfo.biSize (0x00000028)
                 db       0x6E, 0x20  ; 6E 20       ;                      ; BitMapInfo.biBitsPerPel (0x0020)
                 dw       0x0003      ; 03 00       ; .Subsystem           ;
                 db       0x4C, 0xC0  ; 4C C0       ; .DllCharacteristics  ; StretchDIBits.DestHeight (0x000000C0)
                 db       0x05, 0xC0  ; 05 C0       ; .SizeOfStackReserve  ; CreateWindexExA.szClass (Thanks Las)
                 db       0x49, 0x01  ; 49 01       ;                      ; StretchDIBits.DestWidth (0x00000100)
                 db       0x0F, 0x91  ; 0F 91       ; .SizeOfStackCommit   ; CreateWindexExA.dwStyle (0x91000000)
                 db       0x65, 0x01  ; 65 01       ;                      ; BitMapInfo.biWidth (0x00000100)
                 db       0x68, 0xC0  ; 68 C0       ; .SizeOfHeapReserve   ; BitMapInfo.biHeight (0x000000C0)
                 db       0x6C, 0x01  ; 6C 01       ;                      ; BitMapInfo.biPlanes (0x0001)
                 db       0x5E, 0xCC  ; 5E CC       ; .SizeOfHeapCommit    ; StretchDIBits.Rop (0x00CC0020)
                 db       0x04, 0x19  ; 04 19       ;                      ; CreateWindexExA.szClass (thanks Las)
                 db       0x52, 0x10  ; 52 10       ; .LoaderFlags         ; StretchDIBits.PixelBufer (0x00020000)
                 db       0x5C, 0x20  ; 5C 20       ;                      ; StretchDIBits.Rop (0x00CC0020)
                 dd       0x00000000  ; 00 00 00 00 ; .NumberOfRvaAndSizes ;
                 PtrStack       equ (edi+PackedStack-0x02-$$)
                 SizeStackClear  = 0x20
                 NumStackValues  = ($-PackedStack)/2

                 ; ******************************************************* ;
                 ; Unpack API Arguments                                    ;
                 ; Uses a sort of Run-Length decoder                       ;
                 ; Any suggestions for improvement?                        ;
                 ; ******************************************************* ;
 DataDirectory:  xchg     eax, edi                 ; 97
                 pop      ecx                      ; 59
                 push     edx                      ; 52
                 loop     $-1                      ; E2 FD
                 mov      cl, NumStackValues       ; B1 10
 UnPack:         mov      eax, [PtrStack+ecx*0x02] ; 8B 44 4F 5A
                 mov      dl, al                   ; 88 C2
                 mov      [esp+edx], ah            ; 88 24 14
                 loop     UnPack                   ; E2 F5

                 ; ******************************************************* ;
                 ; Import By Hash                                          ;
                 ; This allows for 16-bit hashes that can be overlapped    ;
                 ;     hash = hash*0x2F - 0x37 - *str++                    ;
                 ; ******************************************************* ;
                 lea      esi, [edi+User32-$$]     ; 8D 77 24
 GetHashes:      push     NumHashes                ; 6A 1E
                 pop      ecx                      ; 59
                 push     esi                      ; 56
                 mov      esi, edi                 ; 89 FE
 FindFunction:   mov      eax, [esi]               ; 8B 06
                 inc      esi                      ; 46
                 pusha                             ; 60
                 mov      eax, [ebp+0x3C]          ; 8B 45 3C
                 mov      edi, [ebp+eax+0x78]      ; 8B 7C 05 78
                 add      edi, ebp                 ; 01 EF
                 mov      ecx, [edi+0x18]          ; 8B 4F 18
 ReDo:           jecxz    Done                     ; E3 38
                 dec      ecx                      ; 49
                 mov      esi, [edi+0x20]          ; 8B 77 20
                 add      esi, ebp                 ; 01 EE
                 mov      esi, [esi+ecx*0x04]      ; 8B 34 8E
                 add      esi, ebp                 ; 01 EE
                 xor      edx, edx                 ; 31 D2
 Hash:           lodsb                             ; AC
                 imul     edx, 0x2F                ; 6B D2 2F
                 sub      edx, 0x37                ; 83 EA 37
                 sub      edx, eax                 ; 29 C2
                 test     al, al                   ; 84 C0
                 jnz      Hash                     ; 75 F3
                 cmp      dx, word [esp+0x1C]      ; 66 3B 54 24 1C
                 jnz      ReDo                     ; 75 DD
                 mov      edx, [edi+0x24]          ; 8B 57 24
                 add      edx, ebp                 ; 01 EA
                 movzx    ecx, word [edx+ecx*0x02] ; 0F B7 0C 4A
                 mov      edx, [edi+0x1C]          ; 8B 57 1C
                 add      edx, ebp                 ; 01 EA
                 add      ebp, [edx+ecx*0x04]      ; 03 2C 8A
                 mov      ecx, [esp+0x18]          ; 8B 4C 24 18
                 mov      [ebx+ecx*0x04], ebp      ; 89 2C 8B
 Done:           popa                              ; 61
                 loop     FindFunction             ; E2 B2
                 call     dword [LoadLibraryA]     ; FF 53 44
                 xchg     eax, ebp                 ; 95
                 sub      eax, ebp                 ; 29 E8
                 jnz      GetHashes                ; 75 A4

                 ; ******************************************************* ;
                 ; Boiler Plate. Uses Las's WinClass=0xC018 trick          ;
                 ; EBX = ApiContext                                        ;
                 ; EDI = ImageBase                                         ;
                 ; ******************************************************* ;
 mainCRTStartup: call     dword [CreateWindowExA] ; FF 53 48
                 mov      edx, esp                ; 89 E2
                 push     eax                     ; 50
                 push     edx                     ; 52
                 push     eax                     ; 50
                 call     dword [GetWindowRect]   ; FF 53 38
                 call     dword [GetDC]           ; FF 53 64
                 push     eax                     ; 50
                 mov      ebp, esp                ; 89 E5

                 ; ******************************************************* ;
                 ; Main Loop                                               ;
                 ; EBX = ApiContext                                        ;
                 ; EDI = ImageBase                                         ;
                 ; ESI = TickCount                                         ;
                 ; ******************************************************* ;
                 ResX     equ ebp+0x1C         ; 256
                 ResY     equ ebp+0x20         ; 192
                 Size     equ ebp+0x1F         ; 256*192
                 Pixel    equ ebp+0x24         ; 0x00080000

 Main:           call     dword [GetTickCount] ; FF 53 3C
                 xchg     eax, esi             ; 96
                 mov      edi, [Pixel]         ; 8B 7D 24
                 mov      ecx, [Size]          ; 8B 4D 1F
 Draw:           mov      eax, ecx             ; 89 C8
                 dec      eax                  ; 48
                 stosd                         ; AB
                 loop     Draw                 ; E2 FA

                 ; ************************************************* ;
                 ; Blit and Exit                                     ;
                 ; Escape on WM_KEYDOWN (0x0101)                     ;
                 ; ************************************************* ;
                 push     0x01                  ; 6A 01
                 push     ecx                   ; 51
                 push     ecx                   ; 51
                 push     ecx                   ; 51
                 push     edi                   ; 57       ; (Tail end of Pixel Buffer)
                 call     dword [PeekMessageA]  ; FF 53 28 ;
                 call     dword [StretchDIBits] ; FF 53 20 ;
                 mov      [ebp+0x28], esp       ; 89 65 28 ; Add BITMAPINFO*
                 mov      esp, ebp              ; 89 EC    ; Fixup Stack Pointer
                 dec      byte [edi+0x05]       ; FE 4F 05 ; Exit if 0 == WM_KEYDOWN-1
                 jnz      Main                  ; 75 DA
                 call     dword [ExitProcess]   ; FF 53 30


 ; *********************************************************************** ;
 ; v1.0   2019/02/16   303b   Initial implementation
 ; v1.1   2019/03/02   295b   Overlapping 16-bit hashes + Removed ShowCursor
