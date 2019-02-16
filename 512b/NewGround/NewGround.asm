
 ; *********************************************************************** ;
 ; You are free to use the framework for non commercial uses so long as    ;
 ; you publish any refinements you make and give me a greet                ;
 ;    https://github.com/collinsmichael/DemoScene                          ;
 ;                                                                         ;
 ; Thanks to                                                               ;
 ;   Las for the WindowClass trick (unblocked my header packing)           ;
 ;   Rrrola for the camera trick                                           ;
 ;   Hellmood for the raymarching ideas                                    ;
 ;                                                                         ;
 ; Special thanks to TomCat for picking up the ball and running with it    ;
 ; Now the balls in your court                                             ;
 ; *********************************************************************** ;

 format binary as 'exe'
 org    0x00010000
 use32

 ImageBase equ $$
 rva       equ -$$

 macro tinycall proc,[arg] {
    common
    if ~ arg eq
        reverse
        pushd arg
        common
    end if
    call dword [proc]
 }

 MzHdr:          dec      ebp                       ; 4D                   ; .e_magic
                 pop      edx                       ; 5A                   ;
                 jmp      short BootStrap           ; EB 27                ; .e_cblp
 PeSig           dd       'PE'                      ; 50 45 00 00          ;  pesig
 PeHdr:          dw       0x014C                    ; 4C 01                ; .Machine
                 dw       0x0000                    ; 00 00                ; .NumberOfSections


                 ; ******************************************************* ;
                 ; Hashes (Mostly)                                         ;
                 ; ******************************************************* ;
                 sndPlaySoundA   equ     ebp + 0x64 ; Run Time             ;
                 PeekMessageA    equ     ebp + 0x68 ; Run Time             ;
                 StretchDIBits   equ     ebp + 0x6C ; Run Time             ;
                 ExitProcess     equ     ebp + 0x74 ; Run Time             ;
                 GetTickCount    equ     ebp + 0x7C ; Run Time             ;
                 LoadLibraryA    equ     edi + 0x20 ; Start Up             ;
                 ShowCursor      equ     edi + 0x24 ; Start Up             ;
                 GetDC           equ     edi + 0x28 ; Start Up             ;
                 CreateWindowExA equ     edi + 0x2C ; Start Up             ;
                 GetWindowRect   equ     edi + 0x30 ; Start Up             ;

 GETWINDOWRECT   dw       0x0A9A                    ; 9A 0A                ; .TimeDateStamp
 CREATEWINDOWEXA dw       0x2054                    ; 54 02                ;
 GETDC           dw       0xD9D1                    ; D1 D9                ; .PointerToSymbolTable
 SHOWCURSOR      dw       0x4F39                    ; 39 4F                ;
 LOADLIBRARYA    dw       0x5B68                    ; 68 5B                ; .NumberOfSymbols
 GETTICKCOUNT    dw       0x6CA0                    ; 40 6C                ;
                 dw       0x0000                    ; 00 00                ; .SizeOfOptionalHeader
 EXITPROCESS     dw       0x547B                    ; 7B 54                ; .Characteristics
 OpHdr:          dw       0x010B                    ; 0B 01                ; .Magic
 STRETCHDIBITS   dw       0xC7EE                    ; EE C7                ; .MinorLinkerVersion & .MajorLinkerVersion
 PEEKMESSAGEA    dw       0x97B1                    ; B1 97                ; .SizeOfCode
 SNDPLAYSOUNDA   dw       0x0C5F                    ; 5F 0C                ;
 User32          db       'user32',0                ; 75 73 65 72 33 32 00 ; .SizeInitializedData
                 NumHashes equ (User32 rva)/2


                 ; ******************************************************* ;
                 ; Get Kernel32 ImageBase. Uses PEB method                 ;
                 ; includes insane data execution (eax = ImageBase)        ;
                 ; ******************************************************* ;
 BootStrap:      mov      edx, 0x00000000           ; BA 00 00 00 00       ; .SizeUninitializedData & EntryPoint
                 mov      ebx, [fs:edx+0x30]        ; 64 8B 5A 30          ; .BaseOfCode
                 mov      ebx, [ebx+0x0C]           ; 8B 5B 0C             ; .BaseOfData
                 mov      eax, ImageBase            ; B8 00 00 01 00       ; .BaseOfData & ImageBase
                 add      al, 0x00                  ; 04 00                ; .SectionAlignment
                 add      byte [ds:eax], al         ; 00 00                ;
                 add      al, 0x00                  ; 04 00                ; .FileAlignment
                 add      byte [ds:eax], al         ; 00 00                ;
                 push     SizeStackClear            ; 6A 25                ; .MajorOsVersion
                 mov      ebx, [ebx+0x1C]           ; 8B 5B 1C             ; .MinorOsVersion & .MajorImageVersion
 base:           mov      esi, [ebx+0x20]           ; 8B 73 20             ; .MajorImageVersion & MinorImageVersion
                 add      al, 0x00                  ; 04 00                ; .MajorSubsystemVersion
                 mov      ebp, [ebx+0x08]           ; 8B 6B 08             ; .MinorSubsystemVersion & .Win32Version
                 cmp      [esi+0x18], al            ; 38 46 18             ; .Win32VersionValue
                 push     esp                       ; 54                   ; .SizeOfImage
                 mov      ebx, [ebx]                ; 8B 1B                ;
                 pop      edi                       ; 5F                   ;
                 jnz      base                      ; 75 EF                ; .SizeOfHeaders
                 jmp      short DataDirectory       ; EB 25                ;


                 ; ******************************************************* ;
                 ; Run Lengh Encode Stack Args                             ;
                 ; No need to push API args, just decompress to the stack  ;
                 ; Includes BITMAPINFO but requires stack pointer fixup    ;
                 ; ******************************************************* ;
 PackedStack:    db       0x68, 0x28                ; 68 28                ; .CheckSum            ; BitMapInfo.biSize (0x00000028)
                 db       0x76, 0x20                ; 76 20                ;                      ; BitMapInfo.biBitsPerPel (0x0020)
                 dw       0x0003                    ; 03 00                ; .Subsystem           ;
                 db       0x54, 0xC0                ; 54 C0                ; .DllCharacteristics  ; StretchDIBits.DestHeight (0x000000C0)
                 db       0x0D, 0xC0                ; 0D C0                ; .SizeOfStackReserve  ; CreateWindexExA.szClass (Thanks Las)
                 db       0x51, 0x01                ; 51 01                ;                      ; StretchDIBits.DestWidth (0x00000100)
                 db       0x17, 0x91                ; 17 91                ; .SizeOfStackCommit   ; CreateWindexExA.dwStyle (0x91000000)
                 db       0x6D, 0x01                ; 6D 01                ;                      ; BitMapInfo.biWidth (0x00000100)
                 db       0x70, 0xC0                ; 70 C0                ; .SizeOfHeapReserve   ; BitMapInfo.biHeight (0x000000C0)
                 db       0x74, 0x01                ; 74 01                ;                      ; BitMapInfo.biPlanes (0x0001)
                 db       0x66, 0xCC                ; 66 CC                ; .SizeOfHeapCommit    ; StretchDIBits.Rop (0x00CC0020)
                 db       0x0C, 0x18                ; 0C 18                ;                      ; CreateWindexExA.szClass (thanks Las)
                 db       0x5B, 0x10                ; 5A 08                ; .LoaderFlags         ; StretchDIBits.PixelBufer (0x00020000)
                 db       0x64, 0x20                ; 64 20                ;                      ; StretchDIBits.Rop (0x00CC0020)
                 dd       0x00000000                ; 00 00 00 00          ; .NumberOfRvaAndSizes ;
                 PtrStack       equ (ebx + (PackedStack rva) - 0x02)
                 SizeStackClear  =  0x26
                 NumStackValues  = ($-PackedStack)/2

                 ; ******************************************************* ;
                 ; Wav Header                                              ;
                 ; ******************************************************* ;
                 seconds  = 65
                 rate     = 5000
                 samples  = rate*seconds
                 channels = 1
                 bits     = 8
                 size     = samples*channels*bits/8
 Wav:            db       'RIFF'                    ; 52 49 46 46          ;
                 dd       size+0x24                 ; 24 E2 04 00          ;
                 db       'WAVE'                    ; 57 41 56 45          ;
                 db       'fmt '                    ; 66 6D 74 20          ;
                 dd       0x00000010                ; 10 00 00 00          ;
                 dw       0x0001                    ; 01 00                ;
                 dw       channels                  ; 01 00                ;
                 dd       rate                      ; 88 13 00 00          ;
                 dd       rate*channels*bits/8      ; 88 13 00 00          ;
                 dw       channels*bits/8           ; 01 00                ;
                 dw       bits                      ; 08 00                ;
                 dd       'data'                    ; 64 61 74 61          ;
                 dd       size                      ; 00 E2 04 00          ;
                 SizeOfWav = ($-Wav)/4

 WinMM:          db       'winmm',0                 ; 77 69 6E 6D 6D 00    ;
 Gdi32           db       'gdi32',0                 ; 67 64 69 33 32 00    ;

                 ; ******************************************************* ;
                 ; Unpack API Arguments                                    ;
                 ; Uses a sort of Run-Length decoder                       ;
                 ; Any suggestions for improvement?                        ;
                 ; ******************************************************* ;
 DataDirectory:  xchg     eax, ebx                  ; 89 C3                ;
                 pop      ecx                       ; 59                   ;
                 push     edx                       ; 52                   ;
                 loop     $-1                       ; E2 FD                ;
                 mov      cl, NumStackValues        ; B1 0E                ;
 UnPack:         mov      eax, [PtrStack+ecx*0x02]  ; 8B 44 4B 5A          ;
                 mov      dl, al                    ; 88 C2                ;
                 mov      [esp+edx], ah             ; 88 24 14             ;
                 loop     UnPack                    ; E2 F5                ;


                 ; ******************************************************* ;
                 ; Import By Hash                                          ;
                 ; Now with much better algo which allows for 16-bit hash  ;
                 ;     hash ^= *str++ * 113                                ;
                 ; Let me know if you can do better than this              ;
                 ; ******************************************************* ;
                 lea      eax, [ebx+User32 rva]     ; 8D 43 24             ;
                 push     eax                       ; 50                   ;
                 mov      al, Gdi32 rva             ; B0 AE                ;
                 push     eax                       ; 50                   ;
                 mov      al, WinMM rva             ; B0 A8                ;
                 push     eax                       ; 50                   ;
 GetHashes:      push     NumHashes                 ; 6A 12                ;
                 pop      ecx                       ; 59                   ;
                 mov      esi, ebx                  ; 89 DE                ;
 FindFunction:   lodsw                              ; 66 AD                ;
                 pusha                              ; 60                   ;
                 mov      eax, [ebp+0x3C]           ; 8B 45 3C             ;
                 mov      edx, [ebp+eax+0x78]       ; 8B 54 05 78          ;
                 add      edx, ebp                  ; 01 EA                ;
                 mov      ecx, [edx+0x18]           ; 8B 4A 18             ;
 ReDo:           jecxz    Done                      ; E3 36                ;
                 dec      ecx                       ; 49                   ;
                 mov      esi, [edx+0x20]           ; 8B 72 20             ;
                 add      esi, ebp                  ; 01 EE                ;
                 xor      ebx, ebx                  ; 31 DB                ;
                 mov      esi, [esi+ecx*0x04]       ; 8B 34 8E             ;
                 add      esi, ebp                  ; 01 EE                ;
 Hash:           lodsb                              ; AC                   ;
                 imul     ebx, 113                  ; 6B DB 71             ;
                 xor      bl, al                    ; 30 C3                ;
                 test     al, al                    ; 84 C0                ;
                 jnz      Hash                      ; 75 F6                ;
                 cmp      bx, word [esp+0x1C]       ; 66 3B 5C 24 1C       ;
                 jnz      ReDo                      ; 75 E0                ;
                 mov      ebx, [edx+0x24]           ; 8B 5A 24             ;
                 add      ebx, ebp                  ; 01 EB                ;
                 movzx    ecx, word [ebx+ecx*0x02]  ; 0F B7 0C 4B          ;
                 mov      ebx, [edx+0x1C]           ; 8B 5A 1C             ;
                 add      ebx, ebp                  ; 01 EB                ;
                 add      ebp, [ebx+ecx*0x04]       ; 03 2C 8B             ;
                 mov      eax, [esp+0x18]           ; 8B 44 24 18          ;
                 mov      [edi+eax*0x04], ebp       ; 89 2C 87             ;
 Done:           popa                               ; 61                   ;
                 loop     FindFunction              ; E2 B6                ;
                 tinycall LoadLibraryA              ; FF 57 20             ;
                 xchg     eax, ebp                  ; 95                   ;
                 or       ebp, ebp                  ; 09 ED                ;
                 jnz      GetHashes                 ; 75 A9                ;


                 ; ******************************************************* ;
                 ; Boiler Plate. Uses Las's WinClass=0xC018 trick          ;
                 ; EBX = ImageBase                                         ;
                 ; EBP = ApiContext                                        ;
                 ; ******************************************************* ;
 mainCRTStartup: tinycall ShowCursor                ; FF 57 24             ;
                 tinycall CreateWindowExA           ; FF 57 2C             ;
                 mov      edx, esp                  ; 89 E2                ;
                 push     eax                       ; 50                   ;
                 push     edx                       ; 52                   ;
                 push     eax                       ; 50                   ;
                 tinycall GetWindowRect             ; FF 57 30             ;
                 tinycall GetDC                     ; FF 57 28             ;
                 push     eax                       ; 50                   ;
                 mov      ebp, esp                  ; 89 E5                ;

                 ; ******************************************************* ;
                 ; Initialize Synthesizer                                  ;
                 ; We loop PCM from memory, WAV file lives at 0x00020000   ;
                 ; ******************************************************* ;
 Synth:          lea      esi, [ebx+Wav rva]        ; 8D 73 7C             ;
                 lea      edi, [ebx+ebx]            ; 8D 3C 1B             ;
                 push     0x0D                      ; 6A 0D                ;
                 push     edi                       ; 57                   ;
                 push     SizeOfWav                 ; 6A 0B                ;
                 pop      ecx                       ; 59                   ;
                 lodsd                              ; AD                   ;
                 stosd                              ; AB                   ;
                 loop     $-2                       ; E2 FC                ;
                 xchg     eax, ecx                  ; 91                   ;


                 ; ******************************************************* ;
                 ; Byte Beat                                               ;
                 ; Poor man's synthesizer                                  ;
                 ; ******************************************************* ;
 ByteBeat:       mov      eax, ecx                  ; 89 C8                ;
                 mov      edx, ecx                  ; 89 CA                ;
                 mov      esi, ecx                  ; 89 CE                ;
                 sar      edx, 10                   ; C1 FA 0A             ;
                 sar      esi, 13                   ; C1 FE 0D             ;
                 xor      eax, edx                  ; 31 D0                ;
                 and      eax, esi                  ; 21 F0                ;
                 imul     edx                       ; F7 EA                ;
                 lea      edx, [ecx+esi*4]          ; 8D 14 B1             ;
                 add      eax, edx                  ; 01 D0                ;
                 and      eax, 0x1F                 ; 83 E0 1F             ;
                 shr      eax, 0x01                 ; D1 E0                ;
                 add      al, 0x20                  ; D1 E0                ;
                 stosb                              ; AA                   ;
                 loop     ByteBeat                  ; E2 E1                ;
                 tinycall sndPlaySoundA             ; FF 55 64             ;


                 ; ******************************************************* ;
                 ; Main Loop                                               ;
                 ; EBX = ImageBase                                         ;
                 ; EBP = ApiContext                                        ;
                 ; ESI = TickCount                                         ;
                 ; ******************************************************* ;
                 ResX     equ ebp+0x1C              ; 256                  ;
                 ResY     equ ebp+0x20              ; 192                  ;
                 Size     equ ebp+0x1F              ; 256*192              ;
                 Pixel    equ ebp+0x24              ; 0x00080000           ;

 Main:           tinycall GetTickCount              ; FF 55 7C             ;
                 shl      eax, 0x04                 ; C1 E0 04             ;
                 xchg     eax, esi                  ; 96                   ;

                 ; ******************************************************* ;
                 ; Camera Path                                             ;
                 ; Uses a variant of Rrrola's trick                        ;
                 ; ******************************************************* ;
 RayMarcher:     mov      edi, [Pixel]              ; 8B 7D 24             ;
                 mov      ecx, [Size]               ; 8B 4D 1F             ;
 Draw:           mov      eax, ecx                  ; 89 C8                ;
                 sub      ax, 0x6081                ; 66 2D 81 61          ; Thanks Rrrola
                 movsx    edx, ah                   ; 0F BE D4             ; dx = xy % 256 - ResX/2
                 movsx    eax, al                   ; 0F BE C0             ; dy = xy / 256 - ResY/2
                 pusha                              ; 60                   ;
                 mov      ebp, esp                  ; 89 E5                ;
                ;fninit                             ; DB E3                ;
                ;fldpi                              ; D9 EB                ; RayPosX += 8276*sin(TickCount*PI/27808)
                 fild     dword [ebp+0x04]          ; DA 4D 04             ;
                 fidiv    word [ebx+0x16]           ; DE 73 16             ;
                 fsin                               ; D9 FE                ;
                 fimul    word [ebx+0x0E]           ; DE 4B 0E             ;
                 fistp    dword [ebx+0x08]          ; DB 5B 08             ;
                 add      eax, [ebx+0x08]           ; 03 43 08             ;
                 add      ah, 0x40                  ; 80 C4 40             ; RayPosX += CenterOf(Corridor)
                 add      dh, 0x98                  ; 80 C6 98             ; RayPosY += CenterOf(Corridor)


                 ; ******************************************************* ;
                 ; Ray Marching                                            ;
                 ; ******************************************************* ;
                 mov      ecx, [ebx+0x3B]           ; 8B 4B 3B             ;
 RayMarch:       test     dh, 0x20                  ; F6 C6 20             ; Hit ?= Floor | Ceiling
                 mov      edi, 0x00040201           ; BF 01 02 04 00       ; Rgb = 0x00010101 (Brown)
                 jnz      TexGen                    ; 75 1B                ;
                 mov      ebx, esi                  ; 89 F3                ;
                 and      ebx, eax                  ; 21 C3                ;
                 test     bh, 0x80                  ; F6 C7 80             ; Hit ?= Walls
                 mov      edi, 0x00040404           ; BF 04 04 04 00       ; Rgb = 0x00010101 (Grey)
                 jnz      TexGen                    ; 75 0D                ;
                 add      eax, [ebp+0x1C]           ; 03 45 1C             ; RayDirX += [ebp+0x1C]
                 add      edx, [ebp+0x14]           ; 03 55 14             ; RayDirY += [ebp+0x1C]
                 add      esi, 0x7F                 ; 83 C6 7F             ; RayDirZ += 0x7F
                 add      cx, 0x000C                ; 66 83 C1 08          ; RayDist += 8
                 jno      RayMarch                  ; 71 DB                ;


                 ; ******************************************************* ;
                 ; Texture Generation                                      ;
                 ; ******************************************************* ;
 TexGen:         xor      eax, edx                  ; 31 D0                ; TexUV = (X^Y^Z)*256/RayDist
                 xor      eax, esi                  ; 31 F0                ;
                 movzx    eax, ah                   ; 0F B6 C4             ;
                 cdq                                ; 99                   ;
                 mov      ah, al                    ; 88 C4                ;
                 idiv     ecx                       ; F7 F9                ;
                 imul     edi                       ; F7 EF                ; Rgb = TexUV*Rgb
                 mov      [ebp+0x1C], eax           ; 89 45 1C             ;
                 popa                               ; 61                   ;
                 stosd                              ; AB                   ;
                 loop     Draw                      ; E2 99                ;


                 ; ******************************************************* ;
                 ; Blit and Exit                                           ;
                 ; Escape on WM_KEYDOWN (0x0101)                           ;
                 ; ******************************************************* ;
                 push     0x01                      ; 6A 01                ;
                 push     ecx                       ; 51                   ;
                 push     ecx                       ; 51                   ;
                 push     ecx                       ; 51                   ;
                 push     edi                       ; 57                   ; (Tail end of Pixel Buffer)
                 tinycall PeekMessageA              ; FF 55 68             ;
                 tinycall StretchDIBits             ; FF 55 6C             ;
                 mov      [ebp+0x28], esp           ; 89 65 28             ; Add BITMAPINFO*
                 mov      esp, ebp                  ; 89 EC                ; Fixup Stack Pointer
                 dec      byte [edi+0x05]           ; FE 4F 05             ; Exit if 0 == WM_KEYDOWN-1
                 jnz      Main                      ; 0F 85 FF FF FF       ;
                 tinycall ExitProcess               ; FF 55 74             ;
