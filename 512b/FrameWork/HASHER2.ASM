 ;
 ; HASHCALC.ASM
 ;
 format PE GUI 4.0
 entry start
 include 'win32a.inc'


 macro HashIt {
       lodsb                           ; al  = Char Export Asciiz
       imul     ebx, 0x71
       xor      bl, al
      ;imul    ebx, ebx, 141
      ;rol     bx, 0x05                ; ebx = Hash Preparation
      ;rol     bx, 0x01
      ;xor     bl, al                  ; ebx = Hash Complete
      ;add     bl, al
      ;adc     ebx, eax
       test    al, al                  ; al  = 0 Only For End of Asciiz
 }

 ;StretchDIBits    dd 0x4ED54D5C ; gdi32    ; 0xC7EE ;
 ;LoadLibraryA     dd 0xE9826FC6 ; kernel32 ; 0x5B68 ;
 ;ExitProcess      dd 0x38A66AE8 ; kernel32 ; 0x547B ;
 ;GetWindowRect    dd 0xF9AC1F38 ; user32   ; 0x0A9A ;
 ;ShowCursor       dd 0x19A434A8 ; user32   ; 0x4F39 ;
 ;CreateWindowExA  dd 0xF8820ECC ; user32   ; 0x2054 ;
 ;GetDC            dd 0xA4D450D1 ; user32   ; 0xD9D1 ;
 ;PeekMessageA     dd 0xEA1682FE ; user32   ; 0x97B1 ;


 TXT_LIBR = 0x1000 ; Input Process Name
 TXT_NAME = 0x2000 ; Input Process Name
 TXT_HASH = 0x3000 ; Output Hash
 BTN_HASH = 0x4000 ; Calculate Hash For Process Name
 BTN_TEST = 0x5000 ; Test Hash For Collisions
 BTN_EXIT = 0x6000 ; Exit Dialog

 section '.idata' import data readable writeable
      library kernel32, 'KERNEL32.DLL',\
              user32,   'USER32.DLL'
      include 'api\kernel32.inc'
      include 'api\user32.inc'

 section '.rsrc' resource data readable
      directory RT_DIALOG, dialogs
      resource  dialogs, 37, LANG_ENGLISH+SUBLANG_DEFAULT, demonstration
      dialog demonstration,'Calculate Hash', 0x20, 0x20, 0xC8, 0x50, WS_CAPTION+WS_POPUP+WS_SYSMENU+DS_MODALFRAME
      dialogitem 'STATIC','Library:',    -1, 0x08, 0x08, 0x20, 0x08, WS_VISIBLE
      dialogitem 'STATIC','Process:',    -1, 0x08, 0x18, 0x20, 0x08, WS_VISIBLE
      dialogitem 'STATIC','Hash:',       -1, 0x08, 0x28, 0x20, 0x08, WS_VISIBLE

      dialogitem 'EDIT','',        TXT_LIBR, 0x28, 0x06, 0x98, 0x0C, WS_VISIBLE+WS_BORDER+WS_TABSTOP
      dialogitem 'EDIT','',        TXT_NAME, 0x28, 0x16, 0x98, 0x0C, WS_VISIBLE+WS_BORDER+WS_TABSTOP+ES_AUTOHSCROLL
      dialogitem 'EDIT','',        TXT_HASH, 0x28, 0x26, 0x98, 0x0C, WS_VISIBLE+WS_BORDER+WS_TABSTOP+ES_AUTOHSCROLL

      dialogitem 'BUTTON','Hash',  BTN_HASH, 0x08, 0x38, 0x38, 0x10, WS_VISIBLE+WS_TABSTOP+BS_DEFPUSHBUTTON
      dialogitem 'BUTTON','Test',  BTN_TEST, 0x48, 0x38, 0x38, 0x10, WS_VISIBLE+WS_TABSTOP+BS_DEFPUSHBUTTON
      dialogitem 'BUTTON','Exit',  BTN_EXIT, 0x88, 0x38, 0x38, 0x10, WS_VISIBLE+WS_TABSTOP+BS_PUSHBUTTON
      enddialog

 section '.data' data readable writeable
   szHex     db '0123456789ABCDEF'
   szSuccess db 'Success - '
   szName    db 0x101 dup (0)
   szLibr    db 0x101 dup (0)
   szHash    db 0x101 dup (0)

   szFound   db 'Process found using Hash '
   szStr     db '0x........',0
   szNoLibr  db 'Please enter a library name!', 0
   szNoName  db 'Please enter a process name!', 0
   szMissing db 'Library not found!', 0
   szLost    db 'Process not found!', 0
   szFail    db 'Hash failed due to collision!', 0
   lpProcess dd ?
   lpLibrary dd ?
   procHash  dd ?

 section '.code' code readable executable
 start:
      invoke  GetModuleHandleA, 0
      invoke  DialogBoxParamA, eax, 37, HWND_DESKTOP, DialogProc, 0

 exit:
      invoke  ExitProcess,0

 proc DialogProc hDlg, dMsg, dParam, lParam
      push    ebx esi edi
      mov     eax, [dMsg]
      cmp     eax, WM_COMMAND
      jz      .wm_command
      cmp     eax, WM_CLOSE
      jz      .wm_close
      xor     eax, eax
      jmp     .finish


  .wm_test:
      invoke  GetDlgItemTextA, [hDlg], TXT_LIBR, szLibr, 0x101
      cmp     byte [szLibr], NULL
      jnz     .get_name
      invoke  MessageBoxA, HWND_DESKTOP, szNoLibr, NULL, MB_ICONWARNING+MB_OK
      invoke  SetFocus, [hDlg]
      jmp     .processed

  .get_name:
      invoke  GetDlgItemTextA, [hDlg], TXT_NAME, szName, 0x101
      cmp     byte [szName], NULL
      jnz     .test_hash
      invoke  MessageBoxA, HWND_DESKTOP, szNoName, NULL, MB_ICONWARNING+MB_OK
      invoke  SetFocus, [hDlg]
      jmp     .processed

  .test_hash:
      invoke  LoadLibraryA, szLibr
      mov     [lpLibrary], eax
      or      eax, eax
      jnz     .get_proc
      invoke  MessageBoxA, HWND_DESKTOP, szMissing, NULL, MB_ICONWARNING+MB_OK
      invoke  SetFocus, [hDlg]
      jmp     .processed

  .get_proc:
      invoke  GetProcAddress, eax, szName
      mov     [lpProcess], eax
      or      eax, eax
      jnz     .scan_hash
      invoke  MessageBoxA, HWND_DESKTOP, szLost, NULL, MB_ICONWARNING+MB_OK
      invoke  SetFocus, [hDlg]
      jmp     .processed

  .scan_hash:
      call    make_hash
      invoke  SetDlgItemTextA, [hDlg], TXT_HASH, szStr, 0x0A
      mov     ebx, [procHash]

      push    [lpLibrary]
      push    ebx
      call    hash
      pop     edx
      pop     edx
      cmp     eax, [lpProcess]
      jz      .success
      invoke  MessageBoxA, HWND_DESKTOP, szFail, szName, MB_ICONWARNING+MB_OK
      invoke  SetFocus, [hDlg]
      jmp     .processed

  .success:
      invoke  MessageBoxA, HWND_DESKTOP, szFound, szSuccess, MB_OK
      invoke  SetFocus, [hDlg]
      jmp     .processed




  .wm_hash:
      invoke  GetDlgItemTextA, [hDlg], TXT_NAME, szName, 0x101
      cmp     byte [szName], NULL
      jnz     .hashName
      invoke  MessageBoxA, HWND_DESKTOP, szNoName, NULL, MB_ICONWARNING+MB_OK
      invoke  SetFocus, [hDlg]
      jmp     .processed

  .hashName:
      call    make_hash
      invoke  SetDlgItemTextA, [hDlg], TXT_HASH, szStr, 0x0A
      jmp     .processed

  .wm_command:
      mov     eax, [dParam]
      cmp     eax, BN_CLICKED shl 16 + BTN_TEST
      jz      .wm_test
      cmp     eax, BN_CLICKED shl 16 + BTN_HASH
      jz      .wm_hash
      cmp     eax, BN_CLICKED shl 16 + BTN_EXIT
      jnz     .processed

  .wm_close:
      invoke  EndDialog, [hDlg], 0

  .processed:
      mov     eax, TRUE

  .finish:
      pop     edi esi ebx
      ret
 endp

 hash:
      pusha                           ; Preserve Registers
      mov     ebp, [esp + 0x28]       ; ebp = VA DOS Header (eax)
      mov     eax, [ebp + 0x3C]       ; eax = RVA NT Header
      mov     edx, [ebp + eax + 0x78] ; edx = RVA Data Directory
      add     edx, ebp                ; edx = RVA -> VA
      mov     ecx, [edx + 0x18]       ; ecx = Num Exports
      mov     edi, [edx + 0x20]       ; edi = RVA Exports Asciiz
      add     edi, ebp                ; edi = RVA -> VA
                                      ;
 srch:
      jecxz   done                    ; ecx = 0 No More Exports
      dec     ecx                     ; ecx = Num Exports Decreased
      mov     esi, [edi + ecx * 0x04] ; esi = RVA Export Asciiz Index
      add     esi, ebp                ; esi = RVA -> VA
      xor     ebx, ebx                ; ebx = Null Hash
      xor     eax, eax                ; eax = Null Asciiz

 calc:
     ;lodsb                           ; al  = Char Export Asciiz
     ;rol     ebx, 0x06               ; ebx = Hash Preparation
     ;xor     bl, al                  ; ebx = Hash Complete
     ;test    al, al                  ; al  = 0 Only For End of Asciiz
      HashIt
      jnz     calc                    ; If Not Zero Keep Hashing
      cmp     bx, [esp + 0x24]        ; Check Hash Against Input
      jnz     srch                    ; If Not Equal Hash Next Function
                                      ;
      mov     edi, [edx + 0x24]       ; edi = RVA Function Ordinal
      add     edi, ebp                ; edi = RVA -> VA
      mov     cx, [edi + ecx * 0x02]  ; cx  = Function Ordinal Index
      mov     edi, [edx + 0x1C]       ; edi = Function RVAS List
      add     edi, ebp                ; edi = RVA -> VA
      mov     eax, [edi + ecx * 0x04] ; eax = Function RVA
      add     eax, ebp                ; eax = RVA -> VA
      mov     [esp + 0x1C], eax       ; Return eax

 done:
      popa                            ; Restore Registers
      ret                             ; Return

 make_hash:
      mov     esi, szName
      xor     ebx, ebx
      xor     eax, eax

  .hash:
     ;lodsb
     ;rol     ebx, 0x06
     ;xor     bl, al
     ;test    al, al
      HashIt
      jnz     .hash
      and     ebx, 0x0000FFFF

      mov     [procHash], ebx
      xchg    ebx, edx
      mov     ecx, 0x00000008
      mov     ebx, szHex
      mov     edi, szStr+2

  .hexStr:
      xor     eax, eax
      rol     edx, 0x04
      mov     al, dl
      and     al, 0x0F
      mov     al, [ebx+eax]
      stosb
      loop    .hexStr
      ret