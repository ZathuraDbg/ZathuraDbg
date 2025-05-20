{ SPDX-License-Identifier: ZLIB
Copyright (c) 2014 - 2023 Guillaume Vareille http://ysengrin.com
  _________
 /         \ tinyfiledialogs v3.13 [May 2, 2023] zlib licence
 |tiny file|
 | dialogs |
 \____  ___/ http://tinyfiledialogs.sourceforge.net
      \|     git clone http://git.code.sf.net/p/tinyfiledialogs/code tinyfd

 - License -
 This software is provided 'as-is', without any express or implied
 warranty.  In no event will the authors be held liable for any damages
 arising from the use of this software.
 Permission is granted to anyone to use this software for any purpose,
 including commercial applications, and to alter it and redistribute it
 freely, subject to the following restrictions:
 1. The origin of this software must not be misrepresented; you must not
 claim that you wrote the original software.  If you use this software
 in a product, an acknowledgment in the product documentation would be
 appreciated but is not required.
 2. Altered source versions must be plainly marked as such, and must not be
 misrepresented as being the original software.
 3. This notice may not be removed or altered from any source distribution.
         ___________________________________________________________
        |                                                           |
        |     If you like this new PASCAL module please upvote      |
        |        my stackoverflow answer on the PASCAL post         |
        |            https://stackoverflow.com/a/59657117           |
        |___________________________________________________________|
}

unit tinyfd;
interface

{$linklib c}

{ Adapted from
  Automatically converted by H2Pas 1.0.0 from ../../tinyfiledialogs.h
  The following command line parameters were used:
    ../../tinyfiledialogs.h
    -o
    tinyfd.pp
}

  Type
  Pchar  = ^char;

{$ifdef _WIN32}
  Pwchar_t  = ^wchar_t;
{$ENDIF}


{$IFDEF FPC}
{$PACKRECORDS C}
{$ENDIF}

{$ifdef _WIN32}
    var
      tinyfd_winUtf8 : longint;cvar;external;

  function tinyfd_utf8toMbcs(aUtf8string:Pchar):Pchar;cdecl;
  function tinyfd_utf16toMbcs(aUtf16string:Pwchar_t):Pchar;cdecl;
  function tinyfd_mbcsTo16(aMbcsString:Pchar):Pwchar_t;cdecl;
  function tinyfd_mbcsTo8(aMbcsString:Pchar):Pchar;cdecl;
  function tinyfd_utf8to16(aUtf8string:Pchar):Pwchar_t;cdecl;
  function tinyfd_utf16to8(aUtf16string:Pwchar_t):Pchar;cdecl;
{$endif}

  function tinyfd_getGlobalChar(aCharVariableName:Pchar):Pchar;cdecl;
  function tinyfd_getGlobalInt(aIntVariableName:Pchar):longint;cdecl;
  function tinyfd_setGlobalInt(aIntVariableName:Pchar; aValue:longint):longint;cdecl;

    var
      tinyfd_version : array[0..7] of char;cvar;external;
      tinyfd_needs : Pchar;cvar;external;
      tinyfd_verbose : longint;cvar;external;
      tinyfd_silent : longint;cvar;external;
      tinyfd_allowCursesDialogs : longint;cvar;external;
      tinyfd_forceConsole : longint;cvar;external;
      tinyfd_assumeGraphicDisplay : longint;cvar;external;
      tinyfd_response : array[0..1023] of char;cvar;external;

  procedure tinyfd_beep;cdecl;
  function tinyfd_notifyPopup(aTitle:Pchar; aMessage:Pchar; aIconType:Pchar):longint;cdecl;
  function tinyfd_messageBox(aTitle:Pchar; aMessage:Pchar; aDialogType:Pchar; aIconType:Pchar; aDefaultButton:longint):longint;cdecl;
  function tinyfd_inputBox(aTitle:Pchar; aMessage:Pchar; aDefaultInput:Pchar):Pchar;cdecl;
  function tinyfd_saveFileDialog(aTitle:Pchar; aDefaultPathAndFile:Pchar; aNumOfFilterPatterns:longint; aFilterPatterns:PPchar; aSingleFilterDescription:Pchar):Pchar;cdecl;
  function tinyfd_openFileDialog(aTitle:Pchar; aDefaultPathAndFile:Pchar; aNumOfFilterPatterns:longint; aFilterPatterns:PPchar; aSingleFilterDescription:Pchar;aAllowMultipleSelects:longint):Pchar;cdecl;
  function tinyfd_selectFolderDialog(aTitle:Pchar; aDefaultPath:Pchar):Pchar;cdecl;
  function tinyfd_colorChooser(aTitle:Pchar; aDefaultHexRGB:Pchar; aDefaultRGB:array of byte; aoResultRGB:array of byte):Pchar;cdecl;

{$ifdef _WIN32}
  function tinyfd_notifyPopupW(aTitle:Pwchar_t; aMessage:Pwchar_t; aIconType:Pwchar_t):longint;cdecl;
  function tinyfd_messageBoxW(aTitle:Pwchar_t; aMessage:Pwchar_t; aDialogType:Pwchar_t; aIconType:Pwchar_t; aDefaultButton:longint):longint;cdecl;
  function tinyfd_inputBoxW(aTitle:Pwchar_t; aMessage:Pwchar_t; aDefaultInput:Pwchar_t):Pwchar_t;cdecl;
  function tinyfd_saveFileDialogW(aTitle:Pwchar_t; aDefaultPathAndFile:Pwchar_t; aNumOfFilterPatterns:longint; aFilterPatterns:PPwchar_t; aSingleFilterDescription:Pwchar_t):Pwchar_t;cdecl;
  function tinyfd_openFileDialogW(aTitle:Pwchar_t; aDefaultPathAndFile:Pwchar_t; aNumOfFilterPatterns:longint; aFilterPatterns:PPwchar_t; aSingleFilterDescription:Pwchar_t;aAllowMultipleSelects:longint):Pwchar_t;cdecl;
  function tinyfd_selectFolderDialogW(aTitle:Pwchar_t; aDefaultPath:Pwchar_t):Pwchar_t;cdecl;
  function tinyfd_colorChooserW(aTitle:Pwchar_t; aDefaultHexRGB:Pwchar_t; aDefaultRGB:array of byte; aoResultRGB:array of byte):Pwchar_t;cdecl;
{$endif}

implementation

{$Link 'tinyfiledialogs.o'}

{$ifdef _WIN32}
  function tinyfd_utf8toMbcs(aUtf8string:Pchar):Pchar;cdecl;external;
  function tinyfd_utf16toMbcs(aUtf16string:Pwchar_t):Pchar;cdecl;external;
  function tinyfd_mbcsTo16(aMbcsString:Pchar):Pwchar_t;cdecl;external;
  function tinyfd_mbcsTo8(aMbcsString:Pchar):Pchar;cdecl;external;
  function tinyfd_utf8to16(aUtf8string:Pchar):Pwchar_t;cdecl;external;
  function tinyfd_utf16to8(aUtf16string:Pwchar_t):Pchar;cdecl;external;
{$endif}

  function tinyfd_getGlobalChar(aCharVariableName:Pchar):Pchar;cdecl;external;
  function tinyfd_getGlobalInt(aIntVariableName:Pchar):longint;cdecl;external;
  function tinyfd_setGlobalInt(aIntVariableName:Pchar; aValue:longint):longint;cdecl;external;

  procedure tinyfd_beep;cdecl;external;
  function tinyfd_notifyPopup(aTitle:Pchar; aMessage:Pchar; aIconType:Pchar):longint;cdecl;external;
  function tinyfd_messageBox(aTitle:Pchar; aMessage:Pchar; aDialogType:Pchar; aIconType:Pchar; aDefaultButton:longint):longint;cdecl;external;
  function tinyfd_inputBox(aTitle:Pchar; aMessage:Pchar; aDefaultInput:Pchar):Pchar;cdecl;external;
  function tinyfd_saveFileDialog(aTitle:Pchar; aDefaultPathAndFile:Pchar; aNumOfFilterPatterns:longint; aFilterPatterns:PPchar; aSingleFilterDescription:Pchar):Pchar;cdecl;external;
  function tinyfd_openFileDialog(aTitle:Pchar; aDefaultPathAndFile:Pchar; aNumOfFilterPatterns:longint; aFilterPatterns:PPchar; aSingleFilterDescription:Pchar;aAllowMultipleSelects:longint):Pchar;cdecl;external;
  function tinyfd_selectFolderDialog(aTitle:Pchar; aDefaultPath:Pchar):Pchar;cdecl;external;
  function tinyfd_colorChooser(aTitle:Pchar; aDefaultHexRGB:Pchar; aDefaultRGB:array of byte; aoResultRGB:array of byte):Pchar;cdecl;external;

{$ifdef _WIN32}
  function tinyfd_notifyPopupW(aTitle:Pwchar_t; aMessage:Pwchar_t; aIconType:Pwchar_t):longint;cdecl;external;
  function tinyfd_messageBoxW(aTitle:Pwchar_t; aMessage:Pwchar_t; aDialogType:Pwchar_t; aIconType:Pwchar_t; aDefaultButton:longint):longint;cdecl;external;
  function tinyfd_inputBoxW(aTitle:Pwchar_t; aMessage:Pwchar_t; aDefaultInput:Pwchar_t):Pwchar_t;cdecl;external;
  function tinyfd_saveFileDialogW(aTitle:Pwchar_t; aDefaultPathAndFile:Pwchar_t; aNumOfFilterPatterns:longint; aFilterPatterns:PPwchar_t; aSingleFilterDescription:Pwchar_t):Pwchar_t;cdecl;external;
  function tinyfd_openFileDialogW(aTitle:Pwchar_t; aDefaultPathAndFile:Pwchar_t; aNumOfFilterPatterns:longint; aFilterPatterns:PPwchar_t; aSingleFilterDescription:Pwchar_t;aAllowMultipleSelects:longint):Pwchar_t;cdecl;external;
  function tinyfd_selectFolderDialogW(aTitle:Pwchar_t; aDefaultPath:Pwchar_t):Pwchar_t;cdecl;external;
  function tinyfd_colorChooserW(aTitle:Pwchar_t; aDefaultHexRGB:Pwchar_t; aDefaultRGB:array of byte; aoResultRGB:array of byte):Pwchar_t;cdecl;external;
{$endif}

end.
