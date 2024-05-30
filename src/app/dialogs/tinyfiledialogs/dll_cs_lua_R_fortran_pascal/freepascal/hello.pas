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

 See compilation instructions at the end of this file
}

program Hello ;

uses tinyfd ;

var
    lReturnedChar : Pchar;
    lReturnedValue : Integer ;
    lCReturnedString: String ;
    lArrayOfChar: array[0..2] of byte = (0,0,255);

begin
    writeln ('Hello tinyfd');
    tinyfd_beep();

    lReturnedChar := tinyfd_inputBox('tinyfd_query', '', '');
    writeln (tinyfd_response);
    if lReturnedChar <> nil then
        lReturnedValue := tinyfd_messageBox('Graphic Mode',tinyfd_response, 'okcancel', 'info', 1)
	else
        lReturnedValue := tinyfd_messageBox('Console Mode',tinyfd_response, 'okcancel', 'info', 1);

    if lReturnedValue = 0 then exit;

    lReturnedValue := tinyfd_messageBox('A tinyfd title','graphic dialogs [Yes] / console mode [No]', 'yesno', 'question', 1);
    if lReturnedValue = 0  then tinyfd_forceConsole := 1 ;

	tinyfd_notifyPopup('A tinyfd title', 'This is a notification', 'warning');

    lReturnedChar := tinyfd_inputBox('A tinyfd title','This is an input box', '');
    if lReturnedChar = nil then exit; { detect cancel was pressed - no input is allowed }
    lCReturnedString := StrPas(lReturnedChar);
    writeln (lCReturnedString);

    lCReturnedString := tinyfd_inputBox('A tinyfd title','This is a password box', nil);
    writeln (lCReturnedString);
    if Length(lCReturnedString) = 0 then exit; { detect no input }

    lCReturnedString := tinyfd_saveFileDialog('Choose a filename to save to','lala.txt', 0, nil,nil);
    writeln (lCReturnedString);
    if Length(lCReturnedString) = 0 then exit;

    lCReturnedString := tinyfd_openFileDialog('Choose a filename to read from','../lala.txt', 0, nil, nil, 0);
    writeln (lCReturnedString);
    if Length(lCReturnedString) = 0 then exit;

    lCReturnedString := tinyfd_selectFolderDialog('Select a folder','../..');
    writeln (lCReturnedString);
    if Length(lCReturnedString) = 0 then exit;

    lCReturnedString := tinyfd_colorChooser('A tinyfd title','', lArrayOfChar, lArrayOfChar);
    writeln (lCReturnedString);
end.

{
gcc -c ../../tinyfiledialogs.c
fpc tinyfd.pp
fpc hello.pas
}
