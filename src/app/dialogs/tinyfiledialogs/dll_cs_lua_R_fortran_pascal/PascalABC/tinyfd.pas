{ SPDX-License-Identifier: ZLIB
Copyright (c) 2014 - 2023 Guillaume Vareille http://ysengrin.com

found on this page:
	https://github.com/pascalabcnet/pascalabcnet/discussions/2782
}

unit tinyfd;

uses System;

procedure tinyfd_beep(); external 'tinyfiledialogs64.dll';

function tinyfd_notifyPopup(aTitle: string;
                            aMessage: string;
                            aIconType: string): integer;
                            external 'tinyfiledialogs64.dll';

function tinyfd_messageBox(aTitle: string;
                           aMessage: string;
                           aDialogTyle: string;
                           aIconType: string;
                           aDefaultButton: integer): integer;
                           external 'tinyfiledialogs64.dll';

function tinyfd_inputBox(aTitle: string;
                         aMessage: string;
                         aDefaultInput: string): IntPtr;
                         external 'tinyfiledialogs64.dll';

function tinyfd_saveFileDialog(aTitle: string;
                               aDefaultPathAndFile: string;
                               aNumOfFilterPatterns: integer;
                               aFilterPatterns: array of string;
                               aSingleFilterDescription: string): IntPtr;
                               external 'tinyfiledialogs64.dll';

function tinyfd_openFileDialog(aTitle: string;
                               aDefaultPathAndFile: string;
                               aNumOfFilterPatterns: integer;
                               aFilterPatterns: array of string;
                               aSingleFilterDescription: string;
                               aAllowMultipleSelects: integer): IntPtr;
                               external 'tinyfiledialogs64.dll';

function tinyfd_selectFolderDialog(aTitle: string;
                                   aDefaultPathAndFile: string): IntPtr;
                                   external 'tinyfiledialogs64.dll';

function tinyfd_colorChooser(aTitle: string;
                             aDefaultHexRGB: string;
                             aDefaultRGB: array of byte;
                             aoResultRGB: array of byte): IntPtr;
                             external 'tinyfiledialogs64.dll';

end.
