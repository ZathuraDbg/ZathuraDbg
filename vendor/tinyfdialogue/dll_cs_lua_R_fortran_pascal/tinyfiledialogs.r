# SPDX-License-Identifier: ZLIB
# Copyright (c) 2014 - 2023 Guillaume Vareille http://ysengrin.com
#  _________
# /         \ tinyfiledialogs v3.14.0 [Sep 12, 2023]
# |tiny file|
# | dialogs |
# \____  ___/ http://tinyfiledialogs.sourceforge.net
#      \|     git clone http://git.code.sf.net/p/tinyfiledialogs/code tinyfd

# - License -
# This software is provided 'as-is', without any express or implied
# warranty.  In no event will the authors be held liable for any damages
# arising from the use of this software.
# Permission is granted to anyone to use this software for any purpose,
# including commercial applications, and to alter it and redistribute it
# freely, subject to the following restrictions:
# 1. The origin of this software must not be misrepresented; you must not
# claim that you wrote the original software.  If you use this software
# in a product, an acknowledgment in the product documentation would be
# appreciated but is not required.
# 2. Altered source versions must be plainly marked as such, and must not be
# misrepresented as being the original software.
# 3. This notice may not be removed or altered from any source distribution.
#         ___________________________________________________________
#        |                                                           |
#        |     If you like this new R interface please upvote        |
#        |        my stackoverflow answer on the R post              |
#        |            https://stackoverflow.com/a/77091332           |
#        |___________________________________________________________|




# Load the appropriate tinyfd library

# Macintosh
dyn.load("tinyfiledialogsAppleSilicon.dylib")
#dyn.load("tinyfiledialogsIntel.dylib")

# Linux on Intel
#dyn.load("tinyfiledialogsLinux86.so")
#dyn.load("tinyfiledialogsLinux64.so")

# Windows on Intel
#dyn.load("tinyfiledialogs32.dll")
#dyn.load("tinyfiledialogs64.dll")


# R interface to tinyfd C functions

tinyfd_beep <- function() {
  result <- .C("tinyfd_beep")
  return(result)
}


tinyfd_notifyPopup <- function(aTitle, aMessage, aIconType)
{
  result <- .C("tinyfd_notifyPopup",
                charToRaw(aTitle),
                charToRaw(aMessage),
                charToRaw(aIconType))

  return(result)
}


tinyfd_messageBox <- function(aTitle , aMessage , aDialogType , aIconType , aDefaultButton)
{
  result <- .C("tfd_messageBox",
                charToRaw(aTitle),
                charToRaw(aMessage),
                charToRaw(aDialogType),
                charToRaw(aIconType),
		lDefaultButton = as.integer(aDefaultButton) )

  return(result$lDefaultButton)
}


tinyfd_inputBox <- function(aTitle , aMessage , aDefaultInput) # "NULL" for a password box
{
  result <- .C("tfd_inputBox",
                charToRaw(aTitle),
                charToRaw(aMessage),
		lTextOutput = aDefaultInput )

  if ( result$lTextOutput == "NULL" ) return()
  else return(result$lTextOutput)
}


tinyfd_saveFileDialog <- function(aTitle, aDefaultPathAndFile, aNumOfFilterPatterns,
					aFilterPatterns, aSingleFilterDescription )
{
  result <- .C("tfd_saveFileDialog",
                charToRaw(aTitle),
		lSaveFile = aDefaultPathAndFile ,
		as.integer(aNumOfFilterPatterns) ,
		aFilterPatterns ,
		charToRaw(aSingleFilterDescription) )

  if ( result$lSaveFile == "NULL" ) return()
  else return(result$lSaveFile)
}


tinyfd_openFileDialog <- function(aTitle, aDefaultPathAndFile , aNumOfFilterPatterns,
			aFilterPatterns, aSingleFilterDescription , aAllowMultipleSelects )
{
  result <- .C("tfd_openFileDialog",
                charToRaw(aTitle),
		lOpenFile = aDefaultPathAndFile ,
		as.integer(aNumOfFilterPatterns) ,
		aFilterPatterns ,
		charToRaw(aSingleFilterDescription) ,
		as.integer(aAllowMultipleSelects) )

  if ( result$lOpenFile == "NULL" ) return()
  else return(result$lOpenFile)
}


tinyfd_selectFolderDialog <- function(aTitle, aDefaultPath)
{
  result <- .C("tfd_selectFolderDialog",
                charToRaw(aTitle),
		lSelectedFolder = aDefaultPath )

  if ( result$lSelectedFolder == "NULL" ) return()
  else return(result$lSelectedFolder)
}


tinyfd_colorChooser <- function(aTitle, aDefaultHexRGB) # "#FF0000"
{
  result <- .C("tfd_colorChooser",
                charToRaw(aTitle),
		lOutputHexRGB = aDefaultHexRGB )

  if ( result$lOutputHexRGB == "NULL" ) return()
  else return(result$lOutputHexRGB)
}


# example R calls to tinyfd functions

tinyfd_beep()
tinyfd_notifyPopup( "a title" , "a message", "warning" )
tinyfd_messageBox( "a title" , "a message" , "yesno" , "info" , 1 )
tinyfd_inputBox( "a title" , "a message" , "NULL" ) # "NULL" for a password box
tinyfd_saveFileDialog( "a title" , "/Users/bardos/Documents/test.txt" , 0 , "" , "")
tinyfd_saveFileDialog( "a title" , "/Users/bardos/Documents/test.txt" , 1  , c ("*.txt","*.jpg") , "some files")
lFilename <- tinyfd_openFileDialog( "a title" , "/Users/bardos/Documents/" , 1 , c ("*.txt","*.jpg") , "some files" , 0 )
lFilename
tinyfd_selectFolderDialog( "a title" , "/Users/bardos/Devs" )
tinyfd_colorChooser( "a title" , "#FF0000" )
