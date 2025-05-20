! SPDX-License-Identifier: ZLIB
! Copyright (c) 2014 - 2023 Guillaume Vareille http://ysengrin.com
!  _________
! /         \ tinyfiledialogs v3.18.1 [May 26, 2024]
! |tiny file|
! | dialogs |
! \____  ___/ http://tinyfiledialogs.sourceforge.net
!      \|     git clone http://git.code.sf.net/p/tinyfiledialogs/code tinyfd

! - License -
! This software is provided 'as-is', without any express or implied
! warranty.  In no event will the authors be held liable for any damages
! arising from the use of this software.
! Permission is granted to anyone to use this software for any purpose,
! including commercial applications, and to alter it and redistribute it
! freely, subject to the following restrictions:
! 1. The origin of this software must not be misrepresented; you must not
! claim that you wrote the original software.  If you use this software
! in a product, an acknowledgment in the product documentation would be
! appreciated but is not required.
! 2. Altered source versions must be plainly marked as such, and must not be
! misrepresented as being the original software.
! 3. This notice may not be removed or altered from any source distribution.
!         ___________________________________________________________
!        |                                                           |
!        |     If you like this new FORTRAN module please upvote     |
!        |        my stackoverflow answer on the FORTRAN post        |
!        |            https://stackoverflow.com/a/59657117           |
!        |___________________________________________________________|

! See compilation instructions at the end of this file

	program main
		use tinyfd
		use iso_c_binding, only: c_ptr, c_null_char, c_f_pointer, c_loc, c_null_ptr, c_associated, c_int, c_char
		implicit none
		type(c_ptr) :: cpointer
		character(512), pointer :: fpointer
		character(128), target :: aDefaultInput
		character(512) :: string, aMessage, aDefaultPath, aDefaultPathAndFile
		character(128) :: aTitle, aDialogType, aIconType
		character(128) :: aSingleFilterDescription
		integer :: i, aInteger, aButtonPressed, aDefaultButton, aNumOfFilterPatterns, aAllowMultipleSelects
		character(8) :: aDefaultHexRGB
		character(3) :: aDefaultRGB, aoResultRGB
		type (c_ptr), dimension(:), allocatable :: aFilterPatterns
		character(len=16,kind=c_char), allocatable, target :: lExtensions(:)

		! calling subroutine tinyfd_beep (it doesn't return anything: it's a subroutine')
		write(*,'(A)') "Enter tinyfd_beep()"
		call tinyfd_beep()

		! calling function tinyfd_notifyPopup (it returns one value: it's a function')
		write(*,'(A)') "Enter tinyfd_notifyPopup()"
		aTitle = "a Title" // char(0)
		aMessage = "a Message" // char(0)
		aIconType = "info" // char(0)
		aInteger = tinyfd_notifyPopup(aTitle, aMessage, aIconType )

		! calling function tinyfd_messageBox
		write(*,'(A)') "Enter tinyfd_messageBox()"
		aTitle = "a Title" // char(0)
		aMessage = "a Message" // char(0)
		aIconType = "info" // char(0)
		aDialogType = "ok" // char(0)
		aDefaultButton = 1
		aButtonPressed = tinyfd_messageBox(aTitle, aMessage, aDialogType, aIconType, aDefaultButton )
		write (*,*) aButtonPressed

		! calling function tinyfd_inputbox
		write(*,'(A)') "Enter tinyfd_inputbox()"
		aTitle = "a Title" // char(0)
		aMessage = "a Message" // char(0)
		aDefaultInput = "an Input" // char(0)
		cpointer = tinyfd_inputBox(aTitle, aMessage, c_loc(aDefaultInput) )
		! or for a password box: cpointer = tinyfd_inputbox(atitle, amessage, c_null_ptr )
		if ( c_associated(cpointer) ) then
			call c_f_pointer(cpointer, fpointer) ! Convert C Pointer to Fortran pointer
			string = fpointer(1:index(fpointer,c_null_char)-1) ! Remove NULL character at the end
			write (*,'(A)') string
		endif

		! calling function tinyfd_saveFileDialog
		write(*,'(A)') "Enter tinyfd_saveFileDialog()"
		aTitle = "a Title" // char(0)
		aDefaultPathAndFile = "" // char(0)
		aSingleFilterDescription = "" // char(0) ! or "Text Files" // char(0)
		aNumOfFilterPatterns = 2
		allocate (lExtensions( aNumOfFilterPatterns ))
		allocate (aFilterPatterns( aNumOfFilterPatterns ))
		lExtensions(1) = "*.txt" // char(0)
		lExtensions(2) = "*.doc" // char(0)
		do i = 1, aNumOfFilterPatterns, 1
			aFilterPatterns(i) = c_loc(lExtensions(i))
			write (*,'(A)') lExtensions(i)
			!write (*,*) aFilterPatterns(i)
		end do
		cpointer = tinyfd_saveFileDialog(aTitle, aDefaultPathAndFile, aNumOfFilterPatterns, aFilterPatterns, aSingleFilterDescription)
		! or cpointer = tinyfd_saveFileDialog(aTitle, aDefaultPathAndFile, 0, c_null_ptr, aSingleFilterDescription)
		deallocate (aFilterPatterns)
		deallocate (lExtensions)
		if ( c_associated(cpointer) ) then
			call c_f_pointer(cpointer, fpointer) ! Convert C Pointer to Fortran pointer
			string = fpointer(1:index(fpointer,c_null_char)-1) ! Remove NULL character at the end
			write (*,'(A)') string
		endif

		! calling function tinyfd_openFileDialog
		write(*,'(A)') "Enter tinyfd_openFileDialog()"
		aTitle = "a Title" // char(0)
		aDefaultPathAndFile = "" // char(0)
		aAllowMultipleSelects = 1
		aSingleFilterDescription = "" // char(0) ! or "Text Files" // char(0)
		aNumOfFilterPatterns = 2
		allocate (lExtensions( aNumOfFilterPatterns ))
		allocate (aFilterPatterns( aNumOfFilterPatterns ))
		lExtensions(1) = "*.txt" // char(0)
		lExtensions(2) = "*.doc" // char(0)
		do i = 1, aNumOfFilterPatterns, 1
			aFilterPatterns(i) = c_loc(lExtensions(i))
			write (*,'(A)') lExtensions(i)
			!write (*,*) aFilterPatterns(i)
		end do
		cpointer = tinyfd_openFileDialog(aTitle, aDefaultPathAndFile, aNumOfFilterPatterns, aFilterPatterns, &
					aSingleFilterDescription, aAllowMultipleSelects)
		! or cpointer = tinyfd_openFileDialog(aTitle, aDefaultPathAndFile, 0, c_null_ptr, aSingleFilterDescription, aAllowMultipleSelects)
		deallocate (aFilterPatterns)
		deallocate (lExtensions)
		if ( c_associated(cpointer) ) then
			call c_f_pointer(cpointer, fpointer) ! Convert C Pointer to Fortran pointer
			string = fpointer(1:index(fpointer,c_null_char)-1) ! Remove NULL character at the end
			write (*,'(A)') string
		endif

		! calling function tinyfd_selectFolderDialog
		write(*,'(A)') "Enter tinyfd_selectFolderDialog()"
		aTitle = "a Title" // char(0)
		aDefaultPath = "" // char(0)
		cpointer = tinyfd_selectFolderDialog(aTitle, aDefaultPath )
		if ( c_associated(cpointer) ) then
			call c_f_pointer(cpointer, fpointer) ! Convert C Pointer to Fortran pointer
			string = fpointer(1:index(fpointer,c_null_char)-1) ! Remove NULL character at the end
			write (*,'(A)') string
		endif

		! calling function tinyfd_colorChooser
		write(*,'(A)') "Enter tinyfd_colorChooser()"
		aTitle = "a Title" // char(0)
		aDefaultHexRGB = "" // char(0) ! or "#FF0000" // char(0)
		aDefaultRGB = char(0) // char(0) // char(255)
		print *, "aDefaultRGB", IACHAR(aDefaultRGB(1:1)), IACHAR(aDefaultRGB(2:2)), IACHAR(aDefaultRGB(3:3))
		cpointer = tinyfd_colorChooser(aTitle, aDefaultHexRGB, aDefaultRGB, aoResultRGB )
		print *, "aoResultRGB", IACHAR(aoResultRGB(1:1)), IACHAR(aoResultRGB(2:2)), IACHAR(aoResultRGB(3:3))
		if ( c_associated(cpointer) ) then
			call c_f_pointer(cpointer, fpointer) ! Convert C Pointer to Fortran pointer
			string = fpointer(1:index(fpointer,c_null_char)-1) ! Remove NULL character at the end
			write (*,'(A)') string(1:10)
			write (*,*) string
		endif

	end program main

! gcc -c ../../tinyfiledialogs.c
! gfortran -c tinyfd_module.f90 tinyfd_main.f90
! gfortran -o tinyfd_exe tinyfd_module.o tinyfiledialogs.o tinyfd_main.o

! or in one line :  gfortran -o tinyfd_exe tinyfd_module.f90 ../../tinyfiledialogs.c tinyfd_main.f90

! This works on VisualStudio with Intel Fortran (make sure the C project has very similar settings as your fortran project):
      ________________________________________________________________________
! 1) | Install The Windows SDK                                                |
!    |     http://developer.microsoft.com/en-us/windows/downloads/windows-sdk |
!    |                          The end user doesn't need to install anythings |
!    |________________________________________________________________________|
! 2) Create a new empty C/C++ project, verify the configuration is for X64.
! 3) Add existing files: tinyfiledialogs.c and tinyfiledialogs.h
! 4) Build this project. It will fail because there is no main(),
!         but it will create tinyfiledialogs.obj
! 5) Create a new empty Fortran project, verify the configuration is for X64.
! 6) Add existing file: tinyfiledialogs.obj - the one that was created on 4)
! 7) Add existing files: tinyfd_module.f90 and tinyfd_main.f90
! 8) In the properties of this fortran project, in the linker input field,
!              add: comdlg32.lib ole32.lib user32.lib shell32.lib
!              or maybe add: %(AdditionalDependencies)
! 9) Build and Run. Voila !
