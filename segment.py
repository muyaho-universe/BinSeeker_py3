# -*- coding: utf-8 -*-
dataSegment = []  # Initialized global variable and static variable
rodataSegment = []  # String constant and variable decorated by const
bssSegment = []  # Uninitialized global variable and static variable
codeSegment = []  # Used to determine the last block of a function return, where a load operation will load the next statement of the caller from memory. This address is different for each binary, so it is generalized as a pointer.
constUsage = {}  # addr:value
