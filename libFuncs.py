# -*- coding: utf-8 -*-
import math
import sys
import os
import random

libFuncsList = [".sqrt", ".abs", ".rand", ".cabs", ".fabs", ".labs", ".exp", ".frexp", ".ldexp", ".log", ".log10", ".pow", ".pow10", ".acos", ".asin", ".atan", ".atan2", ".cos", ".sin", ".tan", ".cosh", ".sinh", ".tanh", ".hypot", ".ceil", ".floor", ".fmod", ".modf", ".strcmp"]
char_return_type = ['peekb', 'stpcpy', 'strcat', 'strchr', 'strcpy', 'strdup', 'strlwr', 'strncat', 'strncpy', 'strnset', 'strpbrk', 'strrchr', 'strrev', 'strset', 'strstr', 'strtok', 'strupr']
char_pointer_return_type = ['ecvt', 'fcvt', 'gcvt', 'ultoa', 'ltoa', 'itoa', 'getcwd', 'mktemp', 'searchpath', 'ecvt', 'fcvt', 'gcvt', 'ultoa', 'ltoa', 'itoa', 'strerror', 'cgets', 'fgets', 'parsfnm', 'getdta',
'sbrk', 'ctime', 'asctime']
int_return_type = ['isalpha', 'isalnum', 'isascii', 'iscntrl', 'isdigit', 'isgraph', 'islower', 'isprint', 'ispunct', 'isspace', 'isupper', 'isxdigit', 'tolower', 'toupper', 'abs', 'rand', 'atoi',
'matherr', 'chdir', 'findfirst', 'findnext', 'fnsplit', 'getcurdir', 'getdisk', 'setdisk', 'mkdir', 'rmdir', 'execl', 'execle', 'execlp', 'execlpe', 'execv', 'execve', 'execvp', 'execvpe', 'spawnl',
'spawnle', 'spawnlp', 'spawnlpe', 'spawnv', 'spawnve', 'spawnvp', 'spawnvpe', 'system', 'atoi', 'toascii', 'tolower', '_tolower', 'toupper', '_toupper', 'matherr', 'kbhit', 'fgetchar', 'getch', 'putch',
'getchar', 'putchar', 'getche', 'ungetch', 'scanf', 'vscanf', 'cscanf', 'sscanf', 'vsscanf', 'puts', 'printf', 'vprintf', 'cprintf', 'vcprintf', 'sprintf', 'vsprintf', 'rename', 'ioctl', 'gsignal', '_open', 'open', 'creat', '_creat',
'creatnew', 'creattemp', 'read', '_read', 'write', '_write', 'dup', 'dup2', 'eof', 'setmode', 'getftime', 'setftime', 'isatty', 'lock', 'unlock', 'close', '_close', 'getc', 'putc', 'getw', 'putw', 'ungetc', 'fgetc',
'fgetc', 'fputc', 'fputs', 'fread', 'fwrite', 'fscanf', 'vfscanf', 'fprintf', 'vfprintf', 'fseek', 'rewind', 'feof', 'fileno', 'ferror', 'fclose', 'fcloseall', 'fflush', 'fflushall', 'access', 'chmod', '_chmod', 'unlink',
'absread', 'abswrite', 'bdos', 'bdosptr', 'int86', 'int86x', 'intdos', 'intdosx', 'inport', 'inportb', 'peek', 'randbrd', 'randbwr', 'getverify', 'getcbrk', 'setcbrk', 'dosexterr', 'bioscom', 'biosdisk',
'biodquip', 'bioskey', 'biosmemory', 'biosprint', 'biostime', 'memicmp', 'strcmp', 'strcspn', 'stricmp', 'strlen', 'strncmp', 'strnicmp', 'strspn', 'allocmem', 'freemem', 'setblock', 'brk', 'stime']
int_unsigned_return_type = ['_clear87', '_status87', 'sleep', 'FP_OFF', 'FP_SEG', 'getpsp']
double_return_type = ['cabs', 'fabs', 'exp', 'frexp', 'ldexp', 'log', 'log10', 'pow', 'pow10', 'sqrt', 'acos', 'asin', 'atan', 'atan2', 'cos', 'sin', 'tan', 'cosh', 'sinh', 'tanh', 'hypot', 'ceil', 'floor', 'poly',
'modf', 'fmod', 'frexp', 'atof', 'atoi', 'atol', 'atof', 'strtod', '_matherr', 'atof', 'strtod', '_matherr', 'difftime']
long_return_type = ['labs', 'atol', 'strtol', 'atol', 'strtol', 'filelength', 'lseek', 'tell', 'ftell', 'coreleft', 'farcoreleft', 'dostounix']
file_pointer_return_type = ['fopen', 'fdopen', 'freopen']
linux_lib = ['__errno_location']

random.seed(10)

def lib_abs(i):  # int abs(int i) Returns the absolute value of integer i
    return abs(i)  # abs is a built-in function

def lib_rand():  # int rand() Generates and returns a random number
    random.seed(10)
    return random.randint(0, 32767)

def lib_cabs(znum):  # double cabs(struct complex znum) Returns the absolute value of complex number znum
    return abs(znum)

def lib_fabs(x):  # double fabs(double x) Returns the absolute value of double x
    return abs(x)

def lib_labs(n):  # long labs(long n) Returns the absolute value of long integer n
    return abs(n)

def lib_exp(x):  # double exp(double x) Returns the value of the exponential function e^x
    return math.exp(x)

def lib_frexp(value, eptr):  # double frexp(double value, int *eptr) Returns the value x in value=x*2^n, stores n in eptr
    return math.frexp(value)  # math.frexp(1.625) results in (0.8125, 1)

def lib_ldexp(value, exp):  # double ldexp(double value, int exp) Returns the value of value*2^exp
    return math.ldexp(value, exp)

def lib_log(x):  # double log(double x) Returns the natural logarithm of x
    return math.log(x)

def lib_log10(x):  # double log10(double x) Returns the base-10 logarithm of x
    return math.log10(x)

def lib_pow(x, y):  # double pow(double x, double y) Returns the value of x^y
    return math.pow(x, y)

def lib_pow10(p):  # double pow10(int p) Returns the value of 10^p
    return math.pow(10, p)

def lib_sqrt(x):  # double sqrt(double x) Returns the square root of x
    return math.sqrt(x)

def lib_acos(x):  # double acos(double x) Returns the arccosine of x, where x is in radians
    return math.acos(x)

def lib_asin(x):  # double asin(double x) Returns the arcsine of x, where x is in radians
    return math.asin(x)

def lib_atan(x):  # double atan(double x) Returns the arctangent of x, where x is in radians
    return math.atan(x)

def lib_atan2(y, x):  # double atan2(double y, double x) Returns the arctangent of y/x, where y and x are in radians
    return math.atan2(y, x)

def lib_cos(x):  # double cos(double x) Returns the cosine of x, where x is in radians
    return math.cos(x)

def lib_sin(x):  # double sin(double x) Returns the sine of x, where x is in radians
    return math.sin(x)

def lib_tan(x):  # double tan(double x) Returns the tangent of x, where x is in radians
    return math.tan(x)

def lib_cosh(x):  # double cosh(double x) Returns the hyperbolic cosine of x
    return math.cosh(x)

def lib_sinh(x):  # double sinh(double x) Returns the hyperbolic sine of x
    return math.sinh(x)

def lib_tanh(x):  # double tanh(double x) Returns the hyperbolic tangent of x
    return math.tanh(x)

def lib_hypot(x, y):  # double hypot(double x, double y) Returns the length of the hypotenuse of a right triangle with sides x and y
    return math.hypot(x, y)

def lib_ceil(x):  # double ceil(double x) Returns the smallest integer greater than or equal to x
    return math.ceil(x)

def lib_floor(x):  # double floor(double x) Returns the largest integer less than or equal to x
    return math.floor(x)

def lib_poly(x, n, c):  # double poly(double x, int n, double c[]) Generates a polynomial from the parameters
    pass

def lib_fmod(x, y):  # double fmod(double x, double y) Returns the remainder of x divided by y
    return math.fmod(x, y)

def lib_modf(value, iptr):  # double modf(double value, double *iptr) Splits value into its fractional and integer parts
    return math.modf(value)  # Fractional part is returned, integer part is placed in iptr, special attention required
