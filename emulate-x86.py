# -*- coding: utf-8 -*-
from registerOffset import *
import pyvex
import archinfo
import database
import convertToIR
import registerOffset
# import x86g_calculate_eflags_c
import x86g_calculate_condition
import libFuncs
import segment
import math
import sys
import os
import copy
import traceback
from ctypes import *
import shutil  # for deleting directories
import platform
import datetime
import randomInput
from copy import deepcopy
import math
from ctypes import c_longlong, c_int32, c_uint32, c_ubyte, c_ushort, c_byte, c_short, c_ulonglong

# Remove the reload and sys.setdefaultencoding, as they are deprecated in Python 3
# Set encoding in Python 3 by default is UTF-8

ls = os.linesep
currentEmulatedBlock = 0  # block start address
currentNextIP = 0  # block start address, two branches: higher or lower address
maxLoopOrRecursion = 5
funcLoopOrRecursion = {}  # recursion counter
blockLoopOrRecursion = {}  # block loop counter
priorLoopFlag = {}
allUserFuncs = set()
stackStart = 0  # ebp-based function usage, determined by ebp, not used anymore
stackStartList = []  # for non-ebp-based functions, determined by esp
stackEnd = 0  # determined by esp regardless of ebp-based or not
stackArgs = []
registerArgs = []
temporarySpace = {}
globalSpace = {}
memorySpace = {}
constsSpace = {}
switchJump = {}
ebpBased = {}
switchFlag = False
currentInstr = 0
currentState = ""
nextStartAddr = 0
currentStartAddr = 0
ebp = 178956976
esp = 178956970
nan = float('nan')
emulateAll = True
emulateAddr = 0
emulateFunctions = set()
childPath = "signature"
pushAndCallList = []
functionInfo = {}
signatureLength = 0
argsDistributionIndex = 0
randomValueList_same = []
functionArgs = {}
registerArgsState = {}
isVulnerabilityProgram = False
programName = ""
fileName = ""
db = 0
fwrite = 0

def getArgValue(arg):
    if isinstance(arg, pyvex.expr.Const):
        return int(str(arg), 16)
    elif isinstance(arg, pyvex.expr.RdTmp):
        return temporarySpace[int(arg.tmp)]
    else:
        raise BaseException
        return 0

def processTriOp(op, args):
    arg1 = getArgValue(args[0])  # Rounding encoding
    arg2 = getArgValue(args[1])
    arg3 = getArgValue(args[2])
    result = 0
    operation = op[4:]
    
    if operation == "AddF64":
        result = arg2 + arg3        
    elif operation == "SubF64":
        result = arg2 - arg3
    elif operation == "MulF64":
        result = arg2 * arg3
    elif operation == "DivF64":
        result = arg2 / arg3 if arg3 != 0 else 0
    else:
        raise ValueError(f"Unsupported operation: {operation}")
        
    return intOrFloatToFloat(arg1, result)

def processQop(op, args):
    operation = op[4:]
    
    if operation == "x86g_use_seg_selector":
        return 0
    else:
        raise ValueError(f"Unsupported Qop: {operation}")

def processCCall(type, op, args):
    if str(op.name) == "x86g_use_seg_selector":
        return 0
    elif str(op.name) == "x86g_calculate_eflags_c":
        return x86g_calculate_condition.x86g_calculate_eflags_c(
            getValue(args[0]), getValue(args[1]), getValue(args[2]), getValue(args[3])
        )
    elif str(op.name) == "x86g_calculate_condition":
        return x86g_calculate_condition.x86g_calculate_condition(
            getValue(args[0]), getValue(args[1]), getValue(args[2]), getValue(args[3]), getValue(args[4])
        )
    elif str(op.name) == "x86g_calculate_eflags_all":
        return x86g_calculate_condition.x86g_calculate_eflags_all(
            getValue(args[0]), getValue(args[1]), getValue(args[2]), getValue(args[3])
        )
    elif str(op.name) == "x86g_create_fpucw":
        return x86g_calculate_condition.x86g_create_fpucw(getValue(args[0]))
    elif str(op.name) == "x86g_check_fldcw":
        return x86g_calculate_condition.x86g_check_fldcw(getValue(args[0]))
    else:
        raise ValueError(f"Unsupported CCall operation: {op.name}")

def writeCmp(op, arg1, arg2):
    fwrite.write(f"CC {arg1} {arg2} {op}\n")
    
def writeIO(type, value):
    fwrite.write(f"{type} {value}\n")

def two32sTo64(arg1, arg2):
    return (c_ulonglong(arg1).value << 32) | c_ulonglong(arg2).value

def two16to32(arg1, arg2):
    return (c_uint32(arg1).value << 16) | c_uint32(arg2).value

def two32sTo64S(arg1, arg2):
    return (c_longlong(arg1).value << 32) | c_longlong(arg2).value

def divMod64to32(signed, arg1, arg2):
    if arg2 == 0:
        return 0

    if signed:
        div, mod = divmod(arg1, arg2)
        if arg1 * arg2 < 0 and mod != 0:
            mod -= arg2
            div += 1
        return two32sTo64S(mod, div)
    else:
        div, mod = divmod(arg1, arg2)
        return two32sTo64(mod, div)

def getValueFromVector64_u(bits, arg1):
    if bits == 8:
        return [c_ubyte((arg1 >> (i * 8)) & 0xFF).value for i in range(8)]
    elif bits == 16:
        return [c_ushort((arg1 >> (i * 16)) & 0xFFFF).value for i in range(4)]
    elif bits == 32:
        return [c_uint32((arg1 >> (i * 32)) & 0xFFFFFFFF).value for i in range(2)]

def getValueFromVector64_s(bits, arg1):
    if bits == 8:
        return [c_byte((arg1 >> (i * 8)) & 0xFF).value for i in range(8)]
    elif bits == 16:
        return [c_short((arg1 >> (i * 16)) & 0xFFFF).value for i in range(4)]
    elif bits == 32:
        return [c_int32((arg1 >> (i * 32)) & 0xFFFFFFFF).value for i in range(2)]

def permVector64(bits, arg1, arg2):
    values1 = getValueFromVector64_u(bits, arg1)
    values2 = getValueFromVector64_u(bits, arg2)

    argL = values1[::-1]  # Reverse the order of values1
    argR = values2[::-1]  # Reverse the order of values2
    
    result = []
    for i in range(8):
        tmp = argR[i]
        if 0 <= tmp <= 7:
            result.append(argL[tmp])
        else:
            raise ValueError("error in perm8x8")
    
    return sum(result[i] << (i * 8) for i in range(8))

def shiftVector64(bits, arg1, arg2, shift_func):
    values = getValueFromVector64_u(bits, arg1) if shift_func == 'shl' else getValueFromVector64_s(bits, arg1)
    shift = c_int32(arg2).value
    
    max_shift = {8: 7, 16: 15, 32: 31}[bits]
    if not (0 <= shift <= max_shift):
        raise ValueError(f"Shift value out of range for {bits}-bit vector")

    shifted_values = [(shift_op(v, shift) if shift_func == 'shl' else shift_op_signed(v, shift)) for v in values]

    return sum(shifted_values[i] << (i * bits) for i in range(len(shifted_values)))

def shlVector64(bits, arg1, arg2):
    return shiftVector64(bits, arg1, arg2, 'shl')

def sarVector64(bits, arg1, arg2):
    return shiftVector64(bits, arg1, arg2, 'sar')

def shift_op(value, shift):
    return c_ubyte(value << shift).value if isinstance(value, int) else c_ushort(value << shift).value

def shift_op_signed(value, shift):
    return c_byte(value >> shift).value if isinstance(value, int) else c_short(value >> shift).value

def addV128(bits, arg1, arg2):
    count = 128 // bits
    mask = {32: 0xFFFFFFFF, 64: 0xFFFFFFFFFFFFFFFF}.get(bits)
    if mask is None:
        raise ValueError("Unsupported bit size in addV128 method")

    result = 0
    for i in range(count):
        item1 = arg1 & mask
        item2 = arg2 & mask
        if bits == 32:
            temp = c_uint32(item1 + item2).value
            result |= temp << (32 * i)
            arg1 >>= 32
            arg2 >>= 32
        elif bits == 64:
            temp = c_ulonglong(item1 + item2).value
            result |= temp << (64 * i)
            arg1 >>= 64
            arg2 >>= 64

    return result


def addVector64(bits, arg1, arg2):
    def add_values(mask, shift_size, arg1, arg2, bit_class):
        results = []
        for _ in range(64 // shift_size):
            value1 = bit_class(arg1 & mask).value
            value2 = bit_class(arg2 & mask).value
            result = bit_class(value1 + value2).value
            results.append(result)
            arg1 >>= shift_size
            arg2 >>= shift_size
        return sum(r << (i * shift_size) for i, r in enumerate(results))

    if bits == 8:
        return add_values(0xFF, 8, arg1, arg2, c_ubyte)
    elif bits == 16:
        return add_values(0xFFFF, 16, arg1, arg2, c_ushort)
    elif bits == 32:
        return add_values(0xFFFFFFFF, 32, arg1, arg2, c_uint32)
    else:
        raise ValueError("Unsupported bit size in addVector64")

def interleaveLO32_4(value1, value2):
    result = 0
    for i in range(4):
        item1 = value1 & 0xFF  # higher bits
        item2 = value2 & 0xFF  # lower bits
        result |= (item1 << (16 * i + 8)) | (item2 << (16 * i))
        value1 >>= 8
        value2 >>= 8
    return result


def processBinOp(op, args):
    def get_op_suffix(op, offset=4):
        return op[offset:]

    def arithmetic_op(arg1, arg2, func, c_type):
        result = func(arg1, arg2)
        return c_type(result).value

    arg1 = getArgValue(args[0])
    if arg1 is None:
        pass
    arg2 = getArgValue(args[1])
    
    operations = {
        "Sub32": lambda: arithmetic_op(arg1, arg2, lambda x, y: x - y, c_uint32),
        "Sub64": lambda: arithmetic_op(arg1, arg2, lambda x, y: x - y, c_uint32),
        "Sub8": lambda: toUChar(arg1 - arg2),
        "Add8": lambda: toUChar(arg1 + arg2),
        "Add16": lambda: toUShort(arg1 + arg2),
        "Add32": lambda: arithmetic_op(arg1, arg2, lambda x, y: x + y, c_uint32),
        "Add64": lambda: arithmetic_op(arg1, arg2, lambda x, y: x + y, c_uint32),
        "And32": lambda: arithmetic_op(arg1, arg2, lambda x, y: x & y, c_uint32),
        "And64": lambda: arithmetic_op(arg1, arg2, lambda x, y: x & y, c_ulonglong),
        "AndV128": lambda: arg1 & arg2,
        "And8": lambda: toUChar(arg1 & arg2),
        "And16": lambda: toUShort(arg1 & arg2),
        "Max32U": lambda: max(c_uint32(arg1).value, c_uint32(arg2).value),
        "Mul32": lambda: arithmetic_op(arg1, arg2, lambda x, y: x * y, c_uint32),
        "Mul64": lambda: arithmetic_op(arg1, arg2, lambda x, y: x * y, c_ulonglong),
        "Mul8": lambda: toUChar(arg1 * arg2),
        "Mul16": lambda: toUShort(arg1 * arg2),
        "DivU32": lambda: arg1_u // arg2_u if arg2_u != 0 else 0,
        "DivS32": lambda: arg1_s // arg2_s if arg2_s != 0 else 0,
        "Or32": lambda: arithmetic_op(arg1, arg2, lambda x, y: x | y, c_uint32),
        "Or64": lambda: arithmetic_op(arg1, arg2, lambda x, y: x | y, c_ulonglong),
        "Or8": lambda: toUChar(arg1 | arg2),
        "Or16": lambda: toUShort(arg1 | arg2),
        "Shl32": lambda: arithmetic_op(arg1, arg2, lambda x, y: x << y, c_uint32),
        "Shl64": lambda: arithmetic_op(arg1, arg2, lambda x, y: x << y, c_ulonglong),
        "Shr32": lambda: arithmetic_op(c_uint32(arg1).value, c_int32(arg2).value, lambda x, y: x >> y, c_uint32),
        "Shr64": lambda: arithmetic_op(c_ulonglong(arg1).value, c_int32(arg2).value, lambda x, y: x >> y, c_ulonglong),
        "Xor32": lambda: arithmetic_op(arg1, arg2, lambda x, y: x ^ y, c_uint32),
        "Xor64": lambda: arithmetic_op(arg1, arg2, lambda x, y: x ^ y, c_ulonglong),
    }

    op_suffix = get_op_suffix(op)

    if op_suffix in operations:
        return operations[op_suffix]()
    else:
        raise BaseException(f"Unsupported binary operation: {op_suffix}")

    return result


def writeCmpWrapper(type, arg1, arg2):
    pointer1 = isPointer(arg1)
    pointer2 = isPointer(arg2)
    global signatureLength
    signatureLength += 1
    if pointer1 and pointer2:
        writeCmp(type, "pointer", "pointer")
    elif pointer1:
        writeCmp(type, "pointer", arg2)
    elif pointer2:
        writeCmp(type, arg1, "pointer")
    else:
        writeCmp(type, arg1, arg2)

def cmpGT(bits, arg1, arg2, value_type):
    result = 0
    mask = (1 << bits) - 1
    shift = bits
    
    for i in range(64 // bits):
        value1 = value_type(arg1 & mask).value
        value2 = value_type(arg2 & mask).value
        arg1 >>= shift
        arg2 >>= shift
        flag = cmp(value1, value2)
        if flag > 0:
            result |= (1 << (shift * i))
        else:
            result |= (0 << (shift * i))

    return result

def cmpGT64(bits, arg1, arg2):
    if bits == 8:
        return cmpGT(bits, arg1, arg2, c_byte)
    elif bits == 16:
        return cmpGT(bits, arg1, arg2, c_short)
    elif bits == 32:
        return cmpGT(bits, arg1, arg2, c_int32)
    else:
        raise ValueError(f"Unsupported bit size: {bits}")

def f64HItoV128(value1, value2):
    return (value1 << 64) | value2


def f64toI64S(encoding, value):
    if encoding == 0:  # Round to nearest, ties to even
        value11 = math.ceil(value)
        value22 = math.floor(value)
        if abs(value11 - value) > abs(value22 - value):
            return c_longlong(int(math.floor(value))).value
        elif abs(value11 - value) < abs(value22 - value):
            return c_longlong(int(math.ceil(value))).value
        else:  # Handling .5 cases
            value1 = int(math.ceil(value))
            value2 = int(math.floor(value))
            if (value1 % 2) == 0:
                return c_longlong(int(math.ceil(value))).value
            else:
                return c_longlong(int(math.floor(value))).value
    elif encoding == 1:  # Round to negative infinity
        return c_longlong(int(math.floor(value))).value
    elif encoding == 2:  # Round to positive infinity
        return c_longlong(int(math.ceil(value))).value
    elif encoding == 3:  # Round toward zero
        if value > 0:
            return c_longlong(int(math.floor(value))).value
        else:
            return c_longlong(int(math.ceil(value))).value
    elif encoding == 4:  # Round to nearest, ties away from 0
        value11 = math.ceil(value)
        value22 = math.floor(value)
        if abs(value11 - value) > abs(value22 - value):
            return c_longlong(int(math.floor(value))).value
        elif abs(value11 - value) < abs(value22 - value):
            return c_longlong(int(math.ceil(value))).value
        else:  # Handling .5 cases
            if value < 0:
                return c_longlong(int(math.floor(value))).value
            else:
                return c_longlong(int(math.ceil(value))).value
    elif encoding == 5:  # Round to prepare for shorter precision
        return c_longlong(int(round(value))).value
    elif encoding == 6:  # Round to away from 0
        if value < 0:
            return c_longlong(int(math.floor(value))).value
        else:
            return c_longlong(int(math.ceil(value))).value
    elif encoding == 7:  # Round to nearest, ties towards 0
        value11 = math.ceil(value)
        value22 = math.floor(value)
        if abs(value11 - value) > abs(value22 - value):
            return c_longlong(int(math.floor(value))).value
        elif abs(value11 - value) < abs(value22 - value):
            return c_longlong(int(math.ceil(value))).value
        else:  # Handling .5 cases
            if value > 0:
                return c_longlong(int(math.floor(value))).value
            else:
                return c_longlong(int(math.ceil(value))).value
    else:
        raise BaseException

def f64toI32S(encoding, value):
    if encoding == 0:  # Round to nearest, ties to even
        value11 = math.ceil(value)
        value22 = math.floor(value)
        if abs(value11 - value) > abs(value22 - value):
            return c_int32(int(math.floor(value))).value
        elif abs(value11 - value) < abs(value22 - value):
            return c_int32(int(math.ceil(value))).value
        else:  # Handling .5 cases
            value1 = int(math.ceil(value))
            value2 = int(math.floor(value))
            if (value1 % 2) == 0:
                return c_int32(int(math.ceil(value))).value
            else:
                return c_int32(int(math.floor(value))).value
    elif encoding == 1:  # Round to negative infinity
        return c_int32(int(math.floor(value))).value
    elif encoding == 2:  # Round to positive infinity
        return c_int32(int(math.ceil(value))).value
    elif encoding == 3:  # Round toward zero
        if value > 0:
            return c_int32(int(math.floor(value))).value
        else:
            return c_int32(int(math.ceil(value))).value
    elif encoding == 4:  # Round to nearest, ties away from 0
        value11 = math.ceil(value)
        value22 = math.floor(value)
        if abs(value11 - value) > abs(value22 - value):
            return c_int32(int(math.floor(value))).value
        elif abs(value11 - value) < abs(value22 - value):
            return c_int32(int(math.ceil(value))).value
        else:  # Handling .5 cases
            if value < 0:
                return c_int32(int(math.floor(value))).value
            else:
                return c_int32(int(math.ceil(value))).value
    elif encoding == 5:  # Round to prepare for shorter precision
        return c_int32(int(round(value))).value
    elif encoding == 6:  # Round to away from 0
        if value < 0:
            return c_int32(int(math.floor(value))).value
        else:
            return c_int32(int(math.ceil(value))).value
    elif encoding == 7:  # Round to nearest, ties towards 0
        value11 = math.ceil(value)
        value22 = math.floor(value)
        if abs(value11 - value) > abs(value22 - value):
            return c_int32(int(math.floor(value))).value
        elif abs(value11 - value) < abs(value22 - value):
            return c_int32(int(math.ceil(value))).value
        else:  # Handling .5 cases
            if value > 0:
                return c_int32(int(math.floor(value))).value
            else:
                return c_int32(int(math.ceil(value))).value
    else:
        raise BaseException

def intOrFloatToFloat(encoding, value):
    if encoding == 0:  # Round to nearest, ties to even
        value11 = math.ceil(value)
        value22 = math.floor(value)
        if abs(value11 - value) > abs(value22 - value):
            return float(math.floor(value))
        elif abs(value11 - value) < abs(value22 - value):
            return float(math.ceil(value))
        else:  # Handling .5 cases
            value1 = int(math.ceil(value))
            value2 = int(math.floor(value))
            if (value1 % 2) == 0:
                return float(math.ceil(value))
            else:
                return float(math.floor(value))
    elif encoding == 1:  # Round to negative infinity
        return float(math.floor(value))
    elif encoding == 2:  # Round to positive infinity
        return float(math.ceil(value))
    elif encoding == 3:  # Round toward zero
        if value > 0:
            return float(math.floor(value))
        else:
            return float(math.ceil(value))
    elif encoding == 4:  # Round to nearest, ties away from 0
        value11 = math.ceil(value)
        value22 = math.floor(value)
        if abs(value11 - value) > abs(value22 - value):
            return float(math.floor(value))
        elif abs(value11 - value) < abs(value22 - value):
            return float(math.ceil(value))
        else:  # Handling .5 cases
            if value < 0:
                return float(math.floor(value))
            else:
                return float(math.ceil(value))
    elif encoding == 5:  # Round to prepare for shorter precision
        return float(round(value))
    elif encoding == 6:  # Round to away from 0
        if value < 0:
            return float(math.floor(value))
        else:
            return float(math.ceil(value))
    elif encoding == 7:  # Round to nearest, ties towards 0
        value11 = math.ceil(value)
        value22 = math.floor(value)
        if abs(value11 - value) > abs(value22 - value):
            return float(math.floor(value))
        elif abs(value11 - value) < abs(value22 - value):
            return float(math.ceil(value))
        else:  # Handling .5 cases
            if value > 0:
                return float(math.floor(value))
            else:
                return float(math.ceil(value))
    else:
        raise BaseException

def isClose(a, b, rel_tol=1e-09, abs_tol=0.0):
    return abs(a-b) <= max(rel_tol * max(abs(a), abs(b)), abs_tol)

def isNan(x):
    return math.isnan(x)
    
def get64HIto32(value1):
    value1 = c_ulonglong(value1).value
    return c_uint32(value1 >> 32).value

def get32HIto16(value1):
    value1 = c_uint32(value1).value
    return c_uint32(value1 >> 16).value
    
def toUShort(value):
    value = int(value & 0xFFFF)
    return c_ushort(value).value

def toUChar(value):
    value = int(value & 0xFF)
    return c_ubyte(value).value

def processUnopExpr(op, args):
    result = getArgValue(args[0])
    
    if "1Uto32" in op[4:] or "1Uto8" in op[4:] or "1Uto64" in op[4:]:
        return 1 if result else 0
    elif "1Sto8" in op[4:]:
        return 0xFF if result else 0
    elif "1Sto16" in op[4:]:
        return 0xFFFF if result else 0
    elif "1Sto32" in op[4:]:
        return 0xFFFFFFFF if result else 0
    elif "1Sto64" in op[4:]:
        return 0xFFFFFFFFFFFFFFFF if result else 0
    elif "8Sto32" in op[4:]:
        value = c_int32(result << 24).value
        value = value >> 24
        return value
    elif "8Sto64" in op[4:]:
        value = c_longlong(result << 56).value
        value = value >> 56
        return value
    elif "16Sto32" in op[4:]:
        value = c_int32(result << 16).value
        value = value >> 16
        return value
    elif "8Uto32" in op[4:] or "8Uto64" in op[4:]:
        return result & 0xFF
    elif "8Uto16" in op[4:]:
        return result & 0xFF
    elif "8Sto16" in op[4:]:
        value = c_short(result << 8).value
        value = value >> 8
        return value
    elif "16Uto32" in op[4:]:
        return result & 0xFFFF
    elif "16Uto64" in op[4:]:
        return result & 0xFFFF
    elif "32to16" in op[4:]:
        return toUShort(result)
    elif "32to8" in op[4:]:
        return toUChar(result)
    elif "32to1" in op[4:] or "64to1" in op[4:]:
        return bool(result & 1)
    elif "NotV128" in op[4:] or "Not32" in op[4:] or "Not64" in op[4:]:
        return ~result
    elif "Not16" in op[4:]:
        return toUShort(~result)
    elif "Not8" in op[4:]:
        return toUChar(~result)
    elif "Not1" in op[4:]:
        return not result
    elif "64to8" in op[4:]:
        return c_ubyte(int(result & 0xFF)).value
    elif "64to16" in op[4:]:
        return c_ushort(int(result & 0xFFFF)).value
    elif "64to32" in op[4:]:
        return c_uint32(result & 0xFFFFFFFF).value
    elif "64HIto32" in op[4:]:
        return get64HIto32(result)
    elif "32HIto16" in op[4:]:
        return get32HIto16(result)
    elif "32Uto64" in op[4:]:
        return result & 0xFFFFFFFF
    elif "16Sto64" in op[4:]:
        value = c_longlong(result << 48).value
        return value >> 48
    elif "32Sto64" in op[4:]:
        value = c_longlong(result << 32).value
        return value >> 32  # signed shift
    elif "16to8" in op[4:]:
        return toUChar(toUShort(result) & 0xFF)
    elif "16HIto8" in op[4:]:
        return toUChar((toUShort(result) >> 8) & 0xFF)
    elif "CmpNEZ8" in op[4:]:
        return bool(result & 0xFF)
    elif "CmpNEZ32" in op[4:]:
        return bool(result & 0xFFFFFFFF)
    elif "CmpNEZ64" in op[4:]:
        return result != 0
    elif "CmpwNEZ32" in op[4:]:
        value = c_uint32(result).value
        return 0 if value == 0 else 0xFFFFFFFF
    elif "CmpwNEZ64" in op[4:]:
        value = c_ulonglong(result).value
        return 0 if value == 0 else 0xFFFFFFFFFFFFFFFF
    elif "Left32" in op[4:]:
        raise BaseException("Left32")
    elif "Left64" in op[4:]:
        raise BaseException("Left64")
    elif "Clz32" in op[4:]:
        value = c_uint32(result).value
        return fold_Clz32(value)
    elif "Clz64" in op[4:]:
        value = c_ulonglong(result).value
        return fold_Clz64(value)
    elif "32UtoV128" in op[4:]:
        value = c_uint32(result).value
        return value if value != 0 else 0
    elif "V128to64" in op[4:]:
        value = c_ushort(result).value
        if ((value >> 0) & 0xFF) == 0:
            return 0
        else:
            return getLow64BitValue(result)
    elif "V128HIto64" in op[4:]:
        value = c_ushort(result).value
        if ((value >> 8) & 0xFF) == 0:
            return 0
        else:
            return getHigh64BitValue(result) & 0xFFFFFFFFFFFFFFFF
    elif "64UtoV128" in op[4:]:
        value = c_ulonglong(int(result)).value
        return value if value != 0 else 0
    elif "V256to64_0" in op[4:] or "V256to64_1" in op[4:] or "V256to64_2" in op[4:] or "V256to64_3" in op[4:]:
        value = c_uint32(result).value
        if value == 0x00000000:
            return 0
        else:
            raise BaseException("V256to64_0")
    elif "ZeroHI64ofV128" in op[4:]:
        value = c_ushort(result).value
        if value == 0x0000:
            return 0x0000
        else:
            raise BaseException("ZeroHI64ofV128")
    elif "F32toF64" in op[4:]:
        return result
    elif "I32StoF64" in op[4:]:
        return float(result)
    elif "NegF64" in op[4:]:
        return -result
    elif "AbsF64" in op[4:]:
        return math.fabs(result)
    elif "ReinterpF64asI64" in op[4:]:
        return int(result)
    elif "ReinterpI64asF64" in op[4:]:
        return float(result)
    else:
        raise BaseException("other unopExpr", op[4:])

def fold_Clz32(value):
    i = 0
    while i < 32:
        shift = ctypes.c_uint32(1).value << (31 - i)
        result = value & shift
        if result != 0:
            return i
        i += 1
    return 0  # Normally, returning 0 shouldn't occur.

def fold_Clz64(value):
    i = 0
    while i < 64:
        shift = ctypes.c_ulonglong(1).value << (63 - i)
        result = value & shift
        if result != 0:
            return i
        i += 1
    return 0  # Normally, returning 0 shouldn't occur.

def isPointer(value):
    global currentStartAddr
    if IsConstDataAddr(value):
        return True
    else:
        if segment.codeSegment[0] <= value < segment.codeSegment[1]:
            return True
    return False

def processLoadExpr(expr):
    global currentStartAddr
    global signatureLength
    mem = 0
    if isinstance(expr, pyvex.IRExpr.RdTmp):
        mem = temporarySpace[int(expr.tmp)]  # The address from which the value is read.
    elif isinstance(expr, pyvex.IRExpr.Const):
        mem = readValueFromConst(expr)  # The address from which the value is read.
    if mem in memorySpace:
        if mem > stackStartList[-1]:
            signatureLength += 1
            if isPointer(memorySpace[mem]):
                writeIO("I", "pointer")
            else:
                writeIO("I", memorySpace[mem])
        return memorySpace[mem]
    elif mem in constsSpace:
        signatureLength += 1
        if isPointer(constsSpace[mem]):
            writeIO("I", "pointer")
        else:
            writeIO("I", constsSpace[mem])
        return constsSpace[mem]
    else:  # Reading an unknown address value.
        memorySpace[mem] = 0
        return 0

def initFPU(tagname, row, column):
    registerNo = []
    for i in range(row):
        tempList = []
        for j in range(column):
            tempList.append(0)  # 0 means the register hasn't been used yet.
        registerNo.append(tempList)
    return registerNo

def processGetIExpr(descr, ix, bias):
    index = str(descr).find(":")
    fpuTagReg = -1
    if index != -1:
        fpuTagReg = int(str(descr)[:index])
    else:
        print("Error in GetIExpr")
    tagname = registerOffset.x86Offset[fpuTagReg]
    if fpuTagReg == 136:
        if tagname not in globalSpace:
            fpuTag = initFPU(tagname, 8, 8)  # 8,8 indicates a 2D array of 8x8.
            globalSpace[tagname] = fpuTag
        row = temporarySpace[int(ix.tmp)] + bias
        column = 0
        if row > 7:  # Same situation as below.
            row = 7
        return globalSpace[tagname][row][column]
    elif fpuTagReg == 72:
        offset = getValue(ix) + bias
        index = int(descr.base) + offset * 8
        if index not in globalSpace:
            globalSpace[index] = 1  # After a certain number of function simulations, an unknown floating-point register is used.
            if 'fpu_tags' not in globalSpace:
                fpuTag = initFPU('fpu_tags', 8, 8)  # 8,8 indicates a 2D array of 8x8.
                globalSpace['fpu_tags'] = fpuTag
            if offset > 7:  # This ensures that when an exception occurs, the program does not crash.
                offset = 7
            globalSpace['fpu_tags'][offset][0] = 1
            return globalSpace[index]
        else:
            return globalSpace[index]
    else:
        print("Error in processGetIExpr")

def getValue(data):
    if isinstance(data, pyvex.expr.RdTmp):
        return readValueFromTmp(data)
    elif isinstance(data, pyvex.expr.Const):
        return readValueFromConst(data)

def processITEExpr(cond, iftrue, iffalse):
    condition = getValue(cond)
    if condition:
        return getValue(iftrue)
    else:
        return getValue(iffalse)

def getLow8BitValue(value):
    if isinstance(value, str):  # If it's a string, return the ASCII value of the first character.
        return ord(value[0])
    else:
        return value & 255

def getLow16BitValue(value):
    return value & 65535

def getLeft8BitValue(value):
    return value >> 8

def getHigh64BitValue(value):
    return (value >> 64) & 0xFFFFFFFFFFFFFFFF

def getLow64BitValue(value):
    return value & 0xFFFFFFFFFFFFFFFF

def getNewRegister(register):
    if register in ["ah", "eax"]:
        return "eax"
    elif register in ["dh", "edx"]:
        return "edx"
    elif register in ["ch", "ecx"]:
        return "ecx"

def updateRegisterArgsState(offset):
    global currentStartAddr
    global registerArgsState
    if 8 <= offset < 24:
        if offset in registerOffset.x86Offset.keys():
            register = registerOffset.x86Offset[int(offset)]
            register = getNewRegister(register)
            argsList = registerArgsState[currentStartAddr]
            if register in argsList:  # This means the argument register has been modified.
                registerArgsState[currentStartAddr].remove(register)
        else:
            raise BaseException("Error in writeIOWhenRegisterArg")

def writeIOWhenRegisterArg(offset):
    global currentStartAddr
    global registerArgsState
    if 8 <= offset < 24:
        if offset in registerOffset.x86Offset.keys():
            register = registerOffset.x86Offset[int(offset)]
            register = getNewRegister(register)
            argsList = registerArgsState[currentStartAddr]
            if register in argsList:  # This means this is an argument.
                writeIO("I", globalSpace[register])
        else:
            raise BaseException("Error in writeIOWhenRegisterArg")

def processWrTmp(stmt):
    for expr in stmt.expressions:
        if isinstance(expr, pyvex.IRExpr.Get):
            offset = expr.offset
            ty = expr.type
            writeIOWhenRegisterArg(offset)
            number = int(expr.offset)
            if number not in registerOffset.x86Offset.keys():
                if number == 184:  # High 64 bits
                    if "xmm1" in globalSpace.keys():
                        value = getHigh64BitValue(globalSpace["xmm1"])
                        temporarySpace[int(stmt.tmp)] = value
                    else:
                        temporarySpace[int(stmt.tmp)] = 0
                    return 

            if registerOffset.x86Offset[int(expr.offset)] == "esp":
                global stackEnd
                stackEnd = globalSpace[registerOffset.x86Offset[int(expr.offset)]]
            elif registerOffset.x86Offset[int(expr.offset)] == "ebp":
                global stackStart
                stackStart = globalSpace[registerOffset.x86Offset[int(expr.offset)]]
            if registerOffset.x86Offset[int(expr.offset)] in globalSpace.keys():
                value = globalSpace[registerOffset.x86Offset[int(expr.offset)]]
                if "I8" in str(stmt.data)[4:]:
                    result = getLow8BitValue(value)
                    temporarySpace[int(stmt.tmp)] = result
                elif "I16" in str(stmt.data)[4:]:
                    result = getLow16BitValue(value)
                    temporarySpace[int(stmt.tmp)] = result
                else:
                    temporarySpace[int(stmt.tmp)] = globalSpace[registerOffset.x86Offset[int(expr.offset)]]
                return
            elif registerOffset.x86Offset[int(expr.offset)] == "ah":
                if "ah" not in globalSpace.keys():
                    if "eax" in globalSpace.keys():
                        eax_tmp = globalSpace["eax"]
                        ax = getLow16BitValue(eax_tmp)
                        ah = getLeft8BitValue(ax)
                        temporarySpace[int(stmt.tmp)] = ah
                return
            elif registerOffset.x86Offset[int(expr.offset)] == "bh":
                if "bh" not in globalSpace.keys():
                    if "ebx" in globalSpace.keys():
                        ebx_tmp = globalSpace["ebx"]
                        bx = getLow16BitValue(ebx_tmp)
                        bh = getLeft8BitValue(bx)
                        temporarySpace[int(stmt.tmp)] = bh
                return
            elif registerOffset.x86Offset[int(expr.offset)] == "dh":
                if "dh" not in globalSpace.keys():
                    if "edx" in globalSpace.keys():
                        edx_tmp = globalSpace["edx"]
                        dx = getLow16BitValue(edx_tmp)
                        dh = getLeft8BitValue(dx)
                        temporarySpace[int(stmt.tmp)] = dh
                return
            elif registerOffset.x86Offset[int(expr.offset)] == "ch":
                if "ch" not in globalSpace.keys():
                    if "ecx" in globalSpace.keys():
                        ecx_tmp = globalSpace["ecx"]
                        cx = getLow16BitValue(ecx_tmp)
                        ch = getLeft8BitValue(cx)
                        temporarySpace[int(stmt.tmp)] = ch
                return
            elif registerOffset.x86Offset[int(expr.offset)] == "ftop":
                globalSpace["ftop"] = 7
                temporarySpace[int(stmt.tmp)] = globalSpace["ftop"]
                return
            elif registerOffset.x86Offset[int(expr.offset)] == "gs":
                globalSpace["gs"] = 0
                temporarySpace[int(stmt.tmp)] = globalSpace["gs"]
                return
            elif registerOffset.x86Offset[int(expr.offset)] == "ldt":
                globalSpace["ldt"] = 0
                temporarySpace[int(stmt.tmp)] = globalSpace["ldt"]
                return
            elif registerOffset.x86Offset[int(expr.offset)] == "gdt":
                globalSpace["gdt"] = 0
                temporarySpace[int(stmt.tmp)] = globalSpace["gdt"]
                return
            elif registerOffset.x86Offset[int(expr.offset)] == "fpround":
                globalSpace["fpround"] = 0
                temporarySpace[int(stmt.tmp)] = globalSpace["fpround"]
                return
            if registerOffset.x86Offset[int(expr.offset)] not in globalSpace.keys():
                if registerOffset.x86Offset[int(expr.offset)] == "eax":
                    globalSpace["eax"] = 1
                    temporarySpace[int(stmt.tmp)] = globalSpace["eax"]
                    return
                elif registerOffset.x86Offset[int(expr.offset)] == "d":
                    globalSpace["d"] = 1
                    temporarySpace[int(stmt.tmp)] = globalSpace["d"]
                    return
                else:
                    globalSpace[registerOffset.x86Offset[int(expr.offset)]] = 0
                    temporarySpace[int(stmt.tmp)] = 0
                    return
        elif isinstance(expr, pyvex.IRExpr.GetI):
            status = processGetIExpr(expr.descr, expr.ix, expr.bias)
            temporarySpace[int(stmt.tmp)] = status
            return
        elif isinstance(expr, pyvex.IRExpr.Binop):
            result = processBinOp(expr.op, expr.args)
            temporarySpace[int(stmt.tmp)] = result
            return
        elif isinstance(expr, pyvex.IRExpr.Unop):
            result = processUnopExpr(expr.op, expr.args)
            temporarySpace[int(stmt.tmp)] = result
            return
        elif isinstance(expr, pyvex.IRExpr.Load):
            content = processLoadExpr(expr.addr)
            if isinstance(content, str):  # It is possible that the loaded value is a string.
                content = ord(content[0])
            if expr.ty == "Ity_F64":
                temporarySpace[int(stmt.tmp)] = float(content)
            elif expr.ty == "Ity_F32":
                temporarySpace[int(stmt.tmp)] = float(content)
            elif expr.ty == "Ity_I8":
                result = getLow8BitValue(content)
                temporarySpace[int(stmt.tmp)] = result
            elif expr.ty == "Ity_I16":
                result = getLow16BitValue(content)
                temporarySpace[int(stmt.tmp)] = result
            elif expr.ty == "Ity_I32":
                temporarySpace[int(stmt.tmp)] = int(content)
            elif expr.ty == "Ity_I64":
                temporarySpace[int(stmt.tmp)] = int(content)
            else:
                temporarySpace[int(stmt.tmp)] = content
            return
        elif isinstance(expr, pyvex.IRExpr.RdTmp):
            temporarySpace[int(stmt.tmp)] = temporarySpace[int(expr.tmp)]
        elif isinstance(expr, pyvex.IRExpr.Const):
            con = expr.con
            if str(con) == "nan":
                x = float('nan')
                temporarySpace[int(stmt.tmp)] = x
            else:
                temporarySpace[int(stmt.tmp)] = con.value
        elif isinstance(expr, pyvex.IRExpr.ITE):
            result = processITEExpr(expr.cond, expr.iftrue, expr.iffalse)
            temporarySpace[int(stmt.tmp)] = result
            return
        elif isinstance(expr, pyvex.IRExpr.Triop):
            result = processTriOp(expr.op, expr.args)
            temporarySpace[int(stmt.tmp)] = result
            return
        elif isinstance(expr, pyvex.IRExpr.Qop):
            result = processQop(expr.op, expr.args)
            temporarySpace[int(stmt.tmp)] = result
            return
        elif isinstance(expr, pyvex.IRExpr.CCall):
            result = processCCall(expr.retty, expr.cee, expr.args)
            temporarySpace[int(stmt.tmp)] = result
            return
        else:
            print("other:")
            print(type(expr), expr.pp())

def processPut(stmt):
    for expr in stmt.expressions:
        offset = int(stmt.offset)
        updateRegisterArgsState(offset)
        if isinstance(expr, pyvex.expr.RdTmp):
            value = temporarySpace[int(stmt.data.tmp)]
            if isinstance(value, str):  # If it's a string, convert only the first character.
                value = ord(value[0])
            if offset in registerOffset.x86Offset.keys():
                globalSpace[registerOffset.x86Offset[int(stmt.offset)]] = value
            else:
                globalSpace[offset] = value  # Offset could be the high 64 bits of xmm0, not yet assigned to specific xmm.
        elif isinstance(expr, pyvex.expr.Const):
            if offset in registerOffset.x86Offset.keys():
                globalSpace[registerOffset.x86Offset[int(stmt.offset)]] = int(str(expr.con), 16)  # The stored value is str, not sure if it should be an integer, not used yet.
            else:
                globalSpace[offset] = int(str(expr.con), 16)  # Offset could be the high 64 bits of xmm0, not yet assigned to specific xmm, e.g., instruction at 804BEA9 in accept_connection.
    if offset in registerOffset.x86Offset.keys():
        if registerOffset.x86Offset[int(stmt.offset)] == "ebp":
            global ebp, stackStart
            ebp = globalSpace[registerOffset.x86Offset[int(stmt.offset)]]
            stackStart = globalSpace[registerOffset.x86Offset[int(stmt.offset)]]
        elif registerOffset.x86Offset[int(stmt.offset)] == "esp":
            global esp, stackEnd
            esp = globalSpace[registerOffset.x86Offset[int(stmt.offset)]]
            stackEnd = globalSpace[registerOffset.x86Offset[int(stmt.offset)]]
    else:
        pass

def readValueFromTmp(data):
    if int(data.tmp) in temporarySpace.keys():
        return temporarySpace[int(data.tmp)]
    else:
        return -1

def readValueFromConst(data):
    return int(str(data), 16)

def processPutIStmt(stmt):
    offset = getValue(stmt.ix) + stmt.bias
    if int(stmt.descr.base) == 72:
        index = int(stmt.descr.base) + offset * 8
        source = getValue(stmt.data)
        globalSpace[index] = source
    elif int(stmt.descr.base) == 136:
        tagname = registerOffset.x86Offset[136]
        if tagname not in globalSpace.keys():
            fpuTag = initFPU(tagname, 8, 8)  # 8, 8 represents a 2D array of 8x8
            globalSpace[tagname] = fpuTag
        else:
            pass
        result = getValue(stmt.data)
        if offset > 7:  # Same case as in GetI
            offset = 7
        globalSpace[registerOffset.x86Offset[136]][offset][0] = result
    return

def IsConstDataAddr(addr):
    if segment.rodataSegment[0] <= addr < segment.rodataSegment[1]:
        return True
    elif segment.dataSegment[0] <= addr < segment.dataSegment[1]:
        return True
    elif segment.bssSegment[0] <= addr < segment.bssSegment[1]:
        return True
    else:
        return False

def processStore(stmt):
    global currentStartAddr
    global signatureLength
    global constsSpace
    value = 0
    if isinstance(stmt.data, pyvex.expr.RdTmp):
        value = readValueFromTmp(stmt.data)
    elif isinstance(stmt.data, pyvex.expr.Const):
        value = readValueFromConst(stmt.data)
    if IsConstDataAddr(value):  # Handle special case for mov [esp], offset ABC where the offset is treated differently.
        signatureLength += 1
        if value in constsSpace.keys():
            if isinstance(constsSpace[value], str):
                writeIO("I", constsSpace[value].strip())
            else:
                writeIO("I", constsSpace[value])
        else:
            writeIO("I", 0)
    addr = getValue(stmt.addr)
    if IsConstDataAddr(addr):  # If it's a constant address, store in both constant space and regular address space.
        constsSpace[addr] = value
        memorySpace[addr] = value
    else:
        if addr > stackStartList[-1] and currentInstr not in pushAndCallList:
            signatureLength += 1
            if isPointer(value):
                writeIO("O", "pointer")
            else:
                writeIO("O", value)
        memorySpace[addr] = value  # If it's a regular address, store in regular address space.

def setPriorLoopFlag(addr, condition):
    global priorLoopFlag
    priorLoopFlag[addr] = condition

def removeLoopFlag(addr):
    global priorLoopFlag
    global blockLoopOrRecursion
    if addr in priorLoopFlag.keys():
        priorLoopFlag.pop(addr)
    if addr in blockLoopOrRecursion.keys():
        blockLoopOrRecursion.pop(addr)

def processExitStmt(stmt):
    condition = temporarySpace[int(stmt.guard.tmp)]
    global currentEmulatedBlock
    global currentNextIP  # Represents the address for false
    global currentInstr
    loopFlag = 0  # 0 means not a loop
    trueAddr = int(str(stmt.dst), 16)  # Represents the address for true
    global priorLoopFlag
    
    # Check if it's a loop
    if currentNextIP > trueAddr:
        if currentNextIP > currentEmulatedBlock and trueAddr <= currentEmulatedBlock:
            # Handle loop, but rep instruction's repetition is not handled here.
            loopFlag = 1  # Indicates a loop
    else:
        if currentNextIP <= currentEmulatedBlock and trueAddr > currentEmulatedBlock:
            loopFlag = 1
    if currentNextIP > currentEmulatedBlock and trueAddr > currentEmulatedBlock:
        # Rare case, e.g., in openssl's gnames_stack_print function
        loopFlag = 1
    if currentNextIP == trueAddr:
        # Solve the case where rep instruction's IR representation has an if-statement in the middle.
        loopFlag = 0
    if currentInstr == trueAddr:
        # In openssl-gcc-O3's aesni_xts_encrypt function, basic block IR has an if-statement.
        loopFlag = 0
    
    if loopFlag == 1:  # Handle loop
        incCountOfBlock(currentEmulatedBlock)
        if reachMaxCountOfBlock(currentEmulatedBlock):  # If max limit is reached
            if condition == priorLoopFlag[currentEmulatedBlock]:
                condition = not condition
            removeLoopFlag(currentEmulatedBlock)  # Handle forced loop exit, may have nested loops
        else:
            setPriorLoopFlag(currentEmulatedBlock, condition)

    # Handle loop exit
    if condition:
        globalSpace[registerOffset.x86Offset[int(stmt.offsIP)]] = int(str(stmt.dst), 16)
    else:
        globalSpace[registerOffset.x86Offset[int(stmt.offsIP)]] = 0  # May need to change to retain eip value
    return stmt.jk, condition

def setReturnAddr(value):
    if isinstance(value, pyvex.expr.RdTmp):
        globalSpace[registerOffset.x86Offset[68]] = readValueFromTmp(value)
    if isinstance(value, pyvex.expr.Const):
        globalSpace[registerOffset.x86Offset[68]] = readValueFromConst(value)

def processCAS(stmt):
    print('addr', 'dataLo', 'dataHi', 'expdLo', 'expdHi', 'oldLo', 'oldHi', 'end')
    print(stmt.addr, stmt.dataLo, stmt.dataHi, stmt.expdLo, stmt.expdHi, stmt.oldLo, stmt.oldHi, stmt.end)
    if stmt.end == "Iend_LE":
        if stmt.dataHi is None and stmt.expdHi is None:
            value_addr = getValue(stmt.addr)
            value_exped_lo = getValue(stmt.expdLo)
            temporarySpace[int(stmt.oldLo)] = value_addr
            if value_addr == value_exped_lo:
                temporarySpace[int(stmt.addr.tmp)] = getValue(stmt.dataLo)  # New value in data goes to addr

def processDirty(tmpVariable, func, args, storeAddr):  # Converts 64-bit float to 80-bit float, "le" means little-endian
    print(type(func))
    storeAddr = getValue(storeAddr)
    if func.name == "x86g_dirtyhelper_storeF80le":
        valueArg = args[1]
        value = getValue(valueArg)
        memorySpace[storeAddr] = value
    elif func.name == "x86g_dirtyhelper_loadF80le":
        temporarySpace[int(tmpVariable)] = memorySpace[storeAddr]

def emulateIR(irStmts):
    temporarySpace.clear()
    global switchFlag
    global currentInstr
    switchFlag = False
    type_ = ""
    for item in irStmts:
        if isinstance(item, pyvex.IRStmt.IMark):
            currentInstr = item.addr
            if item.addr in switchJump.keys():
                switchFlag = True
            continue
        elif isinstance(item, pyvex.IRStmt.NoOp):
            raise BaseException("NoOp operation")
        elif isinstance(item, pyvex.IRStmt.AbiHint):
            raise BaseException("AbiHint operation")
        elif isinstance(item, pyvex.IRStmt.Put):
            processPut(item)
        elif isinstance(item, pyvex.IRStmt.PutI):
            processPutIStmt(item)
        elif isinstance(item, pyvex.IRStmt.WrTmp):  # t0 = GET:I32 etc.
            processWrTmp(item)
        elif isinstance(item, pyvex.IRStmt.Store):
            processStore(item)
        elif isinstance(item, pyvex.IRStmt.CAS):
            processCAS(item)
        elif isinstance(item, pyvex.IRStmt.LLSC):
            raise BaseException("LLSC operation")
        elif isinstance(item, pyvex.IRStmt.MBE):
            raise BaseException("MBE operation")
        elif isinstance(item, pyvex.IRStmt.Dirty):
            processDirty(item.tmp, item.cee, item.args, item.mAddr)
        elif isinstance(item, pyvex.IRStmt.Exit):
            type_, condition = processExitStmt(item)
            if "MapFail" in type_[4:]:  # Ijk_MapFail may appear in the middle of IR
                continue
            elif "SigSEGV" in type_[4:]:
                continue  # Represents an invalid address trying to write to a read-only mapped area
            if condition:  # Exit block emulation when the condition becomes true
                return type_
        elif isinstance(item, pyvex.IRStmt.LoadG):
            raise BaseException("LoadG operation")
        elif isinstance(item, pyvex.IRStmt.StoreG):
            raise BaseException("StoreG operation")
        else:
            pass  
    return type_

def initArgs(regArgs, stackArgs, randomValueList, startAddr):
    global ebpBased
    global argsDistributionIndex
    global randomValueList_same
    argsDistributionIndex = argsDistributionIndex % 10
    i = argsDistributionIndex * 15
    tempRegArgs = copy.deepcopy(regArgs)
    for arg in tempRegArgs:
        globalSpace[arg] = randomValueList[i]
        i += 1
    tempStackArgs = sorted(copy.deepcopy(stackArgs))
    if ebpBased[startAddr]:  # If function is ebp-based, adjust the address offset due to saved registers
        newEBP = esp - 4        
        for arg in tempStackArgs:
            mem = arg + newEBP
            memorySpace[mem] = randomValueList[i]
            i += 1 
            if i >= 200:
                raise BaseException("Too many arguments!!!")
    else:
        newEBP = esp     
        for arg in tempStackArgs:
            mem = arg + newEBP
            memorySpace[mem] = randomValueList[i]
            i += 1 
            if i >= 200:
                raise BaseException("Too many arguments!!!")

def setVirtualReturnAddress():
    memorySpace.clear()
    memorySpace[esp] = 0

def updateFPU(value):
    ftop = globalSpace["ftop"]
    ftop -= 1  # Set new stack top for storing the return value after the library call
    globalSpace["ftop"] = ftop
    globalSpace[registerOffset.x86Offset[136]][ftop][0] = 1
    index = 72 + ftop * 8
    globalSpace[index] = value 

def updateEAX(value):
    globalSpace["eax"] = value

def getString1(addr):
    exit_flag = False
    catString = ""
    sourceAddr = memorySpace[addr]
    while not exit_flag:        
        if sourceAddr not in memorySpace.keys():
            memorySpace[sourceAddr] = 0
        source = memorySpace[sourceAddr]
        hexString = hex(source)[2:]
        while len(hexString) < 8:  # Ensure hexString is 8 characters long
            hexString = '0' + hexString
        tmp = hexString[-2:]
        count = 1
        while tmp != "00":
            catString += chr(int(tmp, 16))
            hexString = hexString[:7 - 2 * count + 1]
            tmp = hexString[-2:]
            count += 1
            if count == 5:
                sourceAddr += 4
                break
        if count < 5:
            exit_flag = True
    return catString  # String ends when '00' is encountered

def processLibFunc(funcName):
    global esp
    sourceAddr = esp + 4  # Get library function's parameter
    if funcName == ".exit":
        return "exit"
    
    if funcName in libFuncs.libFuncsList:
        if funcName == ".sqrt":
            source = memorySpace[sourceAddr]
            result = libFuncs.lib_sqrt(source)
            updateFPU(result)
        elif funcName == ".abs":
            source = memorySpace[sourceAddr]
            result = libFuncs.lib_abs(source)
            updateEAX(result)
        elif funcName == ".rand":
            result = libFuncs.lib_rand()
            updateEAX(result)
        elif funcName == ".cabs":
            pass
        elif funcName == ".fabs":
            source = memorySpace[sourceAddr]
            result = libFuncs.lib_fabs(source)
            updateFPU(result)
        elif funcName == ".labs":
            source = memorySpace[sourceAddr]
            result = libFuncs.lib_labs(source)
            updateEAX(result)  # Long integer return might not always be in eax
        elif funcName == ".exp":
            source = memorySpace[sourceAddr]
            result = libFuncs.lib_exp(source)
            updateFPU(result)
        elif funcName == ".frexp":
            source = memorySpace[sourceAddr]
            result1, result2 = libFuncs.lib_frexp(source, 0)  # Special handling, needs verification
            updateFPU(result1)
            source2 = memorySpace[sourceAddr + 8]
            memorySpace[source2] = result2
        elif funcName == ".ldexp":
            source = memorySpace[sourceAddr]  # Special handling, needs verification
            source2 = memorySpace[sourceAddr + 8]
            result = libFuncs.lib_ldexp(source, source2)
            updateFPU(result)
        elif funcName == ".log":
            source = memorySpace[sourceAddr]
            result = libFuncs.lib_log(source)
            updateFPU(result)
        elif funcName == ".log10":
            source = memorySpace[sourceAddr]
            result = libFuncs.lib_log10(source)
            updateFPU(result)
        elif funcName == ".pow":  # Special handling, needs verification
            source = memorySpace[sourceAddr]
            source2 = memorySpace[sourceAddr + 8]
            result = libFuncs.lib_pow(source, source2)
            updateFPU(result)
        elif funcName == ".pow10":
            source = memorySpace[sourceAddr]
            result = libFuncs.lib_pow10(source)
            updateFPU(result)
        elif funcName == ".acos":
            source = memorySpace[sourceAddr]
            result = libFuncs.lib_acos(source)
            updateFPU(result)
        elif funcName == ".asin":
            source = memorySpace[sourceAddr]
            result = libFuncs.lib_asin(source)
            updateFPU(result)
        elif funcName == ".atan":
            source = memorySpace[sourceAddr]
            result = libFuncs.lib_atan(source)
            updateFPU(result)
        elif funcName == ".atan2":
            source = memorySpace[sourceAddr]
            result = libFuncs.lib_atan2(source)
            updateFPU(result)
        elif funcName == ".cos":
            source = memorySpace[sourceAddr]
            result = libFuncs.lib_cos(source)
            updateFPU(result)
        elif funcName == ".sin":
            source = memorySpace[sourceAddr]
            result = libFuncs.lib_sin(source)
            updateFPU(result)
        elif funcName == ".tan":
            source = memorySpace[sourceAddr]
            result = libFuncs.lib_tan(source)
            updateFPU(result)
        elif funcName == ".cosh":
            source = memorySpace[sourceAddr]
            result = libFuncs.lib_cosh(source)
            updateFPU(result)
        elif funcName == ".sinh":
            source = memorySpace[sourceAddr]
            result = libFuncs.lib_sinh(source)
            updateFPU(result)
        elif funcName == ".tanh":
            source = memorySpace[sourceAddr]
            result = libFuncs.lib_tanh(source)
            updateFPU(result)
        elif funcName == ".hypot":
            source = memorySpace[sourceAddr]
            source2 = memorySpace[sourceAddr + 8]
            result = libFuncs.lib_hypot(source, source2)
            updateFPU(result)
        elif funcName == ".ceil":
            source = memorySpace[sourceAddr]
            result = libFuncs.lib_ceil(source)
            updateFPU(result)
        elif funcName == ".floor":
            source = memorySpace[sourceAddr]
            result = libFuncs.lib_floor(source)
            updateFPU(result)
        elif funcName == ".fmod":
            source = memorySpace[sourceAddr]
            source2 = memorySpace[sourceAddr + 8]
            result = libFuncs.lib_fmod(source, source2)
            updateFPU(result)
        elif funcName == ".modf":  # Special handling, needs verification
            source = memorySpace[sourceAddr]
            result1, result2 = libFuncs.lib_modf(source, 0)
            updateFPU(result1)
            source2 = memorySpace[sourceAddr + 8]
            memorySpace[source2] = result2
        elif funcName == ".strcmp":  # Two arguments are pointers, referenced twice
            str1 = getString1(sourceAddr)
            str2 = getString1(sourceAddr + 4)
            result = (str1 > str2) - (str1 < str2)  # Python 3에서 cmp() 제거되어 대체함
            globalSpace['eax'] = result
    else:
        print("other case in processLibFunc", funcName)

def reachMaxCountOfBlock(addr):
    global maxLoopOrRecursion
    if blockLoopOrRecursion[addr] < maxLoopOrRecursion:
        return False
    else:
        return True

def incCountOfBlock(addr):
    if addr not in blockLoopOrRecursion.keys():
        blockLoopOrRecursion[addr] = 1
    else:
        blockLoopOrRecursion[addr] += 1

def reachMaxCountOfFunction(addr):
    global maxLoopOrRecursion
    if addr not in funcLoopOrRecursion.keys():
        funcLoopOrRecursion[addr] = 1
    else:
        funcLoopOrRecursion[addr] += 1
    if funcLoopOrRecursion[addr] <= maxLoopOrRecursion:
        return False
    else:
        return True

def isUserFunc(addr):
    return addr in allUserFuncs

def emulateFunctionAgain(db, startAddr, item):
    global stackStartList
    stackStartList = []
    name = item["name"]
    stackArgs = item["stackArgs"]  # list
    registerArgs = item["registerArgs"]  # list
    initEbpAndEsp()
    setVirtualReturnAddress()
    globalSpace.clear()  # This line was swapped with the next one
    randomValueCondition = {}
    randomValueCondition["name"] = name
    randomValueList = randomInput.getEmulationArgs()
    initArgs(registerArgs, stackArgs, randomValueList, startAddr)
    funcLoopOrRecursion.clear()
    blockLoopOrRecursion.clear()
    consts = database.findAllConsts(db)
    loadConsttoMemory(consts)
    emulateFunction(db, startAddr)

def initialRegisterArgsState(startAddr):
    global functionArgs
    global registerArgsState  # Track the usage state of the register arguments of the current function
    if startAddr in functionArgs.keys():
        registerArgsState[startAddr] = functionArgs[startAddr][0]  # The dict value is a list, and the first element is the register arguments list, which could be an empty list

def emulateFunction(db, startAddr):
    global esp
    global ebp
    global switchFlag
    global currentInstr
    global currentState
    global nextStartAddr  # Function start address to call
    global currentStartAddr
    global functionInfo
    global signatureLength
    initialRegisterArgsState(startAddr)
    nextStartAddr = startAddr
    stackStartList.append(esp)
    
    if isUserFunc(startAddr) and reachMaxCountOfFunction(startAddr):  # Recursive check, currently simple count, can be improved with depth tracking
        addrAfterCall = memorySpace[esp]  # Get the address of the next instruction to execute
        esp += 4  # Clear the pushed address for the next statement execution
        globalSpace[registerOffset.x86Offset[24]] = esp
        globalSpace[registerOffset.x86Offset[68]] = addrAfterCall
        return "self-define return"
    
    globalSpace["ebp"] = ebp
    globalSpace["esp"] = esp
    exit = False
    blockAddr = startAddr
    currentStartAddr = startAddr
    endAddr = 0
    
    while not exit:
        global currentEmulatedBlock
        currentEmulatedBlock = blockAddr
        findCondition = {"start": blockAddr}
        block = database.findOneBlock(db, findCondition)
        
        if block is None:
            libCondition = {"start": blockAddr}
            libFunction = database.findOneLib(db, libCondition)
            
            if libFunction is not None:
                signatureLength += 1
                fwrite.write("LC " + libFunction["name"] + "\n")
                exit = processLibFunc(libFunction["name"])
                
                if exit == "exit":
                    currentState = "exit"
                    return "library exit"
                return "library return"
            else:
                currentState = "Ijk_Ret"
                return "library return"
        
        endAddr = block["end"]
        binaryInstrs = eval(block["hexInstrs"])
        blockIR, jumpKind, nextIP = convertToIR.constructIR(binaryInstrs, blockAddr)
        global currentNextIP
        currentNextIP = getValue(nextIP)
        resultType = emulateIR(blockIR)
        
        if resultType == "Ijk_Boring":
            currentState = "Ijk_Boring"
            endAddr = int(block["end"])
            
            if globalSpace[registerOffset.x86Offset[68]] == 0:
                globalSpace[registerOffset.x86Offset[68]] = int(str(nextIP), 16)
            
            blockAddr = globalSpace[registerOffset.x86Offset[68]]
        
        else:
            currentState = jumpKind
            
            if jumpKind == "Ijk_Ret":
                exit = True
                setReturnAddr(nextIP)
                signatureLength += 1
                
                if "eax" in globalSpace:
                    if isPointer(globalSpace["eax"]):
                        writeIO("r", "pointer")
                    else:
                        writeIO("r", globalSpace["eax"])
                else:
                    writeIO("r", sys.maxsize)  # Handle possible lack of return value, assign max int as placeholder
                
                return "self-define return"
            
            elif jumpKind == "Ijk_Call":
                nextAddr = getValue(nextIP)
                returnType = emulateFunction(db, nextAddr)
                currentStartAddr = startAddr
                stackStartList.pop()
                
                if returnType == "library return":
                    esp += 4  # Clear the pushed address
                    global stackStart
                    stackStart = esp
                    globalSpace[registerOffset.x86Offset[24]] = esp
                    condition = {"startAddr": blockAddr}
                    cfgInfo = database.findOneCfg(db, condition)
                    
                    if cfgInfo["num"] != 0:
                        blockAddr = endAddr
                        if blockAddr >= functionInfo[startAddr]:
                            return
                    else:
                        return
                
                elif returnType == "library exit":
                    return
                else:
                    blockAddr = globalSpace[registerOffset.x86Offset[68]]
            
            elif jumpKind == "Ijk_Boring":
                if switchFlag:
                    globalSpace["eip"] = switchJump[currentInstr]
                    blockAddr = switchJump[currentInstr]
                    switchFlag = False
                else:
                    blockAddr = getValue(nextIP)
            
            elif jumpKind == "Ijk_NoDecode":
                blockAddr = int(endAddr)
                pass
            
            else:
                print("other in emulateFunction")
                
def loadConsttoMemory(consts):
    global constsSpace
    constsSpace.clear()
    for const in consts:
        addr = const["addr"]
        value = const["value"]
        constsSpace[addr] = value

def initEbpAndEsp():
    global esp
    global ebp
    ebp = 178956976
    esp = 178956970

def initSegment(db):
    condition = {}
    condition["name"] = "data"
    result = database.findOneSegment(db, condition)
    if result is None:
        segment.dataSegment.extend([-1, -1])
    else:
        segment.dataSegment.extend([result["start"], result["end"]])
    condition.clear()
    
    condition["name"] = "rodata"
    result = database.findOneSegment(db, condition)
    if result is None:
        segment.rodataSegment.extend([-1, -1])  # Program may not contain .rodata section
    else:
        segment.rodataSegment.extend([result["start"], result["end"]])
    condition.clear()
    
    condition["name"] = "bss"
    result = database.findOneSegment(db, condition)
    if result is None:
        segment.bssSegment.extend([-1, -1])
    else:
        segment.bssSegment.extend([result["start"], result["end"]])
    condition.clear()
    
    condition["name"] = "text"
    result = database.findOneSegment(db, condition)
    segment.codeSegment.extend([result["start"], result["end"]])

def initialUserFuncs(db):
    global functionInfo  # Start address as the key, end address as the value
    funcs = database.findAllFunctions(db)
    for item1 in funcs:
        addr = item1["start"]
        allUserFuncs.add(addr)
        endAddr = item1["end"]
        functionInfo[addr] = endAddr
    funcs.close()

def initialPushAndCall(db):
    global pushAndCallList
    tempLists = database.findAllPushAndCall(db)
    for item in tempLists:
        pushAndCallList = item["addrs"]

def loadSwitchJump(db):
    global switchJump
    switchs = database.findAllSwitchs(db)
    for switch in switchs:
        switchJump[switch["stmtAddr"]] = switch["firstTarget"]

def getPath():
    return os.path.dirname(os.path.realpath(__file__)).strip()

def createSignatureDirectory(currentPath, directoryName):
    sysstr = platform.system()
    directory = currentPath
    if sysstr == "Windows":
        directory = os.path.join(directory, directoryName)
    elif sysstr == "Linux":
        directory = os.path.join(directory, directoryName)
    else:
        directory = os.path.join(directory, directoryName)

    if os.path.exists(directory):
        shutil.rmtree(directory)
    os.mkdir(directory)
    return directory

def generateFilePath(currentPath, fileName):
    sysstr = platform.system()
    filePath = currentPath
    if sysstr == "Windows":
        filePath = os.path.join(filePath, fileName + ".txt")
    elif sysstr == "Linux":
        filePath = os.path.join(filePath, fileName + ".txt")
    else:
        filePath = os.path.join(filePath, fileName + ".txt")
    return filePath    

def initialEbpBased(funcs):
    for fun in funcs:        
        ebpBased[fun["start"]] = fun["ebpBased"]

def initialRegisterArgs(funcs):
    global functionArgs
    for func in funcs:
        tempList = []
        tempList.append(func["registerArgs"])  # First element in tempList is the list of register arguments
        tempList.append(func["stackArgs"])     # Second element in tempList is the list of stack arguments
        functionArgs[func["start"]] = tempList
        

def resetAllGlobalVariables():
    global currentEmulatedBlock, currentNextIP, maxLoopOrRecursion, funcLoopOrRecursion, blockLoopOrRecursion, priorLoopFlag, allUserFuncs
    global stackStart, stackStartList, stackEnd, stackArgs, registerArgs, temporarySpace, globalSpace, memorySpace, constsSpace, switchJump
    global ebpBased, switchFlag, currentInstr, currentState, nextStartAddr, currentStartAddr, ebp, esp, nan, emulateAll, emulateAddr, emulateFunctions
    global childPath, pushAndCallList, functionInfo, signatureLength, argsDistributionIndex, randomValueList_same, functionArgs, registerArgsState
    global isVulnerabilityProgram, programName, fileName, db, fwrite

    currentEmulatedBlock = 0
    currentNextIP = 0
    maxLoopOrRecursion = 5
    funcLoopOrRecursion = {}  # Recursion count
    blockLoopOrRecursion = {}  # Block loop count
    priorLoopFlag = {}
    allUserFuncs = set()
    stackStart = 0
    stackStartList = []
    stackEnd = 0
    stackArgs = []
    registerArgs = []
    temporarySpace = {}
    globalSpace = {}
    memorySpace = {}
    constsSpace = {}
    switchJump = {}
    ebpBased = {}
    switchFlag = False
    currentInstr = 0
    currentState = ""
    nextStartAddr = 0
    currentStartAddr = 0
    ebp = 178956976
    esp = 178956970
    nan = float('nan')
    emulateAll = False
    emulateAddr = 0
    emulateFunctions = set()
    childPath = "signature"
    pushAndCallList = []
    functionInfo = {}
    signatureLength = 0
    argsDistributionIndex = 0
    randomValueList_same = []
    functionArgs = {}
    registerArgsState = {}
    isVulnerabilityProgram = False
    programName = ""
    fileName = ""
    db = None
    fwrite = None

def emulateSpecifiedFunction(directory, proName, fiName, funcName, calledFrom=1):
    resetAllGlobalVariables()
    global programName, fileName, isVulnerabilityProgram
    programName = proName
    fileName = fiName
    global db, fwrite

    if calledFrom == 2:
        isVulnerabilityProgram = True
    db, client = database.connectDB(isVulnerabilityProgram, False, programName, fileName)
    functions = database.findAllFunctions(db)
    initialUserFuncs(db)
    initialPushAndCall(db)
    initialEbpBased(copy.deepcopy(functions))
    initialRegisterArgs(copy.deepcopy(functions))
    initSegment(db)
    loadSwitchJump(db)
    fwrite = None
    with open("function.txt", 'a') as fwrite1:
        starttime = datetime.datetime.now()
        fwrite1.write("start time:" + str(starttime) + "\n")
        functionCondition = {"name": funcName}
        item = database.findOneFunction(db, functionCondition)
        if item is None:
            with open("wrong_function_path.txt", 'a') as fwrite_wrongpath:
                fwrite_wrongpath.write(f"cannot find this function\tprogram name:{proName}\tfile name:{fiName}\tfunction name:{funcName}\n")
            return "wrong"
        
        try:
            global signatureLength, argsDistributionIndex, globalSpace, emulateFunctions
            signatureLength = 0
            argsDistributionIndex = 0
            startAddr = item["start"]
            name = item["name"]
            stackArgs = item["stackArgs"]
            registerArgs = item["registerArgs"]
            initEbpAndEsp()
            setVirtualReturnAddress()
            globalSpace.clear()
            randomValueList = randomInput.getEmulationArgs()
            initArgs(registerArgs, stackArgs, randomValueList, startAddr)
            funcLoopOrRecursion.clear()
            blockLoopOrRecursion.clear()
            consts = database.findAllConsts(db)
            loadConsttoMemory(consts)
            fileWritePosition = generateFilePath(directory, f"{programName}+{fileName}+{item['name']}")
            fwrite = open(fileWritePosition, 'w')
            emulateFunctions.add(startAddr)
            emulateFunction(db, startAddr)
            while signatureLength < 20:
                argsDistributionIndex += 1
                emulateFunctionAgain(db, startAddr, item)
        except BaseException as e:
            if startAddr in emulateFunctions:
                fwrite1.write(f"{item['name']}    fail {startAddr}\n")
                fwrite1.flush()
                print(f"Error: {str(e)}")
                if fwrite:
                    fwrite.flush()
                    fwrite.close()
        else:
            if startAddr in emulateFunctions:
                global currentState
                fwrite1.write(f"{item['name']}    success {currentState}\n")
                fwrite1.flush()
                if fwrite:
                    fwrite.flush()
                    fwrite.close()

    functions.close()
    print(">>>>> Emulation end! <<<<<")
    endtime = datetime.datetime.now()
    time_diff = (endtime - starttime).seconds
    with open("function.txt", 'a') as fwrite1:
        fwrite1.write(f"end time: {str(endtime)}\n")
        fwrite1.write(f"time diff: {str(time_diff)}\n")
    database.closeConnect(client)
    client = None
    
def parseArgs(args):
    global emulateAll, programName
    global emulateAddr, fileName
    global childPath, isVulnerabilityProgram

    argList = args[1:]
    presetArgs = ["--childPath", "--addr", "--type", "--path", "--file"]
    requiredArgs = ["--path", "--file"]
    acquiredArgs = []
    
    for arg in argList:
        tempList = arg.split('=')
        acquiredArgs.append(tempList[0])
    
    for arg in requiredArgs:
        if arg not in acquiredArgs:
            print("Please specify --path=programName and --file=fileName parameters")
            exit()
    
    for i in range(len(argList)):
        arg = argList[i]
        index = arg.find("=")
        if index == -1:
            print("Invalid argument. There must be no spaces around '='")
            exit()
        
        leftSide = arg[:index]
        rightSide = arg[index+1:]
        
        if leftSide not in presetArgs:
            print(f"Invalid argument [{i}]. Please re-specify with --all, --childPath")
            exit()

        if leftSide == "--childPath":
            childPath = rightSide
        elif leftSide == "--addr":
            emulateAddr = int(rightSide)
            emulateAll = False
        elif leftSide == "--type":
            if rightSide.lower() == "v":
                isVulnerabilityProgram = True
        elif leftSide == "--path":
            programName = rightSide
        elif leftSide == "--file":
            fileName = rightSide

if __name__ == '__main__':
    if len(sys.argv) < 4:
        print("Too few arguments. Please specify [--addr=13565443] --childPath=signature-gcc-O0")
        exit()
    else:
        parseArgs(sys.argv)
        global db, fwrite
        currentDirectory = getPath()
        directory = createSignatureDirectory(currentDirectory, childPath)
        db, client = database.connectDB(isVulnerabilityProgram, False, programName, fileName)
        functions = database.findAllFunctions(db)
        initialUserFuncs(db)
        initialPushAndCall(db)
        initialEbpBased(copy.deepcopy(functions))
        initialRegisterArgs(copy.deepcopy(functions))
        initSegment(db)
        loadSwitchJump(db)
        fwrite = None

        with open("function.txt", 'w') as fwrite1:
            starttime = datetime.datetime.now()
            fwrite1.write("start time: " + str(starttime) + "\n")
            for item in functions:
                try:
                    global signatureLength
                    global argsDistributionIndex
                    global globalSpace
                    global emulateFunctions
                    signatureLength = 0
                    argsDistributionIndex = 0
                    startAddr = item["start"]
                    name = item["name"]
                    stackArgs = item["stackArgs"]
                    registerArgs = item["registerArgs"]
                    initEbpAndEsp()
                    setVirtualReturnAddress()
                    globalSpace.clear()
                    randomValueList = randomInput.getEmulationArgs()
                    initArgs(registerArgs, stackArgs, randomValueList, startAddr)
                    funcLoopOrRecursion.clear()
                    blockLoopOrRecursion.clear()
                    consts = database.findAllConsts(db)
                    loadConsttoMemory(consts)
                    
                    if not emulateAll:
                        if startAddr == emulateAddr:
                            fileWritePosition = generateFilePath(directory, item["name"])
                            fwrite = open(fileWritePosition, 'w')
                            emulateFunctions.add(startAddr)
                            emulateFunction(db, startAddr)
                            while signatureLength < 20:
                                argsDistributionIndex += 1
                                emulateFunctionAgain(db, startAddr, item)
                    else:
                        fileWritePosition = generateFilePath(directory, item["name"])
                        fwrite = open(fileWritePosition, 'w')
                        emulateFunctions.add(startAddr)
                        emulateFunction(db, startAddr)
                        while signatureLength < 20:
                            argsDistributionIndex += 1
                            emulateFunctionAgain(db, startAddr, item)
                except BaseException as e:
                    if startAddr in emulateFunctions:
                        fwrite1.write(f"{item['name']}    fail {str(startAddr)}\n")
                        fwrite1.flush()
                        print(f"Error: {str(e)}")
                        fwrite.flush()
                        fwrite.close()
                else:
                    if startAddr in emulateFunctions:
                        global currentState
                        fwrite1.write(f"{item['name']}    success {currentState}\n")
                        fwrite1.flush()
                        fwrite.flush()
                        fwrite.close()

        functions.close()
        print(">>>>> Emulation end! <<<<<")
        endtime = datetime.datetime.now()
        timeDiff = (endtime - starttime).seconds
        with open("function.txt", 'w') as fwrite1:
            fwrite1.write("end time: " + str(endtime) + "\n")
            fwrite1.write("time diff: " + str(timeDiff) + "\n")

        database.closeConnect(client)
        client = None
