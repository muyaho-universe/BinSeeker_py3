# -*- coding: utf-8 -*-

from idaapi import *
from idc import *
from idautils import *
from collections import defaultdict
from itertools import zip_longest
import sys
import os
import globalVariable
import queue  # Python 3에서는 Queue가 queue로 변경됨
import chardet
import operator
import copy
import function
import convertToIR
import segment
import database
import libFuncs
import graph
import randomInput
import math
import example

f = 0
stackAddr = 0xaaaaab0
argRegisters = ["eax", "ecx", "edx"]
stackIdentifier = ["[esp", "[ebp"]
repAddr = []  # Separate storage for rep instruction addresses
functionSet = set()
functionEBPBased = {}
doubleOperandsInstrs = ["mov", "lea", "lds", "les", "movzx", "movsx"]
allFuncInstancesPath = {}
currentArgList = {}
currentArgList_stack = []
pushAndCallList = set()
is64bit_binary = False
isVulnerabilityProgram = False
programName = ""
fileName = ""


class Process_with_Single_Function(object):
    def __init__(self, func_t):
        self._num = 0
        self._Blocks = set()
        self._Blocks_list = []
        self._func = func_t
        self._block_boundary = {}
        self._offspringSet = {}  # the successors of a basic block
        self._offspring = {}
        self._mapping = {}  # key is the start address of a basic block, value is its id
        self._addr_func = func_t.start_ea  # first address of function, startEA에서 start_ea로 변경
        self._name_func = str(get_func_name(func_t.start_ea))  # GetFunctionName에서 get_func_name으로 변경
        self._ids = []
        self._endblocks = []
        self.allPaths = []
        self._init_all_nodes()

    # initial block_boundary, get every node's range of address
    def _init_all_nodes(self):
        flowchart = FlowChart(self._func)
        self._num = flowchart.size
        for i in range(flowchart.size):
            basicblock = flowchart[i]  # flowchart.__getitem__(i) 대신 flowchart[i] 사용
            self._Blocks.add(basicblock.start_ea)
            self._block_boundary[basicblock.start_ea] = basicblock.end_ea
            self._ids.append(basicblock.id)
            self._mapping[basicblock.start_ea] = basicblock.id
            suc = basicblock.succs()
            block_list = []
            for item in suc:
                block_list.append(item.start_ea)
            if len(block_list) == 0:
                self._endblocks.append(basicblock.start_ea)
            self._offspringSet[basicblock.start_ea] = block_list


class Switch(object):
    def __init__(self, ea):
        self._ea = ea
        results = self._calc_cases()
        self._map = self._build_map(results)
        self._reverse_map = self._build_reverse(self._map)

    def _build_reverse(self, switch_map):
        reverse_map = defaultdict(list)
        for case, target in switch_map.items():  # iteritems()는 items()로 대체됩니다
            reverse_map[target].append(case)
        return reverse_map

    def _calc_cases(self):
        si = idaapi.get_switch_info_ex(self._ea)
        results = idaapi.calc_switch_cases(self._ea, si)
        if not results:
            raise exceptions.SarkNotASwitch(
                "Seems like 0x{:08X} is not a switch jump instruction.".format(self._ea))

        return results

    def _build_map(self, results):
        switch_map = {}
        for cases, target in zip_longest(results.cases, results.targets):  # izip -> zip_longest
            for case in cases:
                switch_map[case] = target
        return switch_map

    @property
    def targets(self):
        """Switch Targets"""
        return list(self._map.values())

    @property
    def cases(self):
        """Switch Cases"""
        return list(self._map.keys())

    @property
    def pairs(self):
        """(case, target) pairs"""
        return iter(self._map.items())  # iteritems()는 items()로 대체됩니다

    def __iter__(self):
        """Iterate switch cases."""
        return iter(self._map.keys())  # iterkeys()는 keys()로 대체됩니다

    def __getitem__(self, case):
        """switch[case] -> target"""
        return self._map[case]

    def get_cases(self, target):
        """switch.get_cases(target) -> [case]"""
        if target in self.targets:
            return self._reverse_map[target]
        raise KeyError("Target 0x{:08X} does not exist.".format(target))


def is_switch(ea):
    try:
        switch = Switch(ea)
        return True
    except exceptions.SarkNotASwitch:
        return False


def identify_switch(startAddr, endAddr):
    casesList = []
    targetsList = []
    head_ea_List = []
    jumps_List = []
    jumpsEnd_List = []
    jumptable = dict()
    for head_ea in Heads(startAddr, endAddr):
        if idc.isCode(idc.get_full_flags(head_ea)):  # GetFlags -> get_full_flags
            switch_info = idaapi.get_switch_info_ex(head_ea)
            if switch_info and switch_info.jumps != 0:
                my_switch = Switch(head_ea)
                casesList.append(my_switch.cases)
                targetsList.append(my_switch.targets)
                head_ea_List.append(head_ea)
                jumps_List.append(switch_info.jumps)
                jumpsEnd_List.append(switch_info.jumps + switch_info.get_jtable_size() * switch_info.get_jtable_element_size())
    return head_ea_List, jumps_List, jumpsEnd_List, casesList, targetsList


def getABinaryInstr(startea, itemsize):  # \x88 스타일
    out = []
    strr = '0000000'
    for i in range(startea, itemsize + startea):
        strq = str(bin(get_original_byte(i)))[2:]  # GetOriginalByte -> get_original_byte
        n = len(strq)
        strq = strr[0:8 - n] + strq
        temp = hex(int(strq, 2))[1:]  # x8 또는 x88 스타일
        if len(temp) == 2:
            temp = temp[0] + '0' + temp[1]
        temp = "\\" + temp
        out.append(temp)
    return "".join(out)


def get_instruction(ea):
    return idc.GetDisasm(ea)


def getRepBinaryInstrInOneAddr(addr, size):
    result = getABinaryInstr(addr, size)
    return "'" + result + "'"


def getAllBinaryInstrInOneNode(func_t, startEA, endEA):
    it_code = func_item_iterator_t(func_t, startEA)
    ea = it_code.current()
    binaryInstrs = []
    while ea < endEA:
        instr = getABinaryInstr(ea, get_item_size(ea))  # ItemSize -> get_item_size
        binaryInstrs.append(instr)
        if not it_code.next_code():
            break
        ea = it_code.current()
    result = "'"
    for a in binaryInstrs:
        result = result + a
    result = result + "'"
    return result


def getAllAsmInstrInOneNode(func_t, startEA, endEA):
    instr_list = []
    it_code = func_item_iterator_t(func_t, startEA)
    ea = it_code.current()
    address = []
    while ea < endEA:
        instr = get_instruction(ea)
        instr_list.append(instr)
        address.append(ea)
        if not it_code.next_code():
            break
        ea = it_code.current()
    return instr_list, address


def getAllInstrAddrInOneFunction(func_t, startEA, endEA):
    it_code = func_item_iterator_t(func_t, startEA)
    ea = it_code.current()
    address = []
    while ea < endEA:
        address.append(ea)
        if not it_code.next_code():
            break
        ea = it_code.current()
    return address


def getAllBlocksInFunction(func_t):
    flowchart = FlowChart(func_t)
    allBlocks = {}
    startAddr = func_t.start_ea  # startEA -> start_ea
    endAddr = func_t.end_ea  # endEA -> end_ea
    for i in range(flowchart.size):
        basicBlock = flowchart[i]
        if startAddr <= basicBlock.start_ea < endAddr:
            allBlocks[basicBlock.start_ea] = basicBlock
    return allBlocks


def getNewCFGIncludeCall(cfg, allBlocks, func_t):
    global repAddr
    repAddr = []
    startEnd = {}
    for address in allBlocks.keys():
        blockStart = address
        blockEnd = allBlocks[address].end_ea
        addrs = getAllInstrAddrInOneFunction(func_t, blockStart, blockEnd)
        count = 0
        start = blockStart
        startEnd[start] = blockEnd
        numCount = 0
        for addr in addrs:
            numCount += 1
            if numCount == 99 or GetMnem(addr) in ["call", "movs", "scas", "stos", "rdrand", "cmps"]:
                if count < (len(addrs) - 1):
                    originalSuccessors = cfg[start]
                    cfg[start] = addrs[count + 1]
                    startEnd[start] = addrs[count + 1]
                    start = addrs[count + 1]
                    startEnd[start] = blockEnd
                    tempList = []
                    for i in originalSuccessors:
                        tempList.append(i)
                    cfg[addrs[count + 1]] = tempList
                if numCount == 99:
                    numCount = 0
            count += 1
        for addr in addrs:
            if GetMnem(addr) in ["movs", "scas", "stos", "rdrand", "cmps"]:
                repAddr.append(addr)
    return cfg, startEnd, repAddr


def getCFG_OF_Func(func_t):
    flowchart = FlowChart(func_t)
    cfg = {}
    for i in range(flowchart.size):
        basicBlock = flowchart[i]
        succs = [item.start_ea for item in basicBlock.succs()]
        cfg[basicBlock.start_ea] = succs
    return cfg


def depth_first_search(cfg, root=None):
    order = []
    visited = {}

    def dfs(node):
        visited[node] = True
        order.append(node)
        for n in cfg[node]:
            if n not in visited:
                dfs(n)

    if root:
        dfs(root)
    for node in cfg.keys():
        if node not in visited:
            dfs(node)
    return order


def isContainDot(value):
    return "." in value


def containSemicolonAndComma(value):
    return '; "' in value


def isString(value):
    return "\"" in value or "'" in value

def getOffsetWithEBP(content, size):
    # [ebp + arg_0]
    if "[ebp" in content:
        if size > 400000000:
            return 0
        else:
            return size
    else:
        return 0

def isDecimal(ch):
    return ('0' <= ch <= '9') or ('A' <= ch <= 'F')

def secondOrThird(value1, value2):
    string1 = value1.rstrip('h')
    string2 = value2.rstrip('h')

    flag1 = 1 if string1 else 0
    flag2 = 2 if string2 else 0

    for temp in list(string1):
        if not isDecimal(temp):
            flag1 = 0
            break

    for temp in list(string2):
        if not isDecimal(temp):
            flag2 = 0
            break

    if flag1 == 1 and flag2 == 2:
        return 3
    elif flag1 == 0 and flag2 == 2:
        return 2
    elif flag1 == 1 and flag2 == 0:
        return 1
    else:
        return 0

def computeValue(value1, value2, withh):
    valueDecimal = 0
    if withh == 1:
        value1 = value1.rstrip('h')
        valueDecimal = int(value1, 16)
    elif withh == 2:
        value2 = value2.rstrip('h')
        valueDecimal = int(value2, 16)
    elif withh == 3:
        value1 = value1.rstrip('h')
        valueDecimal = int(value1, 16)
        value2 = value2.rstrip('h')
        valueDecimal += int(value2, 16)
    return valueDecimal

def getOffsetWithoutEBP(content, size):
    # [esp+2Ch+s2]
    count = content.count("+")
    if "[esp" in content:
        if count == 0:
            return 0
        elif count == 1:
            return size
        elif count == 2:
            index1 = content.find("+")
            index2 = content.find("+", index1 + 1)
            value1 = content[index1 + 1:index2]
            value2 = content[index2 + 1:-1]
            withh = secondOrThird(value1, value2)
            valueDecimal = computeValue(value1, value2, withh)
            difference = size - valueDecimal
            return max(difference, 0)
        elif count == 3:
            index1 = content.find("+")
            index2 = content.find("+", index1 + 1)
            index3 = content.find("+", index2 + 1)
            value1 = content[index1 + 1:index2]
            value2 = content[index2 + 1:index3]
            withh = secondOrThird(value1, value2)
            valueDecimal = computeValue(value1, value2, withh)
            difference = size - valueDecimal
            return max(difference, 0)
    else:
        return 0

def isSameRegister(content):
    index1 = content.find(',')
    register1 = content[3:index1].strip()
    register2 = content[index1 + 1:].strip()
    return register1 == register2

def isRegisterReadLeft(content):
    index = content.find(',')
    content = content[3:index].strip()
    return "[eax" in content or "[edx" in content or "[ecx" in content

def isRegisterRead(content):
    # mov     edi, [eax+170h]
    index = content.find(',')
    content = content[index + 1:].strip()
    return "[eax" in content or "[edx" in content or "[ecx" in content

def getRegister(content):
    index = content.find(',')
    content = content[index + 1:].strip()  # [eax+12h]or [eax]
    index2 = content.find('[')
    index1 = content.find('+')
    if index1 == -1:  # doesn't contain '+'
        index3 = content.find('-')
        if index3 == -1:  # doesn't contain '-'
            content = content[index2 + 1:-1]
            return content
        else:
            content = content[index2 + 1:index3]
            return content
    else:
        content = content[index2 + 1:index1]
        return content

def getString1(disam):
    # dd offset aDefault; "default" string indirect jump issue
    index1 = disam.find(";")
    if index1 != -1:
        disam = "" + disam[index1 + 3: -1]
    else:
        disam = " "
    return disam

def getRegisterLeft(content):
    index = content.find(',')
    content = content[3:index].strip()
    index2 = content.find('[')
    index1 = content.find('+')
    if index1 == -1:  # doesn't contain '+'
        index3 = content.find('-')
        if index3 == -1:  # doesn't contain '-'
            content = content[index2 + 1:-1]
            return content
        else:
            content = content[index2 + 1:index3]
            return content
    else:
        content = content[index2 + 1:index1]
        return content

def isLibFunc_EAX_return(name):
    return name in libFuncs.linux_lib or \
           name in libFuncs.char_return_type or \
           name in libFuncs.char_pointer_return_type or \
           name in libFuncs.int_return_type or \
           name in libFuncs.int_unsigned_return_type or \
           name in libFuncs.long_return_type or \
           name in libFuncs.file_pointer_return_type

    
def getNewArgsRegister(register):  # Change al, etc., to eax
    eaxRegister = ['eax', 'ax', 'ah', 'al']
    edxRegister = ['edx', 'dx', 'dh', 'dl']
    ecxRegister = ['ecx', 'cx', 'ch', 'cl']
    if register in eaxRegister:
        return "eax"
    elif register in edxRegister:
        return "edx"
    elif register in ecxRegister:
        return "ecx"
    else:
        return register

def getNewArgsRegisterList(tempList):
    for i in range(len(tempList)):
        tempList[i] = getNewArgsRegister(tempList[i])
    return tempList

def identifyArgs_AllPath(func_t):
    pass

def identifyStackArgs(func_t):
    name = str(GetFunctionName(func_t.start_ea))
    global functionSet
    global pushAndCallList
    functionSet.add(name)
    if not function.identifiedVisited_stack[name]:
        stackArgs = set()
        registerArgs = set()
        modifiedReg = set()
        instrAddrs = getAllInstrAddrInOneFunction(func_t, func_t.start_ea, func_t.end_ea)
        for addr in instrAddrs:
            type1 = GetOpType(addr, 0)
            type2 = GetOpType(addr, 1)
            for i in range(2):
                type = GetOpType(addr, i)
                if type == 4:  # base + index + displacement. e.g., [esp+arg_0]
                    result = 0
                    if functionEBPBased[name]:  # ebp based
                        result = getOffsetWithEBP(GetOpnd(addr, i), GetOperandValue(addr, i))
                    else:
                        result = getOffsetWithoutEBP(GetOpnd(addr, i), GetOperandValue(addr, i))
                    if result > 0:
                        stackArgs.add(result)
                    if i == 1 and isRegisterRead(get_instruction(addr)):
                        register = getRegister(get_instruction(addr))
                        register = getNewArgsRegister(register)
                        if register not in modifiedReg:
                            registerArgs.add(register)
                elif type == 3:  # register indirect, base + index. e.g., dword ptr[esp], byte ptr [eax]
                    instr = GetMnem(addr)
                    if i == 1 and isRegisterRead(get_instruction(addr)):
                        register = getRegister(get_instruction(addr))
                        register = getNewArgsRegister(register)
                        if register not in modifiedReg:
                            registerArgs.add(register)
                    if instr == "cmp":
                        if i == 0 and isRegisterReadLeft(get_instruction(addr)):
                            register = getRegisterLeft(get_instruction(addr))
                            register = getNewArgsRegister(register)
                            if register not in modifiedReg:
                                registerArgs.add(register)
                elif type == 1:
                    register = GetOpnd(addr, i)
                    register = getNewArgsRegister(register)
                    instr = GetMnem(addr)
                    if instr == "push":
                        pushAndCallList.add(addr)
                    if register in argRegisters:
                        if type2 == 0:  # If there is no second operand
                            if instr not in ["push", "pop"]:
                                if register not in modifiedReg:
                                    registerArgs.add(register)
                                    modifiedReg.add(register)
                            if instr == "pop" and register in modifiedReg:
                                modifiedReg.remove(register)
                        elif type2 != 0:  # Two operands
                            if instr == "xor" and isSameRegister(get_instruction(addr)):
                                modifiedReg.add(register)
                            else:
                                if i == 1 and register not in modifiedReg:
                                    registerArgs.add(register)
                                if i == 0 and register not in modifiedReg:
                                    registerArgs.add(register)
                                    modifiedReg.add(register)
                            if i == 0 and instr not in ["cmp", "test"]:
                                modifiedReg.add(register)
                            if i == 1 and instr == "xchg":
                                modifiedReg.add(register)
                    else:
                        continue
                elif type == 2:  # Memory Reference
                    valueAddr = GetOperandValue(addr, i)
                    disam = idc.GetDisasm(valueAddr)
                    size = ItemSize(valueAddr)
                    value = 0
                    if size == 8:
                        value = GetDouble(valueAddr)
                        if math.isnan(value):
                            value = 0
                    elif size == 4:
                        if segment.rodataSegment[0] <= valueAddr < segment.rodataSegment[1]:
                            if isContainDot(disam):
                                value = round(GetFloat(valueAddr), 6)
                            else:
                                value = int(Dword(valueAddr))
                        elif segment.dataSegment[0] <= valueAddr < segment.dataSegment[1]:
                            if isContainDot(disam):
                                value = round(GetFloat(valueAddr), 6)
                            else:
                                value = int(Dword(valueAddr))
                    segment.constUsage[valueAddr] = value
                elif type == 5:  # offset
                    valueAddr = GetOperandValue(addr, i)
                    disam = idc.GetDisasm(valueAddr)
                    if isString(disam):
                        value = getString1(disam) if containSemicolonAndComma(disam) else GetString(valueAddr) or getString1(disam) or " "
                        if segment.rodataSegment[0] <= valueAddr < segment.rodataSegment[1]:
                            value = changeEncoding(value)
                        elif segment.dataSegment[0] <= valueAddr < segment.dataSegment[1]:
                            value = changeEncoding(value)
                        segment.constUsage[valueAddr] = value
                    else:
                        value = 0
                        size = ItemSize(valueAddr)
                        if size == 8:
                            value = GetDouble(valueAddr)
                        elif size == 4:
                            if segment.rodataSegment[0] <= valueAddr < segment.rodataSegment[1]:
                                value = round(GetFloat(valueAddr), 6) if isContainDot(disam) else int(Dword(valueAddr))
                            elif segment.dataSegment[0] <= valueAddr < segment.dataSegment[1]:
                                value = round(GetFloat(valueAddr), 6) if isContainDot(disam) else int(Dword(valueAddr))
                        segment.constUsage[valueAddr] = value
                if type in [6, 7]:  # call or jmp, including near or far address
                    if GetMnem(addr) == "call":
                        pushAndCallList.add(addr)
                        continue
        function.identifiedVisited_stack[name] = True
        argsList = [list(stackArgs), list(registerArgs), list(modifiedReg)]
        function.args_stack[name] = argsList
    else:
        argsList = function.args_stack[name]
        stackArgs, registerArgs, modifiedReg = set(argsList[0]), set(argsList[1]), set(argsList[2])
    return stackArgs, registerArgs, modifiedReg


def identifyArgs(func_t):
    name = str(GetFunctionName(func_t.start_ea))
    global functionSet
    functionSet.add(name)
    global allFuncInstancesPath

    if not function.identifiedVisited[name]:
        stackArgs_all = set()
        registerArgs_all = set()
        modifiedReg_all = set()
        for path in allFuncInstancesPath[func_t.start_ea].allPaths:
            stackArgs = set()
            registerArgs = set()
            modifiedReg = set()
            length = 0
            while length < len(path):
                addr = path[length]
                type1 = GetOpType(addr, 0)
                type2 = GetOpType(addr, 1)
                for i in range(2):
                    type = GetOpType(addr, i)
                    if type == 4:  # base + index + displacement. e.g., [esp+arg_0]
                        result = 0
                        if functionEBPBased[name]:  # ebp based
                            result = getOffsetWithEBP(GetOpnd(addr, i), GetOperandValue(addr, i))
                        else:
                            result = getOffsetWithoutEBP(GetOpnd(addr, i), GetOperandValue(addr, i))
                        if result > 0:
                            stackArgs.add(result)
                        if i == 1 and isRegisterRead(get_instruction(addr)):
                            register = getRegister(get_instruction(addr))
                            register = getNewArgsRegister(register)
                            if register not in modifiedReg:
                                registerArgs.add(register)
                    elif type == 3:  # register indirect, base + index. e.g., dword ptr[esp], byte ptr [eax]
                        instr = GetMnem(addr)
                        if i == 1 and isRegisterRead(get_instruction(addr)):
                            register = getRegister(get_instruction(addr))
                            register = getNewArgsRegister(register)
                            if register not in modifiedReg:
                                registerArgs.add(register)
                        if instr == "cmp":
                            if i == 0 and isRegisterReadLeft(get_instruction(addr)):
                                register = getRegisterLeft(get_instruction(addr))
                                register = getNewArgsRegister(register)
                                if register not in modifiedReg:
                                    registerArgs.add(register)
                    elif type == 1:
                        register = GetOpnd(addr, i)
                        register = getNewArgsRegister(register)
                        instr = GetMnem(addr)
                        if register in argRegisters:
                            if type2 == 0:  # If there is no second operand
                                if instr not in ["push", "pop"]:
                                    if register not in modifiedReg:
                                        registerArgs.add(register)
                                        modifiedReg.add(register)
                                if instr == "pop" and register in modifiedReg:
                                    modifiedReg.remove(register)
                            elif type2 != 0:  # Two operands
                                if instr == "xor" and isSameRegister(get_instruction(addr)):
                                    modifiedReg.add(register)
                                else:
                                    if register not in modifiedReg:
                                        if not (i == 0 and instr in doubleOperandsInstrs):
                                            registerArgs.add(register)
                                    if i == 0 and instr not in ["cmp", "test"]:
                                        modifiedReg.add(register)
                                    if i == 1 and instr == "xchg":
                                        modifiedReg.add(register)
                        else:
                            continue
                    elif type == 2:  # Memory Reference
                        valueAddr = GetOperandValue(addr, i)
                        disam = idc.GetDisasm(valueAddr)
                        size = ItemSize(valueAddr)
                        value = 0
                        if size == 8:
                            value = GetDouble(valueAddr)
                            if math.isnan(value):
                                value = 0
                        elif size == 4:
                            if segment.rodataSegment[0] <= valueAddr < segment.rodataSegment[1]:
                                value = round(GetFloat(valueAddr), 6) if isContainDot(disam) else int(Dword(valueAddr))
                            elif segment.dataSegment[0] <= valueAddr < segment.dataSegment[1]:
                                value = round(GetFloat(valueAddr), 6) if isContainDot(disam) else int(Dword(valueAddr))
                        segment.constUsage[valueAddr] = value
                    elif type == 5:  # offset
                        valueAddr = GetOperandValue(addr, i)
                        disam = idc.GetDisasm(valueAddr)
                        if isString(disam):
                            value = getString1(disam) if containSemicolonAndComma(disam) else GetString(valueAddr) or getString1(disam) or " "
                            if segment.rodataSegment[0] <= valueAddr < segment.rodataSegment[1]:
                                value = changeEncoding(value)
                            elif segment.dataSegment[0] <= valueAddr < segment.dataSegment[1]:
                                value = changeEncoding(value)
                            segment.constUsage[valueAddr] = value
                        else:
                            value = 0
                            size = ItemSize(valueAddr)
                            if size == 8:
                                value = GetDouble(valueAddr)
                            elif size == 4:
                                if segment.rodataSegment[0] <= valueAddr < segment.rodataSegment[1]:
                                    value = round(GetFloat(valueAddr), 6) if isContainDot(disam) else int(Dword(valueAddr))
                                elif segment.dataSegment[0] <= valueAddr < segment.dataSegment[1]:
                                    value = round(GetFloat(valueAddr), 6) if isContainDot(disam) else int(Dword(valueAddr))
                            segment.constUsage[valueAddr] = value
                    if type in [6, 7]:  # call or jmp, including near or far address
                        if GetMnem(addr) == "call":
                            functionName = GetOpnd(addr, i)
                            if functionName in function.functionMap:
                                if functionName not in functionSet:
                                    storeCurrentArgs(name, stackArgs, registerArgs, modifiedReg)
                                    calleeStackArgs, calleeRegisterArgs, calleeModifiedReg = identifyArgs(function.functionMap[functionName])
                                    tempRegisterArgs = calleeRegisterArgs - modifiedReg
                                    registerArgs |= tempRegisterArgs
                                    modifiedReg |= calleeModifiedReg
                                    if functionName in functionSet:
                                        functionSet.remove(functionName)
                                else:
                                    if function.identifiedVisited[functionName]:
                                        argsList1 = function.args[functionName]
                                        calleeStackArgs = set(argsList1[0])
                                        calleeRegisterArgs = set(argsList1[1])
                                        calleeModifiedReg = set(argsList1[2])
                                        tempRegisterArgs = calleeRegisterArgs - modifiedReg
                                        registerArgs |= tempRegisterArgs
                                        modifiedReg |= calleeModifiedReg
                                    else:
                                        calleeRegisterArgs, calleeModifiedReg = getCurrentArgs(functionName)
                                        tempRegisterArgs = calleeRegisterArgs - modifiedReg
                                        registerArgs |= tempRegisterArgs
                                        modifiedReg |= calleeModifiedReg
                            elif isLibFunc_EAX_return(functionName[1:]):
                                modifiedReg.add("eax")
                length += 1
            stackArgs_all |= stackArgs
            registerArgs_all |= registerArgs
            modifiedReg_all |= modifiedReg
        function.identifiedVisited[name] = True
        argsList_all = [list(stackArgs_all), list(registerArgs_all), list(modifiedReg_all)]
        function.args[name] = argsList_all
    else:
        argsList_all = function.args[name]
        stackArgs_all = set(argsList_all[0])
        registerArgs_all = set(argsList_all[1])
        modifiedReg_all = set(argsList_all[2])
    return stackArgs_all, registerArgs_all, modifiedReg_all
       

def storeCurrentArgs(name, stackArgs, registerArgs, modifiedReg):
    global currentArgList
    registerList = []
    registerList.append(list(registerArgs))
    registerList.append(list(modifiedReg))
    currentArgList[name] = registerList

def getCurrentArgs(name):
    global currentArgList
    if name in currentArgList.keys():
        registerList = currentArgList[name]
        return set(registerList[0]), set(registerList[1])
    else:
        return set(), set()

def decompile_func(ea):
    f = get_func(ea)
    if f is None:
        return False
    try:
        cfunc = decompile(f)
    except Exception as e:
        print("decompile failure")
        return False
    else:
        if cfunc is None:
            print("error in decompile")
            return False
    
        lines = []
        sv = cfunc.get_pseudocode()
        for sline in sv:
            line = tag_remove(sline.line)
            lines.append(line)
        return lines[0]

def getRegisterParametersFromFunctionPseudocode(funcStartAddr):
    declarationLine = decompile_func(funcStartAddr)
    if declarationLine == False:
        print("Failure during decompiling")
        return []
    else:
        index1 = declarationLine.find('(')
        if index1 != -1:
            declarationLine = declarationLine[index1 + 1:-1]
        parametersString = declarationLine.split(',')
        registerParameterList = []
        for item in parametersString:
            index2 = item.find('<')
            if index2 != -1:
                registerParameterList.append(item[index2 + 1:-1])
        return registerParameterList

def getFunctionsArgs():
    return set(), set(), set()

def storeNewCfg(db, cfgInfo):
    documents = []
    for item in cfgInfo.keys():
        document = {}
        document["startAddr"] = item
        if isinstance(cfgInfo[item], list):
            document["num"] = len(cfgInfo[item])
            document["successors"] = cfgInfo[item]
        else:
            document["num"] = 1
            tempList = []
            tempList.append(cfgInfo[item])
            document["successors"] = tempList
        documents.append(document)
    database.insertManyForCfg(db, documents)

def processFunction(func_t, db):
    global functionSet
    functionSet.clear()
    startAddr = func_t.start_ea
    frameSize = get_frame_size(func_t.start_ea)
    allBlocks = getAllBlocksInFunction(func_t)  # allBlocks is a dictionary
    cfg = getCFG_OF_Func(func_t)
    newCfg, startEnd, reps = getNewCFGIncludeCall(cfg, allBlocks, func_t)
    storeNewCfg(db, copy.deepcopy(newCfg))
    for item in startEnd.keys():
        binaryInBlock = getAllBinaryInstrInOneNode(func_t, item, startEnd[item])
        document = {}
        document["start"] = item
        document["end"] = startEnd[item]
        document["hexInstrs"] = binaryInBlock
        database.insertOneForBlock(db, document)
    document1List = []
    for item in reps:
        repBinary = getRepBinaryInstrInOneAddr(item, item_size(item))
        document1 = {}
        document1["start"] = item
        document1["hexInstrs"] = repBinary
        document1["end"] = 0  # not needed for now
        document1List.append(document1)
    database.insertManyForBlock(db, document1List)
    registerParameterList = getRegisterParametersFromFunctionPseudocode(func_t.start_ea)
    registerArgs = getNewArgsRegisterList(registerParameterList)
    functionSet.clear()
    stackArgs_stack, registerArgs_stack, modifiedReg_stack = identifyStackArgs(func_t)
    funDocument = {}
    funDocument["start"] = startAddr
    funDocument["end"] = func_t.end_ea
    funDocument["stackArgs"] = list(stackArgs_stack)
    funDocument["registerArgs"] = list(registerArgs)
    funDocument["name"] = str(GetFunctionName(startAddr))
    if functionEBPBased[str(GetFunctionName(startAddr))]:
        funDocument["ebpBased"] = 1
    else:
        funDocument["ebpBased"] = 0
    global isVulnerabilityProgram
    if isVulnerabilityProgram:
        funDocument["vulnerability"] = 0
        funDocument["cve-num"] = ""
    database.insertOneForFunction(db, funDocument)

def storeFunction(db, functionsDict):
    documents = []
    for key in functionsDict.keys():
        document = {}
        document["start"] = key
        document["name"] = functionsDict[key]
        documents.append(document)
    database.insertManyForLibFunction(db, documents)

        
def getArgs(addr, name):
    tif = tinfo_t()
    funcdata = func_type_data_t()
    for i in range(funcdata.size()):
        print("Arg %d: %s (of type %s, and of location: %s)" % 
              (i, funcdata[i].name, print_tinfo('', 0, 0, PRTYPE_1LINE, funcdata[i].type, '', ''), funcdata[i].argloc.atype()))

def generateRandomArgs(db, funName):
    randomValueList = randomInput.getRandomValueList()
    document = {}
    document["name"] = funName
    document["randomValues"] = randomValueList
    database.insertOneForRandomValue(db, document)

def getFunctions(db):
    functionList = []
    functionMap = {}
    global functionEBPBased
    for i in range(get_func_qty()):
        fun = getn_func(i)  # get_func returns a func_t struct for the function
        segname = get_segm_name(fun.start_ea)  # get the segment name of the function by address ,x86 arch segment includes (_init _plt _plt_got _text extern _fini)
        funName = str(GetFunctionName(fun.start_ea))
        function.lib_function[fun.start_ea] = funName
        if segname[1:3] not in ["OA", "OM", "te"]:
            continue        
        if funName in globalVariable.addedFunctions:
            continue
        globalVariable.functionListStruct.append(fun)
        funcInstance = Process_with_Single_Function(fun)  # Create an instance object for each function, including graph relationships, and ultimately generate the function's paths
        getAllPath(funcInstance)
        functionList.append(funName)
        function.functionMap[funName] = fun
        function.identifiedVisited[funName] = False
        function.identifiedVisited_stack[funName] = False
        func_flags = GetFunctionFlags(fun.start_ea)
        generateRandomArgs(db, funName)
        if (func_flags & FUNC_FRAME):  # is this an ebp-based frame?
            functionEBPBased[funName] = True
        else:
            functionEBPBased[funName] = False
    storeFunction(db, function.lib_function)
    global f
    f.flush()
    return functionList, functionMap

def getFunctions_new(db):
    functionList = []
    functionMap = {}
    global functionEBPBased
    for i in range(get_func_qty()):
        fun = getn_func(i)  # get_func returns a func_t struct for the function
        segname = get_segm_name(fun.start_ea)  # get the segment name of the function by address ,x86 arch segment includes (_init _plt _plt_got _text extern _fini)
        funName = str(GetFunctionName(fun.start_ea))
        function.lib_function[fun.start_ea] = funName
        if segname[1:3] not in ["OA", "OM", "te"]:
            continue        
        if funName in globalVariable.addedFunctions:
            continue
        globalVariable.functionListStruct.append(fun)
        functionList.append(funName)
        function.functionMap[funName] = fun
        function.identifiedVisited[funName] = False
        function.identifiedVisited_stack[funName] = False
        func_flags = GetFunctionFlags(fun.start_ea)
        print("Random arguments generated for:", funName)
        generateRandomArgs(db, funName)
        if (func_flags & FUNC_FRAME):  # is this an ebp-based frame?
            functionEBPBased[funName] = True
        else:
            functionEBPBased[funName] = False
        getArgs(fun.start_ea, funName)
    storeFunction(db, function.lib_function)
    global f
    f.flush()
    return functionList, functionMap

def findJumpTable():
    pass

def changeEncoding(value):
    encoding = chardet.detect(value)
    encoding_type = encoding["encoding"]
    if encoding_type == "ISO-8859-1":
        value = value.decode("ISO-8859-1").encode("utf-8")
    elif (encoding_type is None) or (encoding_type == "ISO-8859-8"):
        value = " "
    else:
        value = value.decode(encoding_type).encode("utf-8")
    return value

def storePushAndCall(db):
    global pushAndCallList
    tempList = list(pushAndCallList)
    document = {}
    document["addrs"] = tempList
    try:
        database.insertAllForPushAndCall(db, document)
    except BaseException:
        global f
        f.close()

def storeConst(db):
    documents = []
    for key in segment.constUsage.keys():
        document = {}
        value = segment.constUsage[key]
        document["addr"] = key
        document["value"] = value
        try:
            database.insertOneForConst(db, document)
        except BaseException:
            global f
            f.close()
        documents.append(document)

def initSegment(db):
    result = Segments()  # return the start address of each segment
    documents = []
    for startAddr in result:
        document = {}
        name = get_segm_name(startAddr)
        document["name"] = name[1:]
        document["start"] = startAddr
        document["end"] = SegEnd(startAddr)
        documents.append(document)
        if name[1:] == "rodata":
            endAddr = SegEnd(startAddr)
            segment.rodataSegment.append(startAddr)
            segment.rodataSegment.append(endAddr)
        if name[1:] == "data":
            endAddr = SegEnd(startAddr)
            segment.dataSegment.append(startAddr)
            segment.dataSegment.append(endAddr)
    database.insertManyForSegment(db, documents)


def createGraph(funcInstance):
    g = graph.Graph(funcInstance._num)
    g.add_nodes([i for i in range(funcInstance._num)])
    for m in funcInstance._offspringSet.keys():
        for n in funcInstance._offspringSet[m]:
            if m != n:
                g.add_edge((funcInstance._mapping[m], funcInstance._mapping[n]))
            else:
                print("Self-loop detected")
    paths = []
    for item in funcInstance._endblocks:
        node = funcInstance._mapping[item]
        path = g.getOnePath(0, node, funcInstance._name_func)
        paths.extend(path)
    return paths


def getAllInstrAddrInOneBlock(func_t, startEA, endEA):
    it_code = func_item_iterator_t(func_t, startEA)
    ea = it_code.current()
    address = []
    while ea < endEA:
        address.append(ea)
        if not it_code.next_code():
            break
        ea = it_code.current()
    return address


def getAllPath(funcInstance):
    global allFuncInstancesPath
    reverse_Id_Addr = {v: k for k, v in funcInstance._mapping.items()}
    allPaths = createGraph(funcInstance)
    print("allPaths:", len(allPaths), allPaths)
    allPaths_addr = []
    for path in allPaths:
        path_addr = []
        for item in path:
            path_addr.append(reverse_Id_Addr[item])
        allPaths_addr.append(path_addr)
    allInstr = []
    for path in allPaths_addr:
        instr = []
        for item in path:
            value = getAllInstrAddrInOneBlock(funcInstance._func, item, funcInstance._block_boundary[item])
            instr.extend(value)
        allInstr.append(instr)
    funcInstance.allPaths = allInstr
    allFuncInstancesPath[funcInstance._addr_func] = funcInstance


def print_help():
    help_message = 'Arguments not enough'
    print(help_message)


def printArgs(db):
    functionArgs = database.findAllFunctions(db)
    for i in functionArgs:
        print("-----------------------------------------------")
        print("name:", i["name"])
        print("stackArgs:", i["stackArgs"])
        print("registerArgs:", i["registerArgs"])
        print("-----------------------------------------------")


def processSwitch(db, startAddr, endAddr):
    stmtAddrList, jumpStartList, jumpEndList, casesList, targetsList = identify_switch(startAddr, endAddr)
    for i in range(len(stmtAddrList)):
        funcName = GetFunctionName(stmtAddrList[i])
        targets_sorted = sorted(targetsList[i])
        document = {}
        document["funcName"] = funcName
        document["funcStart"] = startAddr
        document["funcEnd"] = endAddr
        document["stmtAddr"] = stmtAddrList[i]
        document["jumpStartAddr"] = jumpStartList[i]
        document["jumpEndAddr"] = jumpEndList[i]
        document["firstTarget"] = targets_sorted[0]
        document["cases"] = casesList[i]
        document["targets"] = targetsList[i]
        database.insertOneForSwitch(db, document)


def dropCollections(db):
    db.function.drop()
    db.block.drop()
    db.const.drop()
    db.segment.drop()
    db.lib.drop()
    db.switch.drop()
    db.pushAndCall.drop()


def initialSameRandomValue(db):
    list1 = randomInput.getRandomValueList()
    document = {}
    document["name"] = "sameRandomValueList"
    document["valueList"] = list1
    database.insertOneForSameRandomValue(db, document)


def parseArgs():
    global fileName, programName
    fileName = GetInputFile()
    programName = GetInputFilePath().split('\\')[-2]
    argList = ARGV[1:]
    if len(argList) == 0:
        return
    for arg in argList:
        tempList = arg.split('=')
        if tempList[0] == "--type":
            if tempList[1] in ["V", "v"]:
                global isVulnerabilityProgram
                isVulnerabilityProgram = True
        else:
            exit()

def main():
    global is64bit_binary, isVulnerabilityProgram, programName, fileName
    is64bit_binary = GetIdbPath().endswith("i64")
    loadDecompilePlugin()
    parseArgs()
    global f
    print_help()
    if len(idc.ARGV) < 0:
        print_help()
        return
    set_seg = set()
    db, client = database.connectDB(isVulnerabilityProgram, False, programName, fileName)
    initialSameRandomValue(db)
    initSegment(db)
    functionList = getFunctions_new(db)  # all the functions in .text section except addedFunctions
    for func in globalVariable.functionListStruct:  # func is a struct describing functions
        processSwitch(db, func.startEA, func.endEA)
        processFunction(func, db)
        condition = {}
        condition["start"] = func.startEA
        database.findOneFunction(db, condition)
        f.flush()
    storePushAndCall(db)
    storeConst(db)
    printArgs(db)
    database.closeConnect(client)
    client = None
    return


def load_plugin_decompiler():
    global is64bit_binary
    if is64bit_binary:
        # Load 64-bit plugin
        RunPlugin("hexx64", 0)
    else:
        # Load 32-bit plugin
        RunPlugin("hexrays", 0)
        RunPlugin("hexarm", 0)


def loadDecompilePlugin():
    if not init_hexrays_plugin():
        load_plugin_decompiler()
    if not init_hexrays_plugin():
        print("hexrays decompiler is not available :(")
        raise Exception("hexrays decompiler is not available :(")


# Redirect output into a file, original output is the console.
def stdout_to_file(output_file_name, output_dir=None):
    '''Set stdout to a file descriptor
    param: output_file_name: name of the file where standard output is written.
    param: output_dir: output directory for output file, default to script directory.
    Returns: output file descriptor, original stdout descriptor
    '''
    global f
    if not output_dir:
        output_dir = os.path.dirname(os.path.realpath(__file__))

    output_file_path = os.path.join(output_dir, output_file_name)
    orig_stdout = sys.stdout
    f = open(output_file_path, "w")  # Use open() instead of file() in Python 3
    sys.stdout = f

    return f, orig_stdout


if __name__ == '__main__':
    global f
    f, orig_stdout = stdout_to_file("output.txt")
    main()
    sys.stdout = orig_stdout  # Recover the output to the console window
    f.close()

    # idc.Exit(0)
