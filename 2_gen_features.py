#!/usr/bin/python3
# -*- coding: UTF-8 -*-
import config
import config_for_feature
import sys
sys.path.append("/usr/local/python2713/lib/python3.8/site-packages")
import networkx as nx
# import idaapi
import ida_auto
import idautils
import idc
import ida_funcs
import ida_gdl
import ida_pro
import os
import time
import shutil
from miasm2.core.bin_stream_ida import bin_stream_ida
from miasm2.core.asmblock import expr_is_label, AsmLabel, is_int
from miasm2.expression.simplifications import expr_simp
from miasm2.analysis.data_flow import dead_simp
from miasm2.ir.ir import AssignBlock, IRBlock
from utils import guess_machine, expr2colorstr
import re

ida_auto.auto_wait()

bin_num = 0
func_num = 0
function_list_file = ""
function_list_fp = None
# Since Windows filenames are case-insensitive, we record analyzed function names (all converted to lowercase, and if duplicated, add the current timestamp as a suffix)
functions = []

curBinNum = 0

class bbls:
    id = ""
    define = []
    use = []
    defuse = {}
    fathernode = set()
    childnode = set()
    define = set()
    use = set()
    visited = False

def calConstantNumber(ea):
    i = 0
    curStrNum = 0
    numeric = 0
    # print(idc.GetDisasm(ea))
    while i <= 1:
        # if idc.GetOpType(ea, i) == 5:
        if idc.get_operand_type(ea, i) == 5:
            # addr = idc.GetOperandValue(ea, i)
            addr = idc.get_operand_value(ea, i)
            # if idc.SegName(addr) == '.rodata' and idc.GetType(addr) == 'char[]' and i == 1:
            if idc.get_segm_name(addr) == '.rodata' and idc.get_type(addr) == 'char[]' and i == 1:
                curStrNum += 1
            else:
                numeric += 1
        i += 1
    return numeric, curStrNum

# Calculate non-structural features of a basic block
def calBasicBlockFeature_vulseeker(block):
    StackNum = 0  # stackInstr
    MathNum = 0  # arithmeticInstr
    LogicNum = 0  # logicInstr
    CompareNum = 0  # compareInstr
    ExCallNum = 0  # externalInstr
    InCallNum = 0  # internalInstr
    ConJumpNum = 0  # conditionJumpInstr
    UnConJumpNum = 0  # unconditionJumpInstr
    GeneicNum = 0  # genericInstr
    # curEA = block.start_ea
    curEA = block.start_ea
    while curEA <= block.end_ea:
        # inst = idc.GetMnem(curEA)
        inst = idc.print_insn_mnem(curEA)
        if inst in config_for_feature.VulSeeker_stackInstr:
            StackNum += 1
        elif inst in config_for_feature.VulSeeker_arithmeticInstr:
            MathNum += 1
        elif inst in config_for_feature.VulSeeker_logicInstr:
            LogicNum += 1
        elif inst in config_for_feature.VulSeeker_compareInstr:
            CompareNum += 1
        elif inst in config_for_feature.VulSeeker_externalInstr:
            ExCallNum += 1
        elif inst in config_for_feature.VulSeeker_internalInstr:
            InCallNum += 1
        elif inst in config_for_feature.VulSeeker_conditionJumpInstr:
            ConJumpNum += 1
        elif inst in config_for_feature.VulSeeker_unconditionJumpInstr:
            UnConJumpNum += 1
        else:
            GeneicNum += 1

        # curEA = idc.NextHead(curEA, block.end_ea)
        curEA = idc.next_head(curEA, block.end_ea)
    
    fea_str = f"{StackNum},{MathNum},{LogicNum},{CompareNum},{ExCallNum},{ConJumpNum},{UnConJumpNum},{GeneicNum},"
    return fea_str

# Calculate number of string constants, numeric constants, transfer instructions, call instructions, total instructions, and arithmetic instructions
def calBasicBlockFeature_gemini(block):
    numericNum = 0
    stringNum = 0
    transferNum = 0
    callNum = 0
    InstrNum = 0
    arithNum = 0
    logicNum = 0
    curEA = block.start_ea
    while curEA <= block.end_ea:
        # Calculate number of numeric and string constants
        numer, stri = calConstantNumber(curEA)
        numericNum += numer
        stringNum += stri

        # Calculate number of transfer instructions
        # if idc.GetMnem(curEA) in config_for_feature.Gemini_allTransferInstr:
        if idc.print_insn_mnem(curEA) in config_for_feature.Gemini_allTransferInstr:
            transferNum += 1

        # Calculate number of calls
        # if idc.GetMnem(curEA) == 'call':
        if idc.print_insn_mnem(curEA) == 'call':
            callNum += 1

        # Calculate total number of instructions
        InstrNum += 1

        # Calculate number of arithmetic instructions
        # if idc.GetMnem(curEA) in config_for_feature.Gemini_arithmeticInstr:
        if idc.print_insn_mnem(curEA) in config_for_feature.Gemini_arithmeticInstr:
            arithNum += 1

        # Calculate number of logic instructions
        # if idc.GetMnem(curEA) in config_for_feature.Gemini_logicInstr:
        if idc.print_insn_mnem(curEA) in config_for_feature.Gemini_logicInstr:
            logicNum += 1

        # curEA = idc.NextHead(curEA, block.end_ea)
        curEA = idc.next_head(curEA, block.end_ea)

    fea_str = f"{numericNum},{stringNum},{transferNum},{callNum},{InstrNum},{arithNum},{logicNum},"
    return fea_str

def block_fea(allblock, fea_fp):
    for block in allblock:
        gemini_str = calBasicBlockFeature_gemini(block)
        vulseeker_str = calBasicBlockFeature_vulseeker(block)
        fea_str = f"{hex(block.start_ea)},{gemini_str}{vulseeker_str}\n"
        fea_fp.write(fea_str)

def build_dfg(DG, IR_blocks):
    IR_blocks_dfg = IR_blocks
    # Initialize the collection of all defined variables
    startnode = ''
    linenum = 0
    for in_label, in_value in IR_blocks.items():
        linenum = 0
        addr = in_label.split(":")[1].strip()
        tempbbls = bbls()
        tempbbls.id = addr
        tempbbls.childnode = set()
        tempbbls.fathernode = set()
        # Dictionary to record left and right side of the assignment
        tempbbls.defuse = {}
        # Dictionary to record defined and used variables, with initial and final positions
        tempbbls.defined = {}
        tempbbls.used = {}
        # Set to record all defined variables in the basic block
        tempbbls.definedset = set()
        tempbbls.visited = False
        IR_blocks_dfg[addr] = tempbbls

        for i in in_value:
            linenum += 1
            # Analyze each line of code
            if '=' not in i or "call" in i or 'IRDst' in i:
                continue

            define = i.split('=')[0].strip()
            if '[' in define:
                define = define[define.find('[') + 1:define.find(']')]
            use = i.split('=')[1].strip()
            if define not in tempbbls.defined:
                tempbbls.defined[define] = [linenum, 0]
            else:
                tempbbls.defined[define][1] = linenum

            if define not in IR_blocks_dfg[addr].defuse:
                IR_blocks_dfg[addr].defuse[define] = set()

            # If there are no parentheses, assume it’s a simple assignment
            if '(' not in use and '[' not in use:
                IR_blocks_dfg[addr].defuse[define].add(use)
                if use not in tempbbls.used:
                    tempbbls.used[use] = [linenum, 0]
                else:
                    tempbbls.used[use][1] = linenum
            # Remove parentheses
            else:
                srclist = list(i)
                for i in range(len(srclist)):
                    if srclist[i] == ")" and srclist[i - 1] != ")":
                        tmp = srclist[0:i + 1][::-1]
                        for j in range(len(tmp)):
                            if tmp[j] == "(":
                                temps = "".join(srclist[i - j:i + 1])
                                if temps.count(')') == 1 and temps.count('(') == 1:
                                    temps = temps[1:-1]  # Remove parentheses
                                    IR_blocks_dfg[addr].defuse[define].add(temps)
                                    if temps not in tempbbls.used:
                                        tempbbls.used[temps] = [linenum, 0]
                                    else:
                                        tempbbls.used[temps][1] = linenum
                                break

                for i in range(len(srclist)):
                    if srclist[i] == "]" and srclist[i - 1] != "]":
                        tmp = srclist[0:i + 1][::-1]
                        for j in range(len(tmp)):
                            if tmp[j] == "[":
                                temps = "".join(srclist[i - j:i + 1])
                                if temps.count(']') == 1 and temps.count('[') == 1:
                                    temps = temps[1:-1]  # Remove brackets
                                    IR_blocks_dfg[addr].defuse[define].add(temps)
                                    if temps not in tempbbls.used:
                                        tempbbls.used[temps] = [linenum, 0]
                                    else:
                                        tempbbls.used[temps][1] = linenum
                                break

    for cfgedge in DG.edges():
        innode = str(cfgedge[0])
        outnode = str(cfgedge[1])
        if innode == outnode:
            continue
        if innode in IR_blocks_dfg:
            IR_blocks_dfg[innode].childnode.add(outnode)
        if outnode in IR_blocks_dfg:
            IR_blocks_dfg[outnode].fathernode.add(innode)

    # Find the starting node and record all variables defined in each basic block
    cfg_nodes = DG.nodes()
    startnode = None
    for addr, bbloks in IR_blocks_dfg.items():
        if ':' in addr:
            continue
        if len(cfg_nodes) == 1 or startnode is None:  # Only one basic block or a full loop
            startnode = addr
        if addr in cfg_nodes and len(IR_blocks_dfg[addr].fathernode) == 0:
            startnode = addr
        for definevar in IR_blocks_dfg[addr].defuse:
            IR_blocks_dfg[addr].definedset.add(definevar)

    if startnode is None:
        return nx.DiGraph()
    else:
        return gen_dfg(IR_blocks_dfg, startnode)

def gen_dfg(IR_blocks_dfg, startnode):
    # DFS traversal
    res_graph = nx.DiGraph()
    stack_list = []
    visited = {}
    # visited2 represents nodes to be visited a second time but haven’t been yet
    visited2 = {}
    # visited3 represents nodes that have been visited twice and are done
    visited3 = {}
    
    for key, val in IR_blocks_dfg.items():
        visited2[key] = set()
        visited3[key] = set()
    visitorder = []

    IR_blocks_dfg[startnode].visited = True
    visited[startnode] = '1'
    visitorder.append(startnode)
    stack_list.append(startnode)

    while len(stack_list) > 0:
        cur_node = stack_list[-1]
        next_nodes = set()
        if cur_node in IR_blocks_dfg:
            next_nodes = IR_blocks_dfg[cur_node].childnode

        if len(next_nodes) == 0:  # Leaf node needs to backtrack
            stack_list.pop()
            visitorder.pop()

        else:
            if len(set(next_nodes) - set(visited.keys())) == 0 and len(next_nodes & visited2[cur_node]) == 0:
                # If all have been visited, backtrack
                stack_list.pop()
                visitorder.pop()

            else:
                for i in next_nodes:
                    if i not in visited or i in visited2[cur_node]:
                        fathernodes = set()
                        usevar = {}
                        definevar = {}
                        if i in IR_blocks_dfg:
                            # List of parent nodes
                            fathernodes = IR_blocks_dfg[i].fathernode
                            # Dictionary: variables used in the basic block, and their positions
                            usevar = IR_blocks_dfg[i].used
                            # Dictionary: variables defined in the basic block, and their positions
                            definevar = IR_blocks_dfg[i].defined
                        
                        fdefinevarset = set()
                        allfdefinevarset = set()

                        for uvar in usevar:
                            # If this variable used hasn't been defined within the block
                            # or is used before it is defined, look in the parent nodes
                            if uvar not in definevar or usevar[uvar][0] < definevar[uvar][0]:
                                for fnode in fathernodes:
                                    fdefinevarset = set()
                                    if fnode in IR_blocks_dfg:
                                        fdefinevarset = IR_blocks_dfg[fnode].definedset
                                    allfdefinevarset |= fdefinevarset
                                    if uvar in fdefinevarset:
                                        res_graph.add_edge(fnode, i)
                                        print(f"{fnode} -> {i} var: {uvar}")
                                
                                # There may be data dependencies with parent’s parent nodes; search in reverse order based on DFS
                                for j in range(len(visitorder) - 1, -1, -1):
                                    visitednode = visitorder[j]
                                    temp_definedset = set()
                                    if visitednode in IR_blocks_dfg:
                                        temp_definedset = IR_blocks_dfg[visitednode].definedset
                                    if uvar in temp_definedset - allfdefinevarset:
                                        res_graph.add_edge(visitednode, i)
                                        allfdefinevarset |= temp_definedset
                                        print(f"Backtrace {visitednode} -> {i} var: {uvar}")

                        visited[i] = '1'
                        visitorder.append(i)
                        if i in visited2[cur_node]:
                            visited2[cur_node].remove(i)
                            visited3[cur_node].add(i)
                        temp_childnode = set()
                        if i in IR_blocks_dfg:
                            temp_childnode = IR_blocks_dfg[i].childnode
                        visited2[cur_node] |= (set(temp_childnode) & set(visited)) - set(visited3[cur_node])
                        stack_list.append(i)
    return res_graph

def get_father_block(blocks, cur_block, yes_keys):
    # print("find father block", cur_block.label)
    father_block = None
    for temp_block in blocks:
        # print(temp_block.get_next(), "<>", cur_block.label)
        if temp_block.get_next() is cur_block.label:
            father_block = temp_block
    if father_block is None:
        return None
    is_Exist = False
    for yes_label in yes_keys:
        # print(father_block.label)
        if ((str(father_block.label) + "L")).split(' ')[0].endswith(yes_label):
            is_Exist = True
    if not is_Exist:
        # print("Not exist", ((str(father_block.label) + "L")).split(' ')[0])
        father_block = get_father_block(blocks, father_block, yes_keys)
        return father_block
    else:
        # print("exist", ((str(father_block.label) + "L")).split(' ')[0])
        return father_block

def rebuild_graph(cur_block, blocks, IR_blocks, no_ir):
    # print(">>rebuild", len(no_ir))
    yes_keys = list(IR_blocks.keys())
    no_keys = list(no_ir.keys())
    next_label = (str(cur_block.label) + "L").split(' ')[0]
    father_block = get_father_block(blocks, cur_block, yes_keys)
    if father_block is not None:
        for yes_label in yes_keys:
            if ((str(father_block.label) + "L")).split(' ')[0].endswith(yes_label):
                for no_label in no_keys:
                    # print("222", next_label, no_label)
                    if next_label.endswith(no_label):
                        IR_blocks[yes_label].pop()
                        IR_blocks[yes_label].extend(IR_blocks[no_label])
                        # print("<<<del", no_label)
                        # print("<<<len", len(no_ir))
                        del no_ir[no_label]
                        del IR_blocks[no_label]
    return IR_blocks, no_ir

def dataflow_analysis(addr, block_items, DG):
    machine = guess_machine()
    mn, dis_engine, ira = machine.mn, machine.dis_engine, machine.ira
    # print("Arch", dis_engine)
    # fname = idc.GetInputFile()
    # print("file name:", fname)
    # print("machine", machine)

    bs = bin_stream_ida()
    mdis = dis_engine(bs)
    mdis.dont_dis_retcall_funcs = []
    mdis.dont_dis = []
    ir_arch = ira(mdis.symbol_pool)
    blocks = mdis.dis_multiblock(addr)
    for block in blocks:
        ir_arch.add_block(block)
        # print(">>asm block", block)

    IRs = {}
    for lbl, irblock in ir_arch.blocks.items():
        insr = []
        for assignblk in irblock:
            for dst, src in assignblk.items():
                insr.append(str(dst) + "=" + str(src))
        # print(">>ir", (str(lbl) + "L"), insr)
        IRs[str(lbl).split(' ')[0] + "L"] = insr
    # print("IRs.keys()", list(IRs.keys()))

    IR_blocks = {}
    no_ir = {}
    # print("block_items", block_items)
    for block in blocks:
        # print("block.label", block.label)
        isFind = False
        item = str(block.label).split(' ')[0] + "L"
        # item = "0x" + (str(block.label).split(' ')[0].split(':')[1][2:]).lstrip('0') + "L"
        # print("block line number", item)
        for block_item in block_items:
            if item.endswith(block_item):
                isFind = True

        if item in IRs:
            if isFind:
                IR_blocks[item] = IRs[item]
            else:
                IR_blocks[item] = IRs[item]
                no_ir[item] = IRs[item]

    no_keys = list(no_ir.keys())
    for cur_label in no_keys:
        cur_block = None
        for block in blocks:
            temp_index = str(block.label).split(' ')[0] + "L"
            if temp_index.endswith(cur_label):
                cur_block = block
        if cur_block is not None:
            IR_blocks, no_ir = rebuild_graph(cur_block, blocks, IR_blocks, no_ir)

    IR_blocks_toDFG = {}
    for key, value in IR_blocks.items():
        if len(key.split(':')) > 1:
            key = key.split(':')[0] + ":0x" + key.split(':')[1].strip()[2:].lstrip('0')
        IR_blocks_toDFG[key] = value

    dfg = build_dfg(DG, IR_blocks_toDFG)
    dfg.add_nodes_from(DG.nodes())
    print("CFG edges <<", DG.number_of_edges(), ">> :", DG.edges())
    print("DFG edges <<", dfg.number_of_edges(), ">> :", dfg.edges())
    print("DFG nodes:", dfg.number_of_nodes())
    return dfg


def main():
    global bin_num, func_num, function_list_file, function_list_fp, functions

    fea_path = ""
    if len(idc.ARGV) < 1:
        fea_path = config.FEA_DIR + "\\CVE-2015-1791\\DAP-1562_FIRMWARE_1.10"
        bin_path = config.O_DIR + "\\CVE-2015-1791\\DAP-1562_FIRMWARE_1.10\\wpa_supplicant.i64"
        binary_file = bin_path.split(os.sep)[-1]
        program = "CVE-2015-1791"
        version = "DAP-1562_FIRMWARE_1.10"
    else:
        print(idc.ARGV[1])
        print(idc.ARGV[2])
        fea_path_origion = idc.ARGV[1]
        fea_path_temp = idc.ARGV[1] + "\\temp"
        bin_path = idc.ARGV[2]
        binary_file = bin_path.split(os.sep)[-1]
        program = idc.ARGV[3]
        version = idc.ARGV[4]

    print("Directory path:", fea_path_origion)
    fea_path_origion = fea_path_origion.replace("\\", "/").replace("/c/", "C:/")
    if not os.path.exists(fea_path_origion):
        print("Directory does not exist")
        os.makedirs(fea_path_origion)

    function_list_file = fea_path_origion + os.sep + "functions_list_fea.csv"
    function_list_file = function_list_file.replace("\\", "/")
    print("function_list_file: ", function_list_file)
    function_list_fp = open(function_list_file, 'w')

    textstart_ea = 0
    textend_ea = 0
    for seg in idautils.Segments():
        # if idc.SegName(seg) == ".text":
        if idc.get_segm_name(seg) == ".text":
            # textstart_ea = idc.SegStart(seg)
            textstart_ea = idc.get_segm_start(seg)
            # textend_ea = idc.SegEnd(seg)
            textend_ea = idc.get_segm_end(seg)
            break

    # Traverse all instructions in the file and save to a file
    # Generate a dictionary where each instruction address is mapped to an instruction ID
    print("Traversing all instructions, generating instDict, inst_info")
    for func in idautils.Functions(textstart_ea, textend_ea):
        # Ignore Library Code
        # flags = idc.GetFunctionFlags(func)
        flags = idc.get_func_flags(func)
        if flags & idc.FUNC_LIB:
            # print(hex(func), "FUNC_LIB", idc.GetFunctionName(func))
            print(hex(func), "FUNC_LIB", idc.get_func_name(func))
            continue

        # cur_function_name = idc.GetFunctionName(func)
        cur_function_name = idc.get_func_name(func)
        print(cur_function_name)
        
        fea_path = fea_path_origion
        if cur_function_name.lower() in functions:
            fea_path = fea_path_temp
            if not os.path.exists(fea_path):
                os.mkdir(fea_path)
        functions.append(cur_function_name.lower())
        print(cur_function_name, "=====start")  # Print function name
        
        # Record control flow information for the function, generating a CFG adjacency list
        # allblock = idaapi.FlowChart(idaapi.get_func(func))
        allblock = ida_gdl.FlowChart(ida_funcs.get_func(func))
        
        cfg_file = fea_path + os.sep + str(cur_function_name) + "_cfg.txt"
        cfg_file = cfg_file.replace("\\", "/")
        print("cfg_file: ", cfg_file)
        cfg_fp = open(cfg_file, 'w')
        block_items = []
        DG = nx.DiGraph()
        for idaBlock in allblock:
            temp_str = str(hex(idaBlock.start_ea))
            block_items.append(temp_str[2:])
            DG.add_node(hex(idaBlock.start_ea))
            for succ_block in idaBlock.succs():
                DG.add_edge(hex(idaBlock.start_ea), hex(succ_block.start_ea))
            for pred_block in idaBlock.preds():
                DG.add_edge(hex(pred_block.start_ea), hex(idaBlock.start_ea))
        
        for cfg_node in DG.nodes():
            cfg_str = str(cfg_node)
            for edge in DG.succ[cfg_node]:
                cfg_str = cfg_str + " " + edge
            cfg_str = cfg_str + "\n"
            cfg_fp.write(cfg_str)

        # Record data flow information for the function, generating a DFG adjacency list
        dfg = dataflow_analysis(func, block_items, DG)
        dfg_file = fea_path + os.sep + str(cur_function_name) + "_dfg.txt"
        dfg_file = dfg_file.replace("\\", "/")
        print("dfg_file: ", dfg_file)
        dfg_fp = open(dfg_file, 'w')
        for dfg_node in dfg.nodes():
            dfg_str = dfg_node
            for edge in dfg.succ[dfg_node]:
                dfg_str = dfg_str + " " + edge
            dfg_str = dfg_str + "\n"
            dfg_fp.write(dfg_str)

        # Record basic block information for the function, extracting features from each basic block
        fea_file = fea_path + os.sep + str(cur_function_name) + "_fea.csv"
        fea_file = fea_file.replace("\\", "/")
        print("fea_file: ", fea_file)
        fea_fp = open(fea_file, 'w')
        block_fea(allblock, fea_fp)

        # Record function summary information: function name, path, basic block count, control flow edge count, data flow edge count
        print(cur_function_name, "=====finish")  # Print function name
        function_str = f"{cur_function_name},{DG.number_of_nodes()},{DG.number_of_edges()},{dfg.number_of_edges()},{program},{version},{bin_path},\n"
        function_list_fp.write(function_str)
    return

# Redirect output to a file; original output goes to the console
def stdout_to_file(output_file_name, output_dir=None):
    if not output_dir:
        output_dir = os.path.dirname(os.path.realpath(__file__))
    output_file_path = os.path.join(output_dir, output_file_name)
    print(output_file_path)
    print("original output start")
    # Save original stdout descriptor
    orig_stdout = sys.stdout
    # Create output file
    f = open(output_file_path, "w")
    f.write("original output start\n")

    # Set stdout to output file descriptor
    sys.stdout = f
    return f, orig_stdout

if __name__ == '__main__':
    f, orig_stdout = stdout_to_file("output_" + time.strftime('%Y%m%d%H%M%S', time.localtime(time.time())) + ".txt")
    main()
    print("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX")
    # Restore output to the console
    sys.stdout = orig_stdout
    f.close()

    ida_pro.qexit(0)
