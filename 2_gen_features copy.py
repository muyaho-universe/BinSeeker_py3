#!/usr/bin/python
# -*- coding: UTF-8 -*-
import config
import config_for_feature
import sys
sys.path.append("/usr/local/python2713/lib/python2.7/site-packages")
import networkx as nx
import idaapi
import idautils
import idc
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


idaapi.autoWait()


bin_num = 0
func_num = 0
function_list_file = ""
function_list_fp = None
functions = []  # 윈도우 파일 이름이 대소문자를 구분하지 않으므로, 이미 분석된 함수 이름을 저장(모두 소문자로 변환하며 중복 시 현재 타임스탬프를 접미사로 추가)

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
    # print idc.GetDisasm(ea)
    while i <= 1:
        if (idc.GetOpType(ea, i) == 5):
            addr = idc.GetOperandValue(ea, i)
            if (idc.SegName(addr) == '.rodata') and (idc.GetType(addr) == 'char[]') and (i == 1):
                curStrNum = curStrNum + 1
            else:
                numeric = numeric + 1
        i = i + 1
    return numeric, curStrNum

# 기본 블록의 비구조적 특징 계산
def calBasicBlockFeature_vulseeker(block):
    StackNum = 0  # stackInstr
    MathNum = 0   # arithmeticInstr
    LogicNum = 0  # logicInstr
    CompareNum = 0  # compareInstr
    ExCallNum = 0  # externalInstr
    InCallNum = 0  # internalInstr
    ConJumpNum = 0  # conditionJumpInstr
    UnConJumpNum = 0  # unconditionJumpInstr
    GeneicNum = 0  # genericInstr
    curEA = block.startEA
    while curEA <= block.endEA:
        inst = idc.GetMnem(curEA)
        if inst in config_for_feature.VulSeeker_stackInstr:
            StackNum = StackNum + 1
        elif inst in config_for_feature.VulSeeker_arithmeticInstr:
            MathNum = MathNum + 1
        elif inst in config_for_feature.VulSeeker_logicInstr:
            LogicNum = LogicNum + 1
        elif inst in config_for_feature.VulSeeker_compareInstr:
            CompareNum = CompareNum + 1
        elif inst in config_for_feature.VulSeeker_externalInstr:
            ExCallNum = ExCallNum + 1
        elif inst in config_for_feature.VulSeeker_internalInstr:
            InCallNum = InCallNum + 1
        elif inst in config_for_feature.VulSeeker_conditionJumpInstr:
            ConJumpNum = ConJumpNum + 1
        elif inst in config_for_feature.VulSeeker_unconditionJumpInstr:
            UnConJumpNum = UnConJumpNum + 1
        else:
            GeneicNum = GeneicNum + 1

        curEA = idc.NextHead(curEA, block.endEA)

    fea_str = f"{StackNum},{MathNum},{LogicNum},{CompareNum},{ExCallNum},{ConJumpNum},{UnConJumpNum},{GeneicNum},"
    return fea_str

# 문자열 상수의 수, 숫자 상수의 수, 점프 명령어 수, 호출 수, 명령어 수, 산술 명령어 수
def calBasicBlockFeature_gemini(block):
    numericNum = 0
    stringNum = 0
    transferNum = 0
    callNum = 0
    InstrNum = 0
    arithNum = 0
    logicNum = 0
    curEA = block.startEA
    while curEA <= block.endEA:
        # 숫자 상수, 문자열 상수의 수
        numer, stri = calConstantNumber(curEA)
        numericNum += numer
        stringNum += stri
        # 점프 명령어의 수
        if idc.GetMnem(curEA) in config_for_feature.Gemini_allTransferInstr:
            transferNum += 1
        # 호출 명령어의 수
        if idc.GetMnem(curEA) == 'call':
            callNum += 1
        # 명령어 수
        InstrNum += 1
        # 산술 명령어의 수
        if idc.GetMnem(curEA) in config_for_feature.Gemini_arithmeticInstr:
            arithNum += 1
        # 논리 명령어
        if idc.GetMnem(curEA) in config_for_feature.Gemini_logicInstr:
            logicNum += 1

        curEA = idc.NextHead(curEA, block.endEA)

    fea_str = f"{numericNum},{stringNum},{transferNum},{callNum},{InstrNum},{arithNum},{logicNum},"
    return fea_str

def block_fea(allblock, fea_fp):
    for block in allblock:
        gemini_str = calBasicBlockFeature_gemini(block)
        vulseeker_str = calBasicBlockFeature_vulseeker(block)
        fea_str = f"{hex(block.startEA)},{gemini_str}{vulseeker_str}\n"
        fea_fp.write(fea_str)

def build_dfg(DG, IR_blocks):
    IR_blocks_dfg = IR_blocks
    # 모든 정의된 변수들의 집합
    # alldefinedvar = set()
    # 시작 노드
    startnode = ''
    linenum = 0
    for in_label, in_value in IR_blocks.items():
        linenum = 0
        addr = in_label.split(":")[1].strip()
        # addr="0x"+in_label.split(":")[1].strip()[2:].lstrip('0')
        # 기본 블록 구조체 초기화
        tempbbls = bbls()
        tempbbls.id = addr
        tempbbls.childnode = set()
        tempbbls.fathernode = set()
        # 사전: 좌변과 우변 기록
        tempbbls.defuse = {}
        # 사전: 정의된 변수와 사용된 변수의 초기 위치와 최종 위치
        tempbbls.defined = {}
        tempbbls.used = {}
        # 집합: 기본 블록 내에서 정의된 모든 변수 기록
        tempbbls.definedset = set()
        tempbbls.visited = False
        IR_blocks_dfg[addr] = tempbbls

        for i in in_value:
            linenum += 1
            # 각 줄의 코드를 분석
            # print i
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

            # 괄호가 없으면 단순한 대입으로 간주
            if '(' not in use and '[' not in use:
                IR_blocks_dfg[addr].defuse[define].add(use)
                if use not in tempbbls.used:
                    tempbbls.used[use] = [linenum, 0]
                else:
                    tempbbls.used[use][1] = linenum
            # 괄호 제거
            else:
                srclist = list(i)
                for i in range(len(srclist)):
                    if srclist[i] == ")" and srclist[i - 1] != ")":
                        tmp = srclist[0:i + 1][::-1]
                        for j in range(len(tmp)):
                            if tmp[j] == "(":
                                temps = "".join(srclist[i - j:i + 1])
                                if temps.count(')') == 1 and temps.count('(') == 1:
                                    temps = temps[1:-1]  # 괄호 제거
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
                                if temps.count(']') == 1 and temps.count(']') == 1:
                                    temps = temps[1:-1]  # 괄호 제거
                                    IR_blocks_dfg[addr].defuse[define].add(temps)
                                    if temps not in tempbbls.used:
                                        tempbbls.used[temps] = [linenum, 0]
                                    else:
                                        tempbbls.used[temps][1] = linenum
                                break

    # 시작 노드 찾기, 각 기본 블록에서 정의된 모든 변수를 기록
    cfg_nodes = DG.nodes()
    # print "CFG nodes find father ",len(cfg_nodes)
    # startnode = list(IR_blocks_dfg.keys())[0]
    startnode = None
    for addr, bbloks in IR_blocks_dfg.items():
        if ':' in addr:
            continue
        if len(cfg_nodes) == 1 or startnode is None:  # 하나의 기본 블록이거나, 전체 루프를 형성하는 경우
            startnode = addr
        # print addr,addr in cfg_nodes,IR_blocks_dfg[addr].fathernode
        if addr in cfg_nodes and len(IR_blocks_dfg[addr].fathernode) == 0:
            startnode = addr
        for definevar in IR_blocks_dfg[addr].defuse:
            IR_blocks_dfg[addr].definedset.add(definevar)
    # print "startnode	:",startnode
    if startnode is None:
        return nx.DiGraph()
    else:
        return gen_dfg(IR_blocks_dfg, startnode)

def gen_dfg(IR_blocks_dfg, startnode):
    # DFS 탐색
    res_graph = nx.DiGraph()
    # cur_step = 0
    stack_list = []
    visited = {}
    # v2는 두 번째로 방문해야 하지만 아직 방문하지 않은 것을 의미
    visited2 = {}
    # v3는 두 번 방문한 후 끝난 것을 의미
    visited3 = {}
    for key, val in IR_blocks_dfg.items():
        visited2[key] = set()
        visited3[key] = set()
    visitorder = []
    # print "Visit!!", startnode
    # print "startnode!!", startnode
    IR_blocks_dfg[startnode].visited = True
    visited[startnode] = '1'
    visitorder.append(startnode)
    stack_list.append(startnode)
    while len(stack_list) > 0:
        cur_node = stack_list[-1]
        next_nodes = set()
        if IR_blocks_dfg.has_key(cur_node):
            next_nodes = IR_blocks_dfg[cur_node].childnode
        # print len(stack_list),cur_node,"-->",next_nodes
        if len(next_nodes) == 0:  # 리프 노드는 되돌아가야 함
            stack_list.pop()
            visitorder.pop()
            # cur_step = cur_step - 1
        else:
            if (len(set(next_nodes) - set(visited.keys())) == 0) and len(next_nodes & visited2[cur_node]) == 0:
                # 모든 노드를 방문한 경우 되돌아가야 함
                stack_list.pop()
                visitorder.pop()

            else:
                for i in next_nodes:
                    if i not in visited or i in visited2[cur_node]:
                        fathernodes = set()
                        usevar = {}
                        defined = {}
                        if IR_blocks_dfg.has_key(i):
                            # 리스트: 부모 노드
                            fathernodes = IR_blocks_dfg[i].fathernode
                            # 사전: 기본 블록에서 사용된 변수와 출현 위치
                            usevar = IR_blocks_dfg[i].used
                            # 사전: 기본 블록에서 정의된 변수와 출현 위치
                            definevar = IR_blocks_dfg[i].defined
                        # 집합: 부모 노드에서 정의된 변수
                        fdefinevarset = set()
                        # 플래그: 부모 노드에서 변수를 찾았는지 여부
                        findflag = False
                        # 부모 노드에서 정의된 모든 변수들의 집합
                        allfdefinevarset = set()

                        for uvar in usevar:
                            # 이 변수가 자식 노드에서 정의되지 않았거나 사용 위치가 정의 위치보다 이전일 경우 부모 노드에서 찾음
                            if uvar not in definevar or usevar[uvar][0] < definevar[uvar][0]:
                                for fnode in fathernodes:
                                    fdefinevarset = set()
                                    if IR_blocks_dfg.has_key(fnode):
                                        fdefinevarset = IR_blocks_dfg[fnode].definedset
                                    allfdefinevarset |= fdefinevarset
                                    if uvar in fdefinevarset:
                                        res_graph.add_edge(fnode, i)
                                        print(fnode, '->', i, "변수:", uvar)
                                # 부모 노드의 부모까지 거슬러 올라가면서 데이터 의존성을 찾음
                                for j in range(len(visitorder)-1, -1, -1):
                                    visitednode = visitorder[j]
                                    temp_definedset = set()
                                    if IR_blocks_dfg.has_key(visitednode):
                                        temp_definedset = IR_blocks_dfg[visitednode].definedset
                                    if uvar in temp_definedset - allfdefinevarset:
                                        res_graph.add_edge(visitednode, i)
                                        allfdefinevarset |= temp_definedset
                                        print("fffff", visitednode, '->', i, "변수:", uvar)

                        visited[i] = '1'
                        visitorder.append(i)
                        if i in visited2[cur_node]:
                            visited2[cur_node].remove(i)
                            visited3[cur_node].add(i)
                        temp_childnode = set()
                        if IR_blocks_dfg.has_key(i):
                            temp_childnode = IR_blocks_dfg[i].childnode
                        visited2[cur_node] |= (set(temp_childnode) & set(visited)) - set(visited3[cur_node])
                        stack_list.append(i)
    return res_graph

def get_father_block(blocks, cur_block, yes_keys):
    # print "부모 블록 찾기", cur_block.label
    father_block = None
    for temp_block in blocks:
        # print temp_block.get_next(),"<>",cur_block.label
        if temp_block.get_next() is cur_block.label:
            father_block = temp_block
    if father_block is None:
        return None
    is_Exist = False
    for yes_label in yes_keys:
        # print father_block
        # print father_block.label
        if ((str(father_block.label) + "L")).split(' ')[0].endswith(yes_label):
            is_Exist = True
    if not is_Exist:
        # print "존재하지 않음", ((str(father_block.label) + "L")).split(' ')[0]
        father_block = get_father_block(blocks, father_block, yes_keys)
        return father_block
    else:
        # print "존재", ((str(father_block.label) + "L")).split(' ')[0]
        return father_block

def rebuild_graph(cur_block, blocks, IR_blocks, no_ir):
    # print ">> 그래프 재구성", len(no_ir)
    yes_keys = list(IR_blocks.keys())
    no_keys = list(no_ir.keys())
    next_lable = (str(cur_block.label) + "L").split(' ')[0]
    father_block = get_father_block(blocks, cur_block, yes_keys)
    if not father_block is None:
        for yes_label in yes_keys:
            if ((str(father_block.label) + "L")).split(' ')[0].endswith(yes_label):
                for no_label in no_keys:
                    # print "222", next_lable, no_label
                    if next_lable.endswith(no_label):
                        IR_blocks[yes_label].pop()
                        IR_blocks[yes_label].extend(IR_blocks[no_label])
                        # print "<<<삭제", no_label
                        # print "<<<길이", len(no_ir)
                        del (no_ir[no_label])
                        del (IR_blocks[no_label])
    return IR_blocks, no_ir

def dataflow_analysis(addr, block_items, DG):

    machine = guess_machine()
    mn, dis_engine, ira = machine.mn, machine.dis_engine, machine.ira
    #
    # print "아키텍처", dis_engine
    #
    # fname = idc.GetInputFile()
    # print "파일 이름 : ", fname
    # print "머신", machine

    bs = bin_stream_ida()
    mdis = dis_engine(bs)
    mdis.dont_dis_retcall_funcs = []
    mdis.dont_dis = []
    ir_arch = ira(mdis.symbol_pool)
    blocks = mdis.dis_multiblock(addr)
    for block in blocks:
        ir_arch.add_block(block)
        # print ">>어셈블리 블록", block

    IRs = {}
    for lbl, irblock in ir_arch.blocks.items():
        insr = []
        for assignblk in irblock:
            for dst, src in assignblk.iteritems():
                insr.append(str(dst) + "=" + str(src))
        # print ">>ir",(str(lbl)+"L"),insr
        IRs[str(lbl).split(' ')[0] + "L"] = insr
    # print "IRs.keys()", IRs.keys()

    IR_blocks = {}
    no_ir = {}
    # print "block_items", block_items
    for block in blocks:
        # print "block.label", block.label
        isFind = False
        item = str(block.label).split(' ')[0] + "L"
        # print "블록 줄 번호", item
        for block_item in block_items:
            if item.endswith(block_item):
                isFind = True

        if IRs.has_key(item):
            if isFind:
                IR_blocks[item] = IRs[item]
            else:
                IR_blocks[item] = IRs[item]
                no_ir[item] = IRs[item]
    # print "yes_ir : ", list(IR_blocks.keys())
    no_keys = list(no_ir.keys())
    # print "no_ir : ", no_keys
    for cur_label in no_keys:
        cur_block = None
        # print "no_ir 라벨 찾기 : ", cur_label
        for block in blocks:
            # loc_0000000000413D4C:0x00413d4cL callXXX 제거
            temp_index = str(block.label).split(' ')[0] + "L"
            if temp_index.endswith(cur_label):
                cur_block = block
        if not cur_block is None:
            # print "no_ir 찾음", cur_block
            IR_blocks, no_ir = rebuild_graph(cur_block, blocks, IR_blocks, no_ir)
    # print len(no_ir)
    
    IR_blocks_toDFG = {}
    for key, value in IR_blocks.items():
        if len(key.split(':')) > 1:
            key = key.split(':')[0] + ":0x" + key.split(':')[1].strip()[2:].lstrip('0')
        IR_blocks_toDFG[key] = value
    dfg = build_dfg(DG, IR_blocks_toDFG)
    dfg.add_nodes_from(DG.nodes())
    print("CFG 엣지 <<", DG.number_of_edges(), ">> :", DG.edges())
    print("DFG 엣지 <<", dfg.number_of_edges(), ">> :", dfg.edges())
    print("DFG 노드 : ", dfg.number_of_nodes())
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

    print("디렉토리 경로 : ", fea_path_origion)
    function_list_file = fea_path_origion + os.sep + "functions_list_fea.csv"
    function_list_fp = open(function_list_file, 'w')  # 추가 모드로 엶

    textStartEA = 0
    textEndEA = 0
    for seg in idautils.Segments():
        if idc.SegName(seg) == ".text":
            textStartEA = idc.SegStart(seg)
            textEndEA = idc.SegEnd(seg)
            break

    # 파일의 모든 명령어를 순회하고 파일에 저장
    # 명령어 주소와 명령어 ID를 일대일로 대응시키는 dict 생성
    print("모든 명령어를 순회하며 instDict, inst_info 생성")
    for func in idautils.Functions(textStartEA, textEndEA):
        # 라이브러리 코드는 무시
        flags = idc.GetFunctionFlags(func)
        if flags & idc.FUNC_LIB:
            print(hex(func), "FUNC_LIB", idc.GetFunctionName(func))
            continue

        cur_function_name = idc.GetFunctionName(func)
        print(cur_function_name)
        # if cur_function_name != "X509_NAME_get_text_by_NID":
        #    continue
        
        fea_path = fea_path_origion
        if cur_function_name.lower() in functions:
            fea_path = fea_path_temp
            if not os.path.exists(fea_path):
                os.mkdir(fea_path)
            # cur_function_name = cur_function_name + "_" + time.strftime('%Y%m%d%H%M%S',time.localtime(time.time()))
        functions.append(cur_function_name.lower())
        print(cur_function_name, "===== 시작")  # 함수 이름 출력

        ''' 
            함수의 제어 흐름 정보 기록, CFG(제어 흐름 그래프) 인접 리스트 생성
            각 txt 파일에는 함수의 제어 흐름 그래프가 저장됨, 파일 이름 형식: [함수명_cfg.txt]
            # a b c  # a-b a-c
            # d e  # d-e
            # G = nx.read_adjlist(‘test.adjlist’)
        '''
        allblock = idaapi.FlowChart(idaapi.get_func(func))
        cfg_file = fea_path + os.sep + str(cur_function_name) + "_cfg.txt"
        cfg_fp = open(cfg_file, 'w')
        block_items = []
        DG = nx.DiGraph()
        for idaBlock in allblock:
            temp_str = str(hex(idaBlock.startEA))
            block_items.append(temp_str[2:])
            DG.add_node(hex(idaBlock.startEA))
            for succ_block in idaBlock.succs():
                DG.add_edge(hex(idaBlock.startEA), hex(succ_block.startEA))
            for pred_block in idaBlock.preds():
                DG.add_edge(hex(pred_block.startEA), hex(idaBlock.startEA))

        for cfg_node in DG.nodes():
            cfg_str = str(cfg_node)
            for edge in DG.succ[cfg_node]:
                cfg_str = cfg_str + " " + edge
            cfg_str = cfg_str + "\n"
            cfg_fp.write(cfg_str)

        '''
            함수의 데이터 흐름 정보를 기록하고 DFG(데이터 흐름 그래프) 인접 리스트 생성
            각 txt 파일에는 함수의 데이터 흐름 그래프가 저장됨, 파일 이름 형식: [함수명_dfg.txt]
            # a b c  # a-b a-c
            # d e  # d-e
            # G = nx.read_adjlist(‘test.adjlist’)
        '''
        dfg = dataflow_analysis(func, block_items, DG)
        dfg_file = fea_path + os.sep + str(cur_function_name) + "_dfg.txt"
        dfg_fp = open(dfg_file, 'w')
        for dfg_node in dfg.nodes():
            dfg_str = dfg_node
            for edge in dfg.succ[dfg_node]:
                dfg_str = dfg_str + " " + edge
            dfg_str = dfg_str + "\n"
            dfg_fp.write(dfg_str)

        '''
            함수의 기본 블록 정보를 기록하고, 각 기본 블록의 특징을 추출
            각 함수는 CSV 파일로 저장됨, 파일 이름 형식: [함수명_fea.csv]
            # 스택, 산술 연산, 논리 연산, 비교 연산, 외부 호출, 내부 호출, 조건부 점프, 무조건 점프, 일반 명령어
        '''
        fea_file = fea_path + os.sep + str(cur_function_name) + "_fea.csv"
        fea_fp = open(fea_file, 'w')
        block_fea(allblock, fea_fp)

        '''
            함수의 원시 디스어셈블리 명령어 기록
        orig_file = fea_path + os.sep + str(cur_function_name) + "_origion_instruction_info.csv"
        orig_fp = open(orig_file, 'w')
        inst_file = fea_path + os.sep + str(cur_function_name) + "_instruction_info.csv"
        inst_fp = open(inst_file, 'w')
        for instru in idautils.FuncItems(func):
            orig_fp.write(hex(instru) + "," + idc.GetDisasm(instru) + "\n")
            inst_fp.write(idc.GetMnem(instru) + "\n")
        '''

        '''
            함수 요약 정보 기록: 함수명, 경로, 기본 블록 수, 제어 흐름 엣지 수, 데이터 흐름 엣지 수
        '''
        print(cur_function_name, "===== 완료")  # 함수 이름 출력
        # 함수명, 기본 블록 수, 데이터 흐름 노드 수, 제어 흐름 엣지 수, 데이터 흐름 엣지 수, 프로그램명, 버전, 바이너리 경로
        function_str = str(cur_function_name) + "," + str(DG.number_of_nodes()) + "," + \
                       str(DG.number_of_edges()) + "," + str(dfg.number_of_edges()) + "," + \
                       str(program) + "," + str(version) + "," + str(bin_path) + ",\n"
        function_list_fp.write(function_str)
    return

#redirect output into a file, original output is the console.
def stdout_to_file(output_file_name, output_dir=None):
	if not output_dir:
		output_dir = os.path.dirname(os.path.realpath(__file__))
	output_file_path = os.path.join(output_dir, output_file_name)
	print output_file_path
	print "original output start"
	# save original stdout descriptor
	orig_stdout = sys.stdout
	# create output file
	f = file(output_file_path, "w")
	# set stdout to output file descriptor
	sys.stdout = f
	return f, orig_stdout


if __name__=='__main__':
	f, orig_stdout = stdout_to_file("output_"+time.strftime('%Y%m%d%H%M%S',time.localtime(time.time()))+".txt")
	main()
	print "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
	sys.stdout = orig_stdout #recover the output to the console window
	f.close()

	idc.Exit(0)
