from binaryninja.architecture import Architecture, ArchitectureHook, Endianness
from binaryninja.enums import Endianness
from binaryninja import (
    Architecture, RegisterInfo, InstructionInfo,
    InstructionTextToken, InstructionTextTokenType,
    BranchType,
    LowLevelILOperation, LLIL_TEMP,
    LowLevelILLabel,
    FlagRole,
    LowLevelILFlagCondition,
    log_error,
    CallingConvention)
import sys
import cffi
import os

def cond_branch(il, cond, dest):
    t = None
    if il[dest].operation == LowLevelILOperation.LLIL_CONST:
        t = il.get_label_for_address(Architecture['ppc_vle'], il[dest].constant)
    if t is None:
        t = LowLevelILLabel()
        indirect = True
    else:
        indirect = False
    f = LowLevelILLabel()
    il.append(il.if_expr(cond, t, f))
    if indirect:
        il.mark_label(t)
        il.append(il.jump(dest))
    il.mark_label(f)
    return None

class PPCVLE(Architecture):
    name = 'ppc_vle'
    address_size = 4
    default_int_size = 4
    max_instr_length = 4
    instr_alignment = 2
    stack_pointer = Architecture['ppc'].stack_pointer
    link_reg = Architecture['ppc'].link_reg
    endianness = Endianness.BigEndian
    regs = Architecture['ppc'].regs
    full_width_regs = Architecture['ppc'].full_width_regs
    flags = Architecture['ppc'].flags
    flag_roles = Architecture['ppc'].flag_roles
    flag_write_types = Architecture['ppc'].flag_write_types
# ['none', 'cr0_signed', 'cr1_signed', 'cr2_signed', 'cr3_signed',
# 'cr4_signed', 'cr5_signed', 'cr6_signed', 'cr7_signed', 'cr0_unsigned',
# 'cr1_unsigned', 'cr2_unsigned', 'cr3_unsigned', 'cr4_unsigned',
# 'cr5_unsigned', 'cr6_unsigned', 'cr7_unsigned', 'xer', 'xer_ca', 'xer_ov_so',
# 'mtcr0', 'mtcr1', 'mtcr2', 'mtcr3', 'mtcr4', 'mtcr5', 'mtcr6', 'mtcr7',
# 'invl0', 'invl1', 'invl2', 'invl3', 'invl4', 'invl5', 'invl6', 'invl7',
# 'invall']
    flags_written_by_flag_write_type = Architecture['ppc'].flags_written_by_flag_write_type
    flags_required_for_flag_condition = Architecture['ppc'].flags_required_for_flag_condition

    def __init__(self):
        libvle_dir = os.path.join(os.path.dirname(__file__), 'libvle')
        self.ffi = cffi.FFI()

        # with open(os.path.join(libvle_dir, 'vle.c')) as c_source:
        #     self.ffi.set_source('_libvle', c_source.read())
        self.ffi.cdef("""
            enum field_type {
                TYPE_NONE = 0,
                TYPE_REG  = 1,
                TYPE_IMM  = 2,
                TYPE_MEM  = 3,
                TYPE_JMP  = 4,
                TYPE_CR   = 5
            };

            enum op_type {
                OP_TYPE_ILL,

                OP_TYPE_ADD,
                OP_TYPE_SUB,
                OP_TYPE_MUL,
                OP_TYPE_DIV,
                OP_TYPE_SHR,
                OP_TYPE_SHL,
                OP_TYPE_ROR,

                OP_TYPE_AND,
                OP_TYPE_OR,
                OP_TYPE_XOR,
                OP_TYPE_NOR,
                OP_TYPE_NOT,

                OP_TYPE_IO,
                OP_TYPE_LOAD,
                OP_TYPE_STORE,
                OP_TYPE_MOV,

                OP_TYPE_CMP,
                OP_TYPE_JMP,
                OP_TYPE_CJMP,
                OP_TYPE_CALL,
                OP_TYPE_CCALL,
                OP_TYPE_RJMP,
                OP_TYPE_RCALL,
                OP_TYPE_RET,

                OP_TYPE_SYNC,
                OP_TYPE_SWI,
                OP_TYPE_TRAP
            };

            enum op_condition {
                COND_AL,
                COND_GE,
                COND_LE,
                COND_NE,
                COND_VC,
                COND_LT,
                COND_GT,
                COND_EQ,
                COND_VS,
                COND_NV
            };

            typedef struct {
                const uint8_t* end;
                const uint8_t* pos;
                uint16_t inc;
            } vle_handle;

            typedef struct {
                uint32_t value;
                enum field_type type;
            } vle_field_t;

            typedef struct {
                const char* name;
                vle_field_t fields[10];
                uint16_t n;
                uint16_t size;
                enum op_type op_type;
                enum op_condition cond;
            } vle_t;

            int vle_init(vle_handle* handle, const uint8_t* buffer, const uint32_t size);
            int vle_next(vle_handle* handle, vle_t* out);
            void vle_snprint(char* str, int size, uint64_t addr, vle_t* instr);
            """)
        # self.ffi.compile(verbose=True)
        self.libvle = self.ffi.dlopen(os.path.join(libvle_dir, 'libvle.so'))
        self.vle_handle = self.ffi.new('vle_handle*')
        return super(PPCVLE, self).__init__()


    def get_instruction_text(self, data, addr):
        ffi = self.ffi
        libvle = self.libvle
        vle_handle = self.vle_handle
        vle_instr = ffi.new('vle_t*')

        data_len = len(data[0:4])
        data_buf = ffi.new('char[]', data[0:4])
        return_code = libvle.vle_init(vle_handle, data_buf, data_len)
        decoding_success = libvle.vle_next(vle_handle, vle_instr);
        if not decoding_success or vle_instr.name == ffi.NULL:
            return None
        instr_name = ffi.string(vle_instr.name)

        FieldTypeToText = {
            libvle.TYPE_REG: lambda f, _, _2: [InstructionTextToken(InstructionTextTokenType.RegisterToken, 'r'+str(f))],
            libvle.TYPE_IMM: lambda f, _, _2: [InstructionTextToken(InstructionTextTokenType.IntegerToken, hex(f), f)],
            libvle.TYPE_MEM: lambda f, fp, _: [
                InstructionTextToken(InstructionTextTokenType.IntegerToken, hex(fp), fp),
                InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, '('),
                InstructionTextToken(InstructionTextTokenType.RegisterToken, 'r'+str(f)),
                InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ')'),
            ],
            libvle.TYPE_JMP: lambda f, _, address: [InstructionTextToken(InstructionTextTokenType.IntegerToken, hex(f+address), f+address)],
            libvle.TYPE_CR: lambda f, _, _2: [InstructionTextToken(InstructionTextTokenType.RegisterToken, 'cr'+str(f))],
        }

        tokens = [InstructionTextToken(InstructionTextTokenType.TextToken, '{:11s}'.format(instr_name))]
        loop = iter(xrange(vle_instr.n))
        for i in loop:
            f = vle_instr.fields[i]
            if f.type in FieldTypeToText:
                tokens += FieldTypeToText[f.type](f.value, vle_instr.fields[i+1].value, addr);
                tokens += [InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ', ')]
            if f.type == libvle.TYPE_MEM:
                next(loop)

        if len(tokens) > 1:
            return tokens[:-1], vle_instr.size
        return tokens, vle_instr.size

    def get_instruction_info(self, data, addr):
        ffi = self.ffi
        libvle = self.libvle
        vle_handle = self.vle_handle
        vle_instr = ffi.new('vle_t*')

        data_len = len(data[0:4])
        data_buf = ffi.new('char[]', data[0:4])
        return_code = libvle.vle_init(vle_handle, data_buf, data_len)
        decoding_success = libvle.vle_next(vle_handle, vle_instr);
        if not decoding_success or vle_instr.name == ffi.NULL:
            return None

        result = InstructionInfo()
        result.length = vle_instr.size

        if vle_instr.op_type == libvle.OP_TYPE_JMP:
            result.add_branch(BranchType.UnconditionalBranch, vle_instr.fields[0].value + addr)
        elif vle_instr.op_type == libvle.OP_TYPE_CJMP:
            result.add_branch(BranchType.TrueBranch, vle_instr.fields[0].value + addr)
            result.add_branch(BranchType.FalseBranch, result.length + addr)
        elif vle_instr.op_type == libvle.OP_TYPE_CALL:
            result.add_branch(BranchType.CallDestination, vle_instr.fields[0].value + addr)
        elif vle_instr.op_type == libvle.OP_TYPE_CCALL:
            result.add_branch(BranchType.FalseBranch, result.length + addr)
            result.add_branch(BranchType.CallDestination, vle_instr.fields[0].value + addr)
        elif vle_instr.op_type == libvle.OP_TYPE_RJMP:
            result.add_branch(BranchType.IndirectBranch)
        elif vle_instr.op_type == libvle.OP_TYPE_RCALL:
            result.add_branch(BranchType.CallDestination)
        elif vle_instr.op_type == libvle.OP_TYPE_RET:
            result.add_branch(BranchType.FunctionReturn)
        elif vle_instr.op_type == libvle.OP_TYPE_SWI:
            result.add_branch(BranchType.SystemCall)
        elif vle_instr.op_type == libvle.OP_TYPE_TRAP:
            result.add_branch(BranchType.SystemCall)

        return result

    def get_instruction_low_level_il(self, data, addr, il):
        ffi = self.ffi
        libvle = self.libvle
        vle_handle = self.vle_handle
        vle_instr = ffi.new('vle_t*')

        data_len = len(data[0:4])
        data_buf = ffi.new('char[]', data[0:4])
        return_code = libvle.vle_init(vle_handle, data_buf, data_len)
        decoding_success = libvle.vle_next(vle_handle, vle_instr);
        # instr_name = ffi.string(instr.name)
        if not decoding_success or vle_instr.name == ffi.NULL or vle_instr.op_type == libvle.OP_TYPE_ILL:
            return None

        instr_name = ffi.string(vle_instr.name)

        should_update_flags = instr_name[-1] == '.'
        flags_to_update = 'none'
        if should_update_flags:
            flags_to_update = 'cr0_signed'
            instr_name = instr_name[:-1]

        libvle_cond_to_llil_cond = {
            libvle.COND_GE: LowLevelILFlagCondition.LLFC_SGE,
            libvle.COND_LE: LowLevelILFlagCondition.LLFC_SLE,
            libvle.COND_NE: LowLevelILFlagCondition.LLFC_NE,
            libvle.COND_VC: LowLevelILFlagCondition.LLFC_NO,
            libvle.COND_LT: LowLevelILFlagCondition.LLFC_SLT,
            libvle.COND_GT: LowLevelILFlagCondition.LLFC_SGT,
            libvle.COND_EQ: LowLevelILFlagCondition.LLFC_E,
            libvle.COND_VS: LowLevelILFlagCondition.LLFC_O
        }

        if vle_instr.op_type == libvle.OP_TYPE_SYNC:
            il.append(il.nop())
        elif vle_instr.op_type == libvle.OP_TYPE_RET:
            il.append(il.ret(il.reg(4, self.link_reg)))
        elif vle_instr.op_type == libvle.OP_TYPE_JMP:
            il.append(il.jump(il.const_pointer(4, vle_instr.fields[0].value + addr)))
        elif vle_instr.op_type == libvle.OP_TYPE_CALL:
            il.append(il.call(il.const_pointer(4, vle_instr.fields[0].value + addr)))
        elif instr_name == 'se_mtctr':
            il.append(il.set_reg(4, 'ctr', il.reg(4, 'r'+str(vle_instr.fields[0].value))))
        elif instr_name == 'se_mfctr':
            il.append(il.set_reg(4, 'r'+str(vle_instr.fields[0].value), il.reg(4, 'ctr')))
        elif instr_name == 'se_mflr':
            src_reg = 'r'+str(vle_instr.fields[0].value)
            il.append(il.set_reg(4, src_reg, il.reg(4, self.link_reg)))
        elif instr_name == 'se_mtlr':
            src_reg = 'r'+str(vle_instr.fields[0].value)
            il.append(il.set_reg(4, self.link_reg, il.reg(4, src_reg)))
        elif instr_name == 'se_mtspr':
            il.append(il.set_reg(4, 'ctr', il.reg(4, 'r'+str(vle_instr.fields[0].value))))
        elif instr_name == 'se_mfspr':
            il.append(il.set_reg(4, 'r'+str(vle_instr.fields[0].value), il.reg(4, 'ctr')))
        elif instr_name == 'se_bctr':
            il.append(il.jump(il.reg(4, 'ctr')))
        elif instr_name == 'se_bctrl':
            il.append(il.call(il.reg(4, 'ctr')))
        elif instr_name == 'e_lis':
            il.append(il.set_reg(4, 'r'+str(vle_instr.fields[0].value), il.const(4, vle_instr.fields[1].value << 16)))
        elif instr_name == 'se_li':
            il.append(il.set_reg(4, 'r'+str(vle_instr.fields[0].value), il.const(4, vle_instr.fields[1].value)))
        elif instr_name == 'se_mr':
            il.append(il.set_reg(4, 'r'+str(vle_instr.fields[0].value), il.reg(4, 'r'+str(vle_instr.fields[1].value))))
        elif instr_name == 'add':
            dst_reg = 'r'+str(vle_instr.fields[0].value)
            src_reg = 'r'+str(vle_instr.fields[1].value)
            src_2 = 'r'+str(vle_instr.fields[2].value)
            il.append(il.set_reg(4, dst_reg, il.add(4, il.reg(4, src_reg), il.reg(4, src_2))))
        elif instr_name == 'se_add':
            dst_reg = 'r'+str(vle_instr.fields[0].value)
            src_reg = 'r'+str(vle_instr.fields[1].value)
            il.append(il.set_reg(4, dst_reg, il.add(4, il.reg(4, src_reg), il.reg(4, dst_reg))))
        elif instr_name == 'e_add2i':
            src_reg = 'r'+str(vle_instr.fields[0].value)
            il.append(il.set_reg(4, src_reg, il.add(4, il.reg(4, src_reg), il.const(4, vle_instr.fields[1].value), flags=flags_to_update)))
        elif instr_name == 'e_add2is':
            src_reg = 'r'+str(vle_instr.fields[0].value)
            il.append(il.set_reg(4, src_reg, il.add(4, il.reg(4, src_reg), il.const(4, vle_instr.fields[1].value << 16), flags=flags_to_update)))
        elif instr_name == 'e_add16i':
            dst_reg = 'r'+str(vle_instr.fields[0].value)
            src_reg = 'r'+str(vle_instr.fields[1].value)
            il.append(il.set_reg(4, dst_reg, il.add(4, il.reg(4, src_reg), il.const(4, vle_instr.fields[2].value), flags=flags_to_update)))
        elif instr_name in ['se_bge', 'se_ble', 'se_bne', 'se_bns', 'se_blt', 'se_bgt', 'se_beq', 'se_bso', 'se_bc']:
            branch_target = il.const(4, vle_instr.fields[0].value + addr)
            cond = il.flag_condition(libvle_cond_to_llil_cond[vle_instr.cond])
            cond_branch(il, cond, branch_target)
        elif instr_name in ["e_bgectr", "e_blectr", "e_bnectr", "e_bnsctr", "e_bltctr", "e_bgtctr", "e_beqctr", "e_bsoctr", "e_bcctr"]:
            branch_target = il.reg(4, 'ctr')
            cond = il.flag_condition(libvle_cond_to_llil_cond[vle_instr.cond])
            cond_branch(il, cond, branch_target)
        elif instr_name == 'e_crxor':
            dst_reg = 'r'+str(vle_instr.fields[0].value)
            src_1 = 'r'+str(vle_instr.fields[1].value)
            src_2 = 'r'+str(vle_instr.fields[2].value)
            il.append(il.set_reg(4, dst_reg, il.xor_expr(4, il.reg(4, src_1), il.reg(4, src_2), flags='cr0_unsigned')))
        elif instr_name == 'se_subf':
            dst_reg = 'r'+str(vle_instr.fields[0].value)
            src_reg = 'r'+str(vle_instr.fields[1].value)
            il.append(il.set_reg(4, dst_reg, il.sub(4, il.reg(4, src_reg), il.reg(4, dst_reg))))
        elif instr_name == 'se_bgeni':
            dst_reg = 'r'+str(vle_instr.fields[0].value)
            constant = 0x80000000 >> vle_instr.fields[1].value
            il.append(il.set_reg(4, dst_reg, il.const(4, constant)))
        elif instr_name == 'e_lwz':
            dst_reg = 'r'+str(vle_instr.fields[0].value)
            offset = vle_instr.fields[2].value
            base_reg = 'r'+str(vle_instr.fields[1].value)
            il.append(il.set_reg(4, dst_reg, il.load(4, il.add(4, il.reg(4, base_reg), il.const(4, offset)))))
        elif instr_name == 'se_srwi':
            il.append(il.unimplemented())
        elif instr_name == 'se_sub':
            il.append(il.unimplemented())
        elif instr_name == 'e_or2i':
            il.append(il.unimplemented())
        else:
            il.append(il.unimplemented())
        # il.append(il.unimplemented())

        return vle_instr.size

PPCVLE.register()
