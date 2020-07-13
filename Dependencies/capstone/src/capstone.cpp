#include <capstone/capstone.h>

struct Data
{
	cs_arch arch;
	cs_mode mode;
};

CAPSTONE_EXPORT cs_err CAPSTONE_API cs_open(cs_arch arch, cs_mode mode, csh* handle)
{
	auto data = new Data;
	data->arch = arch;
	data->mode = mode;
	*handle = (size_t)data;
	return cs_err::CS_ERR_OK;
}

CAPSTONE_EXPORT cs_err CAPSTONE_API cs_option(csh handle, cs_opt_type type, size_t value)
{
	return cs_err::CS_ERR_OK;
}

CAPSTONE_EXPORT
size_t CAPSTONE_API cs_disasm(csh handle,
	const uint8_t* code, size_t code_size,
	uint64_t address,
	size_t count,
	cs_insn** insn)
{
	return 0;
}

void CAPSTONE_API cs_free(cs_insn* insn, size_t count)
{
}

const char* CAPSTONE_API cs_reg_name(csh handle, unsigned int reg_id)
{
	auto data = (Data*)handle;
	if (data->arch == cs_arch::CS_ARCH_X86)
	{
		switch (reg_id)
		{
		case X86_REG_AH: return "ah";
		case X86_REG_AL: return "al";
		case X86_REG_AX: return "ax";
		case X86_REG_BH: return "bh";
		case X86_REG_BL: return "bl";
		case X86_REG_BP: return "bp";
		case X86_REG_BPL: return "bpl";
		case X86_REG_BX: return "bx";
		case X86_REG_CH: return "ch";
		case X86_REG_CL: return "cl";
		case X86_REG_CS: return "cs";
		case X86_REG_CX: return "cx";
		case X86_REG_DH: return "dh";
		case X86_REG_DI: return "di";
		case X86_REG_DIL: return "dil";
		case X86_REG_DL: return "dl";
		case X86_REG_DS: return "ds";
		case X86_REG_DX: return "dx";
		case X86_REG_EAX: return "eax";
		case X86_REG_EBP: return "ebp";
		case X86_REG_EBX: return "ebx";
		case X86_REG_ECX: return "ecx";
		case X86_REG_EDI: return "edi";
		case X86_REG_EDX: return "edx";
		case X86_REG_EFLAGS: return "eflags";
		case X86_REG_EIP: return "eip";
		case X86_REG_EIZ: return "eiz";
		case X86_REG_ES: return "es";
		case X86_REG_ESI: return "esi";
		case X86_REG_ESP: return "esp";
		case X86_REG_FPSW: return "fpsw";
		case X86_REG_FS: return "fs";
		case X86_REG_GS: return "gs";
		case X86_REG_IP: return "ip";
		case X86_REG_RAX: return "rax";
		case X86_REG_RBP: return "rbp";
		case X86_REG_RBX: return "rbx";
		case X86_REG_RCX: return "rcx";
		case X86_REG_RDI: return "rdi";
		case X86_REG_RDX: return "rdx";
		case X86_REG_RIP: return "rip";
		case X86_REG_RIZ: return "riz";
		case X86_REG_RSI: return "rsi";
		case X86_REG_RSP: return "rsp";
		case X86_REG_SI: return "si";
		case X86_REG_SIL: return "sil";
		case X86_REG_SP: return "sp";
		case X86_REG_SPL: return "spl";
		case X86_REG_SS: return "ss";
		case X86_REG_CR0: return "cr0";
		case X86_REG_CR1: return "cr1";
		case X86_REG_CR2: return "cr2";
		case X86_REG_CR3: return "cr3";
		case X86_REG_CR4: return "cr4";
		case X86_REG_CR5: return "cr5";
		case X86_REG_CR6: return "cr6";
		case X86_REG_CR7: return "cr7";
		case X86_REG_CR8: return "cr8";
		case X86_REG_CR9: return "cr9";
		case X86_REG_CR10: return "cr10";
		case X86_REG_CR11: return "cr11";
		case X86_REG_CR12: return "cr12";
		case X86_REG_CR13: return "cr13";
		case X86_REG_CR14: return "cr14";
		case X86_REG_CR15: return "cr15";
		case X86_REG_DR0: return "dr0";
		case X86_REG_DR1: return "dr1";
		case X86_REG_DR2: return "dr2";
		case X86_REG_DR3: return "dr3";
		case X86_REG_DR4: return "dr4";
		case X86_REG_DR5: return "dr5";
		case X86_REG_DR6: return "dr6";
		case X86_REG_DR7: return "dr7";
		case X86_REG_DR8: return "dr8";
		case X86_REG_DR9: return "dr9";
		case X86_REG_DR10: return "dr10";
		case X86_REG_DR11: return "dr11";
		case X86_REG_DR12: return "dr12";
		case X86_REG_DR13: return "dr13";
		case X86_REG_DR14: return "dr14";
		case X86_REG_DR15: return "dr15";
		case X86_REG_FP0: return "fp0";
		case X86_REG_FP1: return "fp1";
		case X86_REG_FP2: return "fp2";
		case X86_REG_FP3: return "fp3";
		case X86_REG_FP4: return "fp4";
		case X86_REG_FP5: return "fp5";
		case X86_REG_FP6: return "fp6";
		case X86_REG_FP7: return "fp7";
		case X86_REG_K0: return "k0";
		case X86_REG_K1: return "k1";
		case X86_REG_K2: return "k2";
		case X86_REG_K3: return "k3";
		case X86_REG_K4: return "k4";
		case X86_REG_K5: return "k5";
		case X86_REG_K6: return "k6";
		case X86_REG_K7: return "k7";
		case X86_REG_MM0: return "mm0";
		case X86_REG_MM1: return "mm1";
		case X86_REG_MM2: return "mm2";
		case X86_REG_MM3: return "mm3";
		case X86_REG_MM4: return "mm4";
		case X86_REG_MM5: return "mm5";
		case X86_REG_MM6: return "mm6";
		case X86_REG_MM7: return "mm7";
		case X86_REG_R8: return "r8";
		case X86_REG_R9: return "r9";
		case X86_REG_R10: return "r10";
		case X86_REG_R11: return "r11";
		case X86_REG_R12: return "r12";
		case X86_REG_R13: return "r13";
		case X86_REG_R14: return "r14";
		case X86_REG_R15: return "r15";
		case X86_REG_ST0: return "st0";
		case X86_REG_ST1: return "st1";
		case X86_REG_ST2: return "st2";
		case X86_REG_ST3: return "st3";
		case X86_REG_ST4: return "st4";
		case X86_REG_ST5: return "st5";
		case X86_REG_ST6: return "st6";
		case X86_REG_ST7: return "st7";
		case X86_REG_XMM0: return "xmm0";
		case X86_REG_XMM1: return "xmm1";
		case X86_REG_XMM2: return "xmm2";
		case X86_REG_XMM3: return "xmm3";
		case X86_REG_XMM4: return "xmm4";
		case X86_REG_XMM5: return "xmm5";
		case X86_REG_XMM6: return "xmm6";
		case X86_REG_XMM7: return "xmm7";
		case X86_REG_XMM8: return "xmm8";
		case X86_REG_XMM9: return "xmm9";
		case X86_REG_XMM10: return "xmm10";
		case X86_REG_XMM11: return "xmm11";
		case X86_REG_XMM12: return "xmm12";
		case X86_REG_XMM13: return "xmm13";
		case X86_REG_XMM14: return "xmm14";
		case X86_REG_XMM15: return "xmm15";
		case X86_REG_XMM16: return "xmm16";
		case X86_REG_XMM17: return "xmm17";
		case X86_REG_XMM18: return "xmm18";
		case X86_REG_XMM19: return "xmm19";
		case X86_REG_XMM20: return "xmm20";
		case X86_REG_XMM21: return "xmm21";
		case X86_REG_XMM22: return "xmm22";
		case X86_REG_XMM23: return "xmm23";
		case X86_REG_XMM24: return "xmm24";
		case X86_REG_XMM25: return "xmm25";
		case X86_REG_XMM26: return "xmm26";
		case X86_REG_XMM27: return "xmm27";
		case X86_REG_XMM28: return "xmm28";
		case X86_REG_XMM29: return "xmm29";
		case X86_REG_XMM30: return "xmm30";
		case X86_REG_XMM31: return "xmm31";
		case X86_REG_YMM0: return "ymm0";
		case X86_REG_YMM1: return "ymm1";
		case X86_REG_YMM2: return "ymm2";
		case X86_REG_YMM3: return "ymm3";
		case X86_REG_YMM4: return "ymm4";
		case X86_REG_YMM5: return "ymm5";
		case X86_REG_YMM6: return "ymm6";
		case X86_REG_YMM7: return "ymm7";
		case X86_REG_YMM8: return "ymm8";
		case X86_REG_YMM9: return "ymm9";
		case X86_REG_YMM10: return "ymm10";
		case X86_REG_YMM11: return "ymm11";
		case X86_REG_YMM12: return "ymm12";
		case X86_REG_YMM13: return "ymm13";
		case X86_REG_YMM14: return "ymm14";
		case X86_REG_YMM15: return "ymm15";
		case X86_REG_YMM16: return "ymm16";
		case X86_REG_YMM17: return "ymm17";
		case X86_REG_YMM18: return "ymm18";
		case X86_REG_YMM19: return "ymm19";
		case X86_REG_YMM20: return "ymm20";
		case X86_REG_YMM21: return "ymm21";
		case X86_REG_YMM22: return "ymm22";
		case X86_REG_YMM23: return "ymm23";
		case X86_REG_YMM24: return "ymm24";
		case X86_REG_YMM25: return "ymm25";
		case X86_REG_YMM26: return "ymm26";
		case X86_REG_YMM27: return "ymm27";
		case X86_REG_YMM28: return "ymm28";
		case X86_REG_YMM29: return "ymm29";
		case X86_REG_YMM30: return "ymm30";
		case X86_REG_YMM31: return "ymm31";
		case X86_REG_ZMM0: return "zmm0";
		case X86_REG_ZMM1: return "zmm1";
		case X86_REG_ZMM2: return "zmm2";
		case X86_REG_ZMM3: return "zmm3";
		case X86_REG_ZMM4: return "zmm4";
		case X86_REG_ZMM5: return "zmm5";
		case X86_REG_ZMM6: return "zmm6";
		case X86_REG_ZMM7: return "zmm7";
		case X86_REG_ZMM8: return "zmm8";
		case X86_REG_ZMM9: return "zmm9";
		case X86_REG_ZMM10: return "zmm10";
		case X86_REG_ZMM11: return "zmm11";
		case X86_REG_ZMM12: return "zmm12";
		case X86_REG_ZMM13: return "zmm13";
		case X86_REG_ZMM14: return "zmm14";
		case X86_REG_ZMM15: return "zmm15";
		case X86_REG_ZMM16: return "zmm16";
		case X86_REG_ZMM17: return "zmm17";
		case X86_REG_ZMM18: return "zmm18";
		case X86_REG_ZMM19: return "zmm19";
		case X86_REG_ZMM20: return "zmm20";
		case X86_REG_ZMM21: return "zmm21";
		case X86_REG_ZMM22: return "zmm22";
		case X86_REG_ZMM23: return "zmm23";
		case X86_REG_ZMM24: return "zmm24";
		case X86_REG_ZMM25: return "zmm25";
		case X86_REG_ZMM26: return "zmm26";
		case X86_REG_ZMM27: return "zmm27";
		case X86_REG_ZMM28: return "zmm28";
		case X86_REG_ZMM29: return "zmm29";
		case X86_REG_ZMM30: return "zmm30";
		case X86_REG_ZMM31: return "zmm31";
		case X86_REG_R8B: return "r8b";
		case X86_REG_R9B: return "r9b";
		case X86_REG_R10B: return "r10b";
		case X86_REG_R11B: return "r11b";
		case X86_REG_R12B: return "r12b";
		case X86_REG_R13B: return "r13b";
		case X86_REG_R14B: return "r14b";
		case X86_REG_R15B: return "r15b";
		case X86_REG_R8D: return "r8d";
		case X86_REG_R9D: return "r9d";
		case X86_REG_R10D: return "r10d";
		case X86_REG_R11D: return "r11d";
		case X86_REG_R12D: return "r12d";
		case X86_REG_R13D: return "r13d";
		case X86_REG_R14D: return "r14d";
		case X86_REG_R15D: return "r15d";
		case X86_REG_R8W: return "r8w";
		case X86_REG_R9W: return "r9w";
		case X86_REG_R10W: return "r10w";
		case X86_REG_R11W: return "r11w";
		case X86_REG_R12W: return "r12w";
		case X86_REG_R13W: return "r13w";
		case X86_REG_R14W: return "r14w";
		case X86_REG_R15W: return "r15w";
		}
		return "<unknown register>";
	}
	return "<unsupported arch>";
}
