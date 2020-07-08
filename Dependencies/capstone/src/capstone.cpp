#include <capstone/capstone.h>

CAPSTONE_EXPORT cs_err CAPSTONE_API cs_open(cs_arch arch, cs_mode mode, csh* handle)
{
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
	return 0;
}
