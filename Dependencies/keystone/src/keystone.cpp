#include <keystone/keystone.h>

KEYSTONE_EXPORT ks_err ks_open(ks_arch arch, int mode, ks_engine** ks)
{
	return ks_err::KS_ERR_OK;
}

int ks_asm(ks_engine* ks, const char* string, uint64_t address, unsigned char** encoding, size_t* encoding_size, size_t* stat_count)
{
	return 0;
}

void ks_free(unsigned char* p)
{
}
