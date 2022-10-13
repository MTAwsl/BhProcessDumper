#pragma once
#include <stdint.h>

enum MemRegionType { Private = 0, Mapped, Image, Others, Invalid };

#pragma pack(push, 1)
struct dumpfile_header {
	const char magic[8] = {'M','E','M','D','M','P', '\0', '\0'};
	uint64_t time = 0;
	uint16_t arch = 0;
	uint16_t strCount = 0;
	uint32_t pageCount = 0;
	char string_table[1] = {0};
};

struct page_data {
	MemRegionType type;
	uint64_t addr;
	uint64_t alloc_base_addr;
	DWORD State;
	DWORD Protection;
	uint16_t infoStrIndex;
	uint32_t size;
	uint8_t buffer[1];
};
#pragma pack(pop)