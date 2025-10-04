#pragma once

namespace handler
{
    void vmovdqu(uc_engine* uc, uint64_t address, uint32_t size, const insn_t& insn);
    void vmovdqa(uc_engine* uc, uint64_t address, uint32_t size, const insn_t& insn);
    void vpxor(uc_engine* uc, uint64_t address, uint32_t size, const insn_t& insn);
    void vzeroupper(uc_engine* uc, uint64_t address, uint32_t size, const insn_t& insn);
    void handle(uc_engine* uc, uint64_t address, uint32_t size, const insn_t& insn);
}