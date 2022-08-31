from collections import OrderedDict
from enum import Enum

import pwndbg.gdb.typeinfo


# Note that we must inherit from `str` before `Enum`: https://stackoverflow.com/a/58608362/803801
class BinType(str, Enum):
    TCACHE = "tcachebins"
    FAST = "fastbins"
    SMALL = "smallbins"
    LARGE = "largebins"
    UNSORTED = "unsortedbin"
    NOT_IN_BIN = "not_in_bin"

    def valid_fields(self):
        if self in [BinType.FAST, BinType.TCACHE]:
            return ["fd"]
        elif self in [BinType.SMALL, BinType.UNSORTED]:
            return ["fd", "bk"]
        elif self == BinType.LARGE:
            return ["fd", "bk", "fd_nextsize", "bk_nextsize"]


class Bin:
    def __init__(self, fd_chain, bk_chain=None, count=None, is_corrupted=False):
        self.fd_chain = fd_chain
        self.bk_chain = bk_chain
        self.count = count
        self.is_corrupted = is_corrupted

    def contains_chunk(self, chunk):
        return chunk in self.fd_chain

    @staticmethod
    def size_to_display_name(size):
        if size == "all":
            return size

        assert isinstance(size, int)

        return hex(size)


class Bins:
    def __init__(self, bin_type, size_sz):
        self.bins = OrderedDict()
        self.bin_type = bin_type
        self.size_sz = size_sz

    # TODO: There's a bunch of bin-specific logic in here, maybe we should
    # subclass and put that logic in there
    def contains_chunk(self, size, chunk):
        if self.bin_type == BinType.UNSORTED:
            # The unsorted bin only has one bin called 'all'
            # TODO: We shouldn't be mixing int and str types like this
            size = "all"
        elif self.bin_type == BinType.LARGE:
            # All the other bins (other than unsorted) store chunks of the same
            # size in a bin, so we can use the size directly. But the largebin
            # stores a range of sizes, so we need to compute which bucket this
            # chunk falls into
            size = self.largebin_index(size) - 64
        elif self.bin_type == BinType.TCACHE:
            # Unlike fastbins, tcache bins don't store the chunk address in the
            # bins, they store the address of the fd pointer, so we need to
            # search for that address in the tcache bin instead

            # TODO: Can we use chunk_key_offset?
            chunk += self.size_sz * 2

        if size in self.bins:
            return self.bins[size].contains_chunk(chunk)

        return False

    def largebin_index_32(self, sz):
        """Modeled on the GLIBC malloc largebin_index_32 macro.

        https://sourceware.org/git/?p=glibc.git;a=blob;f=malloc/malloc.c;h=f7cd29bc2f93e1082ee77800bd64a4b2a2897055;hb=9ea3686266dca3f004ba874745a4087a89682617#l1414
        """
        return (
            56 + (sz >> 6)
            if (sz >> 6) <= 38
            else 91 + (sz >> 9)
            if (sz >> 9) <= 20
            else 110 + (sz >> 12)
            if (sz >> 12) <= 10
            else 119 + (sz >> 15)
            if (sz >> 15) <= 4
            else 124 + (sz >> 18)
            if (sz >> 18) <= 2
            else 126
        )

    def largebin_index_64(self, sz):
        """Modeled on the GLIBC malloc largebin_index_64 macro.

        https://sourceware.org/git/?p=glibc.git;a=blob;f=malloc/malloc.c;h=f7cd29bc2f93e1082ee77800bd64a4b2a2897055;hb=9ea3686266dca3f004ba874745a4087a89682617#l1433
        """
        return (
            48 + (sz >> 6)
            if (sz >> 6) <= 48
            else 91 + (sz >> 9)
            if (sz >> 9) <= 20
            else 110 + (sz >> 12)
            if (sz >> 12) <= 10
            else 119 + (sz >> 15)
            if (sz >> 15) <= 4
            else 124 + (sz >> 18)
            if (sz >> 18) <= 2
            else 126
        )


class Heap:
    def get_bins():
        return None

    # def get_bins(self, bin_type,  addr):
    #     if bin_type == BinType.TCACHE:
    #         return self.tcachebins(addr)
    #     elif bin_type == BinType.FAST:
    #         return self.fastbins(addr)
    #     elif bin_type == BinType.UNSORTED:
    #         return self.unsortedbin(addr)
    #     elif bin_type == BinType.SMALL:
    #         return self.smallbins(addr)
    #     elif bin_type == BinType.LARGE:
    #         return self.largebins(addr)
    #     else:
    #         return None

    # def fastbin_index(self, size):
    #     if pwndbg.gdb.arch.ptrsize == 8:
    #         return (size >> 4) - 2
    #     else:
    #         return (size >> 3) - 2

    # def fastbins(self, arena_addr):
    #     """Returns: chain or None"""
    #     result = Bins(BinType.FAST)
    #     arena = self.get_arena(arena_addr)

    #     if arena is None:
    #         return result

    #     fastbinsY = arena['fastbinsY']
    #     fd_offset = self.chunk_key_offset('fd')
    #     num_fastbins = 7
    #     size = pwndbg.gdb.arch.ptrsize * 2
    #     safe_lnk = pwndbg.gdb.glibc.check_safe_linking()

    #     for i in range(num_fastbins):
    #         size += pwndbg.gdb.arch.ptrsize * 2
    #         chain = pwndbg.chain.get(
    #             int(fastbinsY[i]),
    #             offset=fd_offset,
    #             limit=heap_chain_limit,
    #             safe_linking=safe_lnk
    #         )

    #         result.bins[size] = Bin(chain)

    #     return result

    # def tcachebins(self, tcache_addr):
    #     """Returns: tuple(chain, count) or None"""
    #     result = Bins(BinType.TCACHE)
    #     tcache = self.get_tcache(tcache_addr)

    #     if tcache is None:
    #         return result

    #     counts = tcache['counts']
    #     entries = tcache['entries']

    #     num_tcachebins = entries.type.sizeof // entries.type.target().sizeof
    #     safe_lnk = pwndbg.gdb.glibc.check_safe_linking()

    #     def tidx2usize(idx):
    #         """Tcache bin index to chunk size, following tidx2usize macro in glibc malloc.c"""
    #         return idx * self.malloc_alignment + self.minsize - self.size_sz

    #     for i in range(num_tcachebins):
    #         size = self._request2size(tidx2usize(i))
    #         count = int(counts[i])
    #         chain = pwndbg.chain.get(
    #             int(entries[i]),
    #             offset=self.tcache_next_offset,
    #             limit=heap_chain_limit,
    #             safe_linking=safe_lnk
    #         )

    #         result.bins[size] = Bin(chain, count=count)

    #     return result

    # def bin_at(self, index, arena_addr):
    #     """
    #     Modeled after glibc's bin_at function - so starts indexing from 1
    #     https://bazaar.launchpad.net/~ubuntu-branches/ubuntu/trusty/eglibc/trusty-security/view/head:/malloc/malloc.c#L1394

    #     bin_at(1) returns the unsorted bin

    #     Bin 1          - Unsorted BiN
    #     Bin 2 to 63    - Smallbins
    #     Bin 64 to 126  - Largebins

    #     Returns: tuple(chain_from_bin_fd, chain_from_bin_bk, is_chain_corrupted) or None
    #     """
    #     index = index - 1
    #     arena = self.get_arena(arena_addr)

    #     if arena is None:
    #         return

    #     normal_bins = arena['bins']
    #     num_bins = normal_bins.type.sizeof // normal_bins.type.target().sizeof

    #     bins_base = int(normal_bins.address) - (pwndbg.gdb.arch.ptrsize * 2)
    #     current_base = bins_base + (index * pwndbg.gdb.arch.ptrsize * 2)

    #     front, back = normal_bins[index * 2], normal_bins[index * 2 + 1]
    #     fd_offset = self.chunk_key_offset('fd')
    #     bk_offset = self.chunk_key_offset('bk')

    #     is_chain_corrupted = False

    #     get_chain = lambda bin, offset: pwndbg.chain.get(
    #         int(bin),
    #         offset=offset,
    #         hard_stop=current_base,
    #         limit=heap_chain_limit,
    #         include_start=True
    #     )
    #     chain_fd = get_chain(front, fd_offset)
    #     chain_bk = get_chain(back, bk_offset)

    #     # check if bin[index] points to itself (is empty)
    #     if len(chain_fd) == len(chain_bk) == 2 and chain_fd[0] == chain_bk[0]:
    #         chain_fd = [0]
    #         chain_bk = [0]

    #     # check if corrupted
    #     elif chain_fd[:-1] != chain_bk[:-2][::-1] + [chain_bk[-2]]:
    #         is_chain_corrupted = True

    #     return (chain_fd, chain_bk, is_chain_corrupted)

    # def unsortedbin(self, arena_addr):
    #     result = Bins(BinType.UNSORTED)
    #     chain = self.bin_at(1, arena_addr=arena_addr)

    #     if chain is None:
    #         return result

    #     fd_chain, bk_chain, is_corrupted = chain
    #     result.bins['all'] = Bin(fd_chain, bk_chain, is_corrupted=is_corrupted)

    #     return result

    # def smallbins(self, arena_addr):
    #     size = self.min_chunk_size - self.malloc_alignment
    #     spaces_table = self._spaces_table()

    #     result = Bins(BinType.SMALL)
    #     for index in range(2, 64):
    #         size += spaces_table[index]
    #         chain = self.bin_at(index, arena_addr=arena_addr)

    #         if chain is None:
    #             # TODO: Should I return an empty Bins() instead?
    #             return result

    #         fd_chain, bk_chain, is_corrupted = chain
    #         result.bins[size] = Bin(
    #             fd_chain, bk_chain, is_corrupted=is_corrupted
    #         )

    #     return result

    # def largebins(self, arena_addr):
    #     size = (
    #         ptmalloc.NSMALLBINS * self.malloc_alignment
    #     ) - self.malloc_alignment
    #     spaces_table = self._spaces_table()

    #     result = Bins(BinType.LARGE)
    #     for index in range(64, 127):
    #         size += spaces_table[index]
    #         chain = self.bin_at(index, arena_addr=arena_addr)

    #         if chain is None:
    #             # TODO: Should I return an empty Bins() instead?
    #             return result

    #         fd_chain, bk_chain, is_corrupted = chain
    #         result.bins[size] = Bin(
    #             fd_chain, bk_chain, is_corrupted=is_corrupted
    #         )

    #     return result

    # def largebin_index_32(self, sz):
    #     """Modeled on the GLIBC malloc largebin_index_32 macro.

    #     https://sourceware.org/git/?p=glibc.git;a=blob;f=malloc/malloc.c;h=f7cd29bc2f93e1082ee77800bd64a4b2a2897055;hb=9ea3686266dca3f004ba874745a4087a89682617#l1414
    #     """
    #     return 56 + (sz >> 6) if (sz >> 6) <= 38 else\
    #     91 + (sz >> 9) if (sz >> 9) <= 20 else\
    #     110 + (sz >> 12) if (sz >> 12) <= 10 else\
    #     119 + (sz >> 15) if (sz >> 15) <= 4 else\
    #     124 + (sz >> 18) if (sz >> 18) <= 2 else\
    #     126

    # def largebin_index_64(self, sz):
    #     """Modeled on the GLIBC malloc largebin_index_64 macro.

    #     https://sourceware.org/git/?p=glibc.git;a=blob;f=malloc/malloc.c;h=f7cd29bc2f93e1082ee77800bd64a4b2a2897055;hb=9ea3686266dca3f004ba874745a4087a89682617#l1433
    #     """
    #     return 48 + (sz >> 6) if (sz >> 6) <= 48 else\
    #     91 + (sz >> 9) if (sz >> 9) <= 20 else\
    #     110 + (sz >> 12) if (sz >> 12) <= 10 else\
    #     119 + (sz >> 15) if (sz >> 15) <= 4 else\
    #     124 + (sz >> 18) if (sz >> 18) <= 2 else\
    #     126

    # def largebin_index(self, sz):
    #     """Pick the appropriate largebin_index_ function for this architecture."""
    #     return self.largebin_index_64(sz) if pwndbg.gdb.arch.ptrsize == 8 else self.largebin_index_32(sz)
