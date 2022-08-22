from unittest import TestCase
from unittest.mock import MagicMock, patch
import sys
import types

# TODO: Will this prevent all the except blocks catching `Exception` from
# catching this?
class MyException(BaseException):
    pass

# We need this only so that `import gdb` works in the imported modules. No gdb
# method should ever be called without explicitly mocking that method
class MockGdb(types.ModuleType):
    def __getattribute__(self, x):
        raise Exception()

gdb = MockGdb('gdb')
sys.modules['gdb'] = gdb

from pwndbg.heap.ptmalloc import DebugSymsHeap, Bins, BinType
import pwndbg.heap

class TestPtmalloc(TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_chunk_flags(self):
        self.skipTest('Unimplemented')

    def test_next_offset(self):
        self.skipTest('Unimplemented')

    def test_get_first_heap_chunk(self):
        self.skipTest('Unimplemented')

    def test_get_arena_for_chunk(self):
        self.skipTest('Unimplemented')

    def test_fastbin_index(self):
        self.skipTest('Unimplemented')

    def test_fastbins(self):
        self.skipTest('Unimplemented')

    def test_tcachebins(self):
        self.skipTest('Unimplemented')

    def test_unsortedbin(self):
        self.skipTest('Unimplemented')

    def test_smallbins(self):
        self.skipTest('Unimplemented')

    def test_largebins(self):
        self.skipTest('Unimplemented')

    def test_chunks(self):
        self.skipTest('Unimplemented')

    def test_chunk_size(self):
        allocator = DebugSymsHeap()
        allocator.chunk_size_nomask = MagicMock(return_value=0x21)
        pwndbg.heap.current = allocator

        pwndbg.glibc.get_version = MagicMock(return_value=(2,26))
        assert allocator.chunk_size(0x1000) == 0x20

        pwndbg.glibc.get_version = MagicMock(return_value=(2,25))
        assert allocator.chunk_size(0x1000) == 0x20

    def test_next_chunk(self):
        self.skipTest('Unimplemented')

    def test_prev_inuse(self):
        self.skipTest('Unimplemented')

    def test_largebin_index(self):
        self.skipTest('Unimplemented')

class TestBins(TestCase):
    def test_contains_chunk(self):
        pass
