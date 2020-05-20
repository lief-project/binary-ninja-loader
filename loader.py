import traceback
import sys
import lief

from binaryninja.enums import SegmentFlag, SymbolType
from binaryninja.platform import Platform
from binaryninja.binaryview import BinaryView
from binaryninja.types import Symbol
from binaryninja.log import log_error, log_info
from binaryninja.interaction import get_choice_input
from functools import wraps

class exceptions_handler(object):
    def __init__(self, exceptions):
        self.exceptions = exceptions
        self.func = None

    def __call__(self, func):
        self.func = func

        @wraps(func)
        def wrapped_func(*args, **kwargs):
            try:
                return self.func(*args, **kwargs)
            except self.exceptions as e:
                log_error("-" * 60)
                log_error("Exception in {}: {}".format(self.func.__name__, e))
                exc_type, exc_value, exc_traceback = sys.exc_info()
                traceback.print_tb(exc_traceback)
                log_error("-" * 60)
                return False
        return wrapped_func


class LiefElfView(BinaryView):
    name = "LIEF"
    long_name = "LIEF ELF loader"

    LIEF2BN = {
        lief.ELF.ARCH.AARCH64: "aarch64",
        lief.ELF.ARCH.ARM:     "armv7",
        lief.ELF.ARCH.x86_64:  "x86_64",
        lief.ELF.ARCH.i386:    "x86",
    }

    def __init__(self, data):
        BinaryView.__init__(self, parent_view=data, file_metadata=data.file)
        self._lief_handler: lief.ELF.Binary = lief.parse(data.file.filename)

    @classmethod
    def is_valid_for_data(self, data):
        hdr = data.read(0, 16)
        if len(hdr) < 16:
            return False
        if hdr[0:4] != b"\x7fELF":
            return False
        choice: int = get_choice_input("Do you want to load the binary with LIEF?", "choices", ["Yes", "No"])
        return choice == 0

    @exceptions_handler(Exception)
    def init(self):
        if self._lief_handler is None:
            log_error("Can't load the binary with LIEF")
            return False

        # TODO(romain): Handle other platforms supported by Binary Ninja (e.g. freebsd)
        arch = self.LIEF2BN.get(self._lief_handler.header.machine_type, None)
        if arch is None:
            log_error("Unsupported architecture: {}".format(str(self._lief_handler.header.machine_type)))
        self.platform = Platform[f"linux-{arch}"]

        # Add segments
        for segment in self._lief_handler.segments:
            if segment.type == lief.ELF.SEGMENT_TYPES.LOAD:
                bn_flags = 0
                if segment.has(lief.ELF.SEGMENT_FLAGS.R):
                    bn_flags |= SegmentFlag.SegmentReadable

                if segment.has(lief.ELF.SEGMENT_FLAGS.W):
                    bn_flags |= SegmentFlag.SegmentWritable

                if segment.has(lief.ELF.SEGMENT_FLAGS.X):
                    bn_flags |= SegmentFlag.SegmentExecutable

                if segment.file_offset > 0:
                    self.add_auto_segment(segment.virtual_address, segment.virtual_address,
                            segment.file_offset, segment.physical_size, bn_flags)
                else:
                    # Workaround: BN does not enable to add segment which starts at 0 (while is it
                    # valid with the ASLR)
                    OFF = 1
                    self.add_auto_segment(OFF, segment.virtual_size,
                            OFF, segment.physical_size, bn_flags)

        # TODO(romain): Handle sections: add_auto_section

        # Add functions
        for func in self._lief_handler.functions:
            log_info(f"Adding function {func!s}")
            self.add_function(func.address)
            if func.name:
                self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, func.address, func.name))

        # Init entrypoint
        if lief.ELF.DYNAMIC_TAGS.INIT_ARRAY in self._lief_handler:
            for func in self._lief_handler[lief.ELF.DYNAMIC_TAGS.INIT_ARRAY].array:
                if func > 0 and self.entry_point == 0:
                    log_info(f"Adding constructor function 0x{func:x}")
                    self.add_entry_point(func)
        # TODO: Hand DT_INIT / DT_PREINIT_ARRAY / header.entrypoint / _start / JNI_OnLoad / ...

        # Add imports: TODO
        # for symbol in self._lief_handler.imported_functions:
        #     sym = Symbol(SymbolType.ImportedFunctionSymbol, 0, symbol.name)
        #     # TODO: How to instanciate a function.Function object ?
        #     # self.define_imported_function(sym, func)
        return True

    def perform_is_valid_offset(self, addr):
        try:
            res = self._lief_handler.virtual_address_to_offset(addr)
            self._lief_handler.get_content_from_virtual_address(addr, 1)
            return res > 0
        except Exception:
            return False

    def perform_read(self, addr, length):
        try:
            return bytes(self._lief_handler.get_content_from_virtual_address(addr, length))
        except Exception:
            return None

    def relocation_ranges_at(addr):
        raise NotImplementedError("Relocation is not supported yet")

    def perform_is_executable(self):
        return True

    def perform_is_relocatable(self):
        return self._lief_handler.is_pie

