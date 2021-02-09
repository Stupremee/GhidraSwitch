package switchkernel.kernel;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.IntBuffer;
import java.nio.LongBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;

import switchkernel.kernel.Section;
import switchkernel.kernel.Segment;

public class KernelFile {
    public static class ParseException extends Exception {
        public ParseException(String msg) {
            super(msg);
        }
    }

    public static final long DT_NULL = 0L;
    public static final long DT_NEEDED = 1L;
    public static final long DT_PLTRELSZ = 2L;
    public static final long DT_PLTGOT = 3L;
    public static final long DT_HASH = 4L;
    public static final long DT_STRTAB = 5L;
    public static final long DT_SYMTAB = 6L;
    public static final long DT_RELA = 7L;
    public static final long DT_RELASZ = 8L;
    public static final long DT_RELAENT = 9L;
    public static final long DT_STRSZ = 10L;
    public static final long DT_SYMENT = 11L;
    public static final long DT_INIT = 12L;
    public static final long DT_FINI = 13L;
    public static final long DT_SONAME = 14L;
    public static final long DT_RPATH = 15L;
    public static final long DT_SYMBOLIC = 16L;
    public static final long DT_REL = 17L;
    public static final long DT_RELSZ = 18L;
    public static final long DT_RELENT = 19L;
    public static final long DT_PLTREL = 20L;
    public static final long DT_DEBUG = 21L;
    public static final long DT_TEXTREL = 22L;
    public static final long DT_JMPREL = 23L;
    public static final long DT_BIND_NOW = 24L;
    public static final long DT_INIT_ARRAY = 25L;
    public static final long DT_FINI_ARRAY = 26L;
    public static final long DT_INIT_ARRAYSZ = 27L;
    public static final long DT_FINI_ARRAYSZ = 28L;
    public static final long DT_RUNPATH = 29L;
    public static final long DT_FLAGS = 30L;

    public static final long[] MULTIPLE_DTS = new long[] { DT_NEEDED };

    public static KernelFile parse(ByteProvider provider)
            throws IOException, ParseException {

        BinaryReader reader = new BinaryReader(provider, true);
        byte[] crt0 = reader.readNextByteArray(0x2000);

        long kmap = -1;
        long textOffset = -1, textEndOffset = -1, rodataOffset = -1, rodataEndOffset = -1,
             dataOffset = -1, dataEndOffset = -1, bssOffset = -1, bssEndOffset = -1,
             ini1Offset = -1, dynamicOffset = -1, initArrayOffset = -1, initArrayEndOffset = -1,
             corelocalOffset = -1;

        for (int off = 0; off < crt0.length - 0x30; off += 4) {
            if (isValidKernelMap(crt0, off)) {
                IntBuffer b = ByteBuffer.wrap(crt0, off, 0x30)
                    .order(ByteOrder.LITTLE_ENDIAN).asIntBuffer();

                textOffset = b.get();
                textEndOffset = b.get();
                rodataOffset = b.get();
                rodataEndOffset = b.get();
                dataOffset = b.get();
                dataEndOffset = b.get();
                bssOffset = b.get();
                bssEndOffset = b.get();
                ini1Offset = b.get();
                dynamicOffset = b.get();
                initArrayOffset = b.get();
                initArrayEndOffset = b.get();
                
                long ini1 = reader.readUnsignedInt(ini1Offset);
                if (ini1 == 0x31494E49L /* b'INI1' */
                        || (0x100000 <= ini1Offset && ini1Offset <= 0x400000)) {

                    kmap = off;
                    break;
                }
            } else if ((off <= crt0.length - 0x58) && isValidKernelMap5x(crt0, off)) {
                LongBuffer b = ByteBuffer.wrap(crt0, off, 0x30)
                    .order(ByteOrder.LITTLE_ENDIAN).asLongBuffer();

                textOffset = b.get();
                textEndOffset = b.get();
                rodataOffset = b.get();
                rodataEndOffset = b.get();
                dataOffset = b.get();
                dataEndOffset = b.get();
                bssOffset = b.get();
                bssEndOffset = b.get();
                ini1Offset = b.get();
                dynamicOffset = b.get();
                corelocalOffset = b.get();

                kmap = off;
                break;
            }
        }

        if (kmap == -1) {
            throw new ParseException("No valid mapping found");
        }

        Segment.Builder segments = new Segment.Builder();

        long textSize = textEndOffset - textOffset;
        long rodataSize = rodataEndOffset - rodataOffset;
        long dataSize = dataEndOffset - dataOffset;
        long bssSize = bssEndOffset - bssOffset;
        long flatSize = dataOffset + dataSize;

        segments.segment(textOffset, textSize, ".text", "CODE");
        segments.segment(rodataOffset, rodataSize, ".rodata", "CONST");
        segments.segment(dataOffset, dataSize, ".data", "DATA");
        segments.segment(bssOffset, bssSize, ".bss", "BSS");

        reader.setPointerIndex(dynamicOffset);

        Map<Long, List<Long>> dynamic = new HashMap<>();

        for (long i: MULTIPLE_DTS) {
            dynamic.put(i, new ArrayList<>());
        }

        for (long idx = 0; idx < (flatSize - dynamicOffset) / 0x10; idx++) {
            long tag = reader.readNextLong();
            long val = reader.readNextLong();

            if (tag == DT_NULL) {
                break;
            }

            if (Arrays.stream(MULTIPLE_DTS).anyMatch(x -> x == tag)) {
                dynamic.get(idx).add(val);
            } else {
                dynamic.put(idx, Collections.singletonList(val));
            }
        }

        long dynamicEnd = reader.getPointerIndex();
        long dynamicSize = dynamicEnd - dynamicOffset;
        segments.section(".dynamic", dynamicOffset, dynamicSize);

        String dynstr = "\u0000";
        if (dynamic.containsKey(DT_STRTAB)
                && dynamic.containsKey(DT_STRSZ)) {

            long idx = dynamic.get(DT_STRTAB).get(0);
            int size = (int) (long) dynamic.get(DT_STRSZ).get(0);
            dynstr = reader.readAsciiString(idx, size);
        }

        addDynSection(segments, dynamic, DT_STRTAB, DT_STRSZ, ".dynstr");
        addDynSection(segments, dynamic, DT_INIT_ARRAY, DT_INIT_ARRAYSZ, ".init_array");
        addDynSection(segments, dynamic, DT_FINI_ARRAY, DT_FINI_ARRAYSZ, ".fini_array");
        addDynSection(segments, dynamic, DT_RELA, DT_RELASZ, ".rela.dyn");
        addDynSection(segments, dynamic, DT_REL, DT_RELSZ, ".rel.dyn");
        addDynSection(segments, dynamic, DT_JMPREL, DT_PLTRELSZ, ".rela.plt");

        return new KernelFile();
    }

    private static void addDynSection(Segment.Builder segs, Map<Long, List<Long>> b,
            long startKey, long sizeKey, String name) {

        if (b.containsKey(startKey) && b.containsKey(sizeKey)) {
            long start = b.get(startKey).get(0);
            long size = b.get(sizeKey).get(0);
            segs.section(name, start, size);
        }
    }


    private static boolean isValidKernelMap5x(byte[] crt0, int off) {
        LongBuffer b = ByteBuffer.wrap(crt0, off, 0x58)
            .order(ByteOrder.LITTLE_ENDIAN).asLongBuffer();

        long ts = b.get();
        long te = b.get();
        long rs = b.get();
        long re = b.get();
        long ds = b.get();
        long de = b.get();
        long bs = b.get();
        long be = b.get();
        long i1 = b.get();
        long dn = b.get();

        return isValidKernelMapImpl(ts, te, rs, re, ds, de, bs, be, i1, dn);
    }

    private static boolean isValidKernelMap(byte[] crt0, int off) {
        IntBuffer b = ByteBuffer.wrap(crt0, off, 0x30)
            .order(ByteOrder.LITTLE_ENDIAN).asIntBuffer();

        int ts = b.get();
        int te = b.get();
        int rs = b.get();
        int re = b.get();
        int ds = b.get();
        int de = b.get();
        int bs = b.get();
        int be = b.get();
        int i1 = b.get();
        int dn = b.get();

        return isValidKernelMapImpl(ts, te, rs, re, ds, de, bs, be, i1, dn);
    }

    private static boolean isValidKernelMapImpl(long ts, long te, long rs,
        long re, long ds, long de, long bs, long be, long i1, long dn) {

        if (ts != 0) {
            return false;
        } else if (ts >= te) {
            return false;
        } else if ((te & 0xFFF) != 0) {
            return false;
        } else if (te > rs) {
            return false;
        } else if ((rs & 0xFFF) != 0) {
            return false;
        } else if (rs >= re) {
            return false;
        } else if ((re & 0xFFF) != 0) {
            return false;
        } else if (re > ds) {
            return false;
        } else if ((ds & 0xFFF) != 0) {
            return false;
        } else if (ds >= de) {
            return false;
        } else if (de > bs) {
            return false;
        } else if (bs > be) {
            return false;
        } else if (be > i1) {
            return false;
        } else if (!(ds <= dn && dn < de) || (rs <= dn && dn < re)) {
            return false;
        } else {
            return true;
        }
    }
}
