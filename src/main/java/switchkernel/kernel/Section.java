package switchkernel.kernel;

public class Section {
    public final long start;
    public final long size;

    /**
     * Inclusive end offset.
     */
    public final long end;

    public final String name;

    public Section(long start, long size, String name) {
        this.start = start;
        this.size = size;
        this.name = name;
        this.end = start + size - 1;
    }
}
