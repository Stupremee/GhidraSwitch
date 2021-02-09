package  switchkernel.kernel;

import java.util.ArrayList;
import java.util.List;

public class Segment {
    public final long start;
    public final long size;

    /**
     * Inclusive end offset.
     */
    public final long end;

    public final String name;
    public final String kind;

    public final List<Section> sections;

    private Segment(long start, long size, String name, String kind) {
        this.start = start;
        this.size = size;
        this.name = name;
        this.kind = kind;
        this.end = start + size - 1;
        this.sections = new ArrayList<>();
    }

    public static class Builder {
        private List<Segment> segments;

        public Builder() {
            this.segments = new ArrayList<>();
        }

        public void segment(long start, long size, String name, String kind) {
            Segment seg = new Segment(start, size, name, kind);

            for (Segment other : this.segments) {
                // self.start <= other._inclend and other.start <= self._inclend
                if (seg.start <= other.end && other.start <= seg.end) {
                    throw new RuntimeException("segments are overlapping");
                }
            }

            this.segments.add(seg);
        }

        public void section(String name, long start, long size) {
            assert size > 0;

            Section sec = new Section(start, size, name);
            for (Segment seg : this.segments) {
                if (sec.start >= seg.start && sec.end <= seg.end) {
                    seg.sections.add(sec);
                    return;
                }
            }
        }
    }
}
