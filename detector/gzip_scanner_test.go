package detector

import "testing"

func TestGzipTargetReaderReadAtContract(t *testing.T) {
	r := &gzipTargetReader{}
	n, err := r.ReadAt(make([]byte, 1), 0)
	if err == nil {
		t.Fatal("ReadAt unexpectedly succeeded")
	}
	if n != 0 {
		t.Fatalf("ReadAt returned n=%d on an unsupported read, want 0", n)
	}
}
