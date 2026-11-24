package detector

import (
	"bytes"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestXFSSectorHeaders(t *testing.T) {
	raw, err := os.ReadFile(buildTestXFS(t))
	if err != nil {
		t.Fatal(err)
	}
	// Relocate the AG headers to sectors 1, 2, 3 in a 4 KiB-sector image.
	agf := append([]byte(nil), raw[512:1024]...)
	agi := append([]byte(nil), raw[1024:1536]...)
	agfl := append([]byte(nil), raw[1536:2048]...)
	clear(raw[512 : 4*4096])
	copy(raw[4096:], agf)
	copy(raw[2*4096:], agi)
	copy(raw[3*4096:], agfl)
	binary.BigEndian.PutUint16(raw[102:104], 4096)
	vol, err := OpenXFS(bytes.NewReader(raw), 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := vol.readAGF(0); err != nil {
		t.Fatal(err)
	}
	if _, err := vol.readAGI(0); err != nil {
		t.Fatal(err)
	}
	g, _ := vol.readAGF(0)
	if blocks, err := vol.agflBlocks(0, g); err != nil || !reflect.DeepEqual(blocks, []uint32{5}) {
		t.Fatalf("AGFL = %v, %v", blocks, err)
	}
}

func TestXFSPackedFSBlocks(t *testing.T) {
	// AGs contain 48 blocks, while their encoded block-number stride is 64.
	vol := &XFSVol{blockSize: 4096, agBlocks: 48, agCount: 2, agblklog: 6, dblocks: 96, base: 8192}
	got := vol.mapExtents(xfsExtentRec(0, 64+7, 1), 100)
	want := []FSExtent{{Start: 8192 + (48+7)*4096, Len: 100}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("later AG mapping = %v, want %v", got, want)
	}
	// Encoded AG padding and extents crossing an AG boundary are invalid.
	for _, rec := range [][]byte{xfsExtentRec(0, 50, 1), xfsExtentRec(0, 47, 2)} {
		if got := vol.mapExtents(rec, 8192); len(got) != 0 {
			t.Errorf("invalid mapping survived: %v", got)
		}
	}
	// The high bit records unwritten preallocation, never file content.
	rec := xfsExtentRec(0, 7, 1)
	rec[0] |= 0x80
	if got := vol.mapExtents(rec, 100); len(got) != 0 {
		t.Errorf("unwritten mapping survived: %v", got)
	}
}

func TestXFSAttributeForkOffset(t *testing.T) {
	raw, err := os.ReadFile(buildTestXFS(t))
	if err != nil {
		t.Fatal(err)
	}
	// di_forkoff is relative to the end of the core, not the inode start.
	const off = 16*4096 + 2*512
	raw[off+82] = 2 // 16 bytes of data fork, then attributes
	vol, err := OpenXFS(bytes.NewReader(raw), 0)
	if err != nil {
		t.Fatal(err)
	}
	in, ok := vol.readInode(130)
	if !ok || len(in.extents) != 1 || in.extents[0] != (FSExtent{Start: 7 * 4096, Len: 100}) {
		t.Fatalf("attribute-bearing inode = %+v, ok=%v", in, ok)
	}
}

func TestXFSBmbtInternalPointers(t *testing.T) {
	const bs = 4096
	img := make([]byte, 64*bs)
	be := binary.BigEndian
	node := img[8*bs : 9*bs]
	be.PutUint32(node[:4], xfsMagicBmbtV5)
	be.PutUint16(node[4:6], 1)
	be.PutUint16(node[6:8], 1)
	// XFS_BMBT_PTR_ADDR uses the block's capacity, not its record count.
	be.PutUint64(node[72+((bs-72)/16)*8:], 9)
	copy(img[9*bs:], mkXFSBmbtLeaf(true, 9, 132, xfsExtentRec(0, 10, 1)))
	fork := xfsBmbtRoot(336, 8)
	be.PutUint16(fork[:2], 2)
	vol := &XFSVol{r: bytes.NewReader(img), blockSize: bs, agBlocks: 64, agCount: 1, agblklog: 6, dblocks: 64}
	got, ok := vol.mapBmbt(fork, 100)
	want := []FSExtent{{Start: 10 * bs, Len: 100}}
	if !ok || !reflect.DeepEqual(got, want) {
		t.Fatalf("deep bmbt = %v, ok=%v, want %v", got, ok, want)
	}
}

func TestXFSRealSectorGeometry(t *testing.T) {
	mkfs, err := exec.LookPath("mkfs.xfs")
	if err != nil {
		t.Skip("needs mkfs.xfs")
	}
	path := filepath.Join(t.TempDir(), "real.img")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(400 << 20); err != nil {
		f.Close()
		t.Fatal(err)
	}
	f.Close()
	args := []string{"-f", "-s", "size=4096", "-d", "agcount=3"}
	// Newer mkfs.xfs releases enable incompatible inode/directory features by
	// default. This test is specifically about sector geometry, while OpenXFS
	// deliberately rejects layouts it cannot decode. Pin optional features off
	// when the local mkfs advertises them; older releases neither expose nor
	// default them. xfsprogs 7.2 needs all three switches (otherwise the image
	// carries incompat 0xcb: the supported 0xb plus exchange and parent).
	help, _ := exec.Command(mkfs, "-i", "help").CombinedOutput()
	var inodeOpts []string
	for _, feature := range []string{"nrext64", "exchange"} {
		if bytes.Contains(help, []byte(feature)) {
			inodeOpts = append(inodeOpts, feature+"=0")
		}
	}
	if len(inodeOpts) != 0 {
		args = append(args, "-i", strings.Join(inodeOpts, ","))
	}
	if bytes.Contains(help, []byte("parent=")) {
		args = append(args, "-n", "parent=0")
	}
	args = append(args, path)
	if out, err := exec.Command(mkfs, args...).CombinedOutput(); err != nil {
		t.Fatalf("mkfs: %v\n%s", err, out)
	}
	vol, _ := openTestXFS(t, path)
	if _, err := vol.Entries(); err != nil {
		t.Fatal(err)
	}
	free, err := vol.Unallocated()
	if err != nil || len(free) == 0 {
		t.Fatalf("free = %v, %v", free, err)
	}
}

func TestXFSUnsupportedGeometry(t *testing.T) {
	raw, err := os.ReadFile(buildTestXFS(t))
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func([]byte){
		"realtime":              func(b []byte) { binary.BigEndian.PutUint64(b[16:24], 64) },
		"large-extent-counters": func(b []byte) { binary.BigEndian.PutUint32(b[216:220], 0x20) },
		"oversized-sector":      func(b []byte) { binary.BigEndian.PutUint16(b[102:104], 8192) },
	} {
		t.Run(name, func(t *testing.T) {
			cp := append([]byte(nil), raw...)
			mutate(cp)
			if _, err := OpenXFS(bytes.NewReader(cp), 0); err == nil {
				t.Fatal("unsupported layout must fail")
			}
		})
	}
}

func TestXFSPartitionScanning(t *testing.T) {
	for version, build := range map[string]func(*testing.T) string{"v4": buildTestXFSv4, "v5": buildTestXFS} {
		for _, scheme := range []string{"mbr", "gpt"} {
			t.Run(version+"/"+scheme, func(t *testing.T) {
				raw, err := os.ReadFile(build(t))
				if err != nil {
					t.Fatal(err)
				}
				const base = 1 << 20
				disk := make([]byte, base+len(raw)+512*34)
				copy(disk[base:], raw)
				if scheme == "mbr" {
					putMBRSlot(disk, 0, 0x83, base/512, uint32(len(raw)/512))
				} else {
					putGPT(disk, []gptTestEntry{{guidLinuxFS, base / 512, uint64((base+len(raw))/512 - 1), "xfs"}})
				}
				path := filepath.Join(t.TempDir(), "disk.img")
				if err := os.WriteFile(path, disk, 0600); err != nil {
					t.Fatal(err)
				}
				kinds, hits := scanAll(t, path, 0, true)
				_, pinned := scanAll(t, path, base, false)
				if !reflect.DeepEqual(kinds, []string{"xfs"}) || !reflect.DeepEqual(hits, pinned) || len(hits) == 0 {
					t.Fatalf("auto vs pinned: kinds %v, hits %v, pinned %v", kinds, hits, pinned)
				}
				foundNamed, foundOrphan := false, false
				for _, d := range hits {
					foundNamed = foundNamed || d.FileName == "wallet2.dat"
					foundOrphan = foundOrphan || d.FileName == "inode:130"
					if d.Offset < base {
						t.Errorf("hit lost partition offset: %+v", d)
					}
				}
				if !foundNamed || !foundOrphan {
					t.Errorf("names missing: %v", hits)
				}
				freeKinds, free, err := UnallocatedRangesAuto(path, 0, true)
				if err != nil || !reflect.DeepEqual(freeKinds, kinds) || len(free) == 0 {
					t.Fatalf("free ranges: %v, %v, %v", freeKinds, free, err)
				}
				for _, r := range free {
					if r.Start < base || r.Start+r.Len > int64(base+len(raw)) {
						t.Errorf("free range outside partition: %+v", r)
					}
				}
			})
		}
	}
}
