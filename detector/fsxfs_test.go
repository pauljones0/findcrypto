package detector

import (
	"bytes"
	"context"
	"encoding/binary"
	"hash/crc32"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Synthetic XFS images (v5 crc + v4 no-crc flavors): 64 blocks of
// 4096 bytes, one allocation group. Layout (v5; v4 differs only as
// noted): block 0 holds the superblock plus the AGF/AGI/AGFL
// sectors; 1 bnobt, 2 cntbt, 3 inobt, 4 rmapbt (v5 only; free on
// v4), 5 AGFL-stashed free block, 6 live hello.txt, 7 deleted wallet
// content, 8 bmbt leaf, 9 its data, 10 wallet2.dat content, 11
// finobt (v5 only; free on v4), 12 refcountbt (v5 only; bmbt leaf
// on v4), 13-15 free, 16-23 the inode chunk (v4: 8-11, 256-byte
// inodes; v4 data moves to 13-14), 24-63 free.
//
// Inodes 128-136: root shortform dir (hello.txt, live2.txt, sub),
// live and deleted extent-mapped files, a deleted inline (local)
// file, a bmbt-mapped file, a bad-bmbt file (degraded marker), an
// unlinked shortform subdir, and a live inline file.
//
// The cntbt, rmapbt, finobt, superblock counters, and CRCs exist for
// oracle acceptance (TestXFSOracleCrossCheck replays the fixture
// through xfs_db): the parser never reads them. CRC offsets and the
// Castagnoli rule were pinned against real mkfs images (see the
// G47a notes): sb@224, AGF@216, AGI@312, AGFL@32, inode-v3@100,
// short-btree@52, bmbt-leaf crc@64 with keys at 72 (pinned by
// xfs_db typed print: owner, crc, and record decode exact).

const (
	xfsTestBlocks = 64
	xfsTestBlock  = 4096
)

var xfsTestUUID = []byte("FINDBTC-XFS-TEST") // exactly 16 bytes

func init() {
	if len(xfsTestUUID) != 16 {
		panic("test uuid must be 16 bytes")
	}
}

// Magics the parser never reads (cntbt/rmapbt/finobt exist in the
// fixture for oracle acceptance only).
const (
	xfsTestCntV5    = 0x41423343 // "AB3C"
	xfsTestCntV4    = 0x41425443 // "ABTC"
	xfsTestRmapV5   = 0x524d4233 // "RMB3"
	xfsTestFinobtV5 = 0x46494233 // "FIB3"
	xfsTestRefcntV5 = 0x52334643 // "R3FC"
)

var xfsCrcTab = crc32.MakeTable(crc32.Castagnoli)

// xfsTestCRC stamps the XFS checksum at off: byteswapped Castagnoli
// over the structure with the field zeroed.
func xfsTestCRC(blk []byte, off int) {
	blk[off], blk[off+1], blk[off+2], blk[off+3] = 0, 0, 0, 0
	c := crc32.Update(0, xfsCrcTab, blk)
	c = c>>24 | (c>>8)&0xFF00 | (c<<8)&0xFF0000 | c<<24
	binary.BigEndian.PutUint32(blk[off:], c)
}

func xfsExtentRec(startoff, startblock, count uint64) []byte {
	rec := make([]byte, 16)
	l0 := (startoff << 9) | (startblock >> 43)
	l1 := ((startblock & ((uint64(1) << 43) - 1)) << 21) | count
	binary.BigEndian.PutUint64(rec[0:8], l0)
	binary.BigEndian.PutUint64(rec[8:16], l1)
	return rec
}

type xfsSFEntry struct {
	name  string
	ino   uint32
	ftype byte
}

// xfsShortform builds a 4-byte-inode shortform directory image.
func xfsShortform(parent uint32, withFtype bool, entries ...xfsSFEntry) []byte {
	var out []byte
	out = append(out, byte(len(entries)), 0)
	var p [4]byte
	binary.BigEndian.PutUint32(p[:], parent)
	out = append(out, p[:]...)
	for _, e := range entries {
		out = append(out, byte(len(e.name)), 0x12, 0x34)
		out = append(out, e.name...)
		if withFtype {
			out = append(out, e.ftype)
		}
		var ino [4]byte
		binary.BigEndian.PutUint32(ino[:], e.ino)
		out = append(out, ino[:]...)
	}
	return out
}

// mkXFSInode builds one inode image: version 2 (256B) or 3 (512B).
func mkXFSInode(version int, mode uint16, nlink uint32, size uint64, format uint8, nextents uint32, fork []byte, ino uint64) []byte {
	be := binary.BigEndian
	var coreLen int
	var in []byte
	if version == 3 {
		coreLen = 176
		in = make([]byte, 512)
	} else {
		coreLen = 100
		in = make([]byte, 256)
	}
	be.PutUint16(in[0:2], xfsMagicIno)
	be.PutUint16(in[2:4], mode)
	in[4] = byte(version)
	in[5] = format
	be.PutUint32(in[16:20], nlink)
	be.PutUint64(in[56:64], size)
	be.PutUint32(in[76:80], nextents)
	be.PutUint32(in[96:100], 0xFFFFFFFF) // next_unlinked: null
	copy(in[coreLen:], fork)
	if version == 3 {
		be.PutUint64(in[152:160], ino)
		copy(in[160:176], xfsTestUUID)
		xfsTestCRC(in, 100)
	}
	return in
}

// mkXFSBtreeLeaf builds one short-pointer btree leaf block.
func mkXFSBtreeLeaf(v5 bool, magic uint32, ownerCode uint64, recs []byte, recSize int) []byte {
	be := binary.BigEndian
	blk := make([]byte, xfsTestBlock)
	be.PutUint32(blk[0:4], magic)
	be.PutUint16(blk[4:6], 0) // level 0
	be.PutUint16(blk[6:8], uint16(len(recs)/recSize))
	be.PutUint32(blk[8:12], 0xFFFFFFFF)
	be.PutUint32(blk[12:16], 0xFFFFFFFF)
	start := 16
	if v5 {
		be.PutUint64(blk[16:24], ownerCode)
		copy(blk[32:48], xfsTestUUID)
		start = 56
	}
	copy(blk[start:], recs)
	if v5 {
		xfsTestCRC(blk, 52)
	}
	return blk
}

func u32rec(vals ...uint32) []byte {
	var out []byte
	var tmp [4]byte
	for _, v := range vals {
		binary.BigEndian.PutUint32(tmp[:], v)
		out = append(out, tmp[:]...)
	}
	return out
}

func buildTestXFS(t *testing.T) string {
	return buildTestXFSVer(t, true)
}

func buildTestXFSv4(t *testing.T) string {
	return buildTestXFSVer(t, false)
}

func buildTestXFSVer(t *testing.T, v5 bool) string {
	t.Helper()
	be := binary.BigEndian
	img := make([]byte, xfsTestBlocks*xfsTestBlock)
	// Superblock.
	sb := img[0:512]
	be.PutUint32(sb[0:4], xfsMagicSB)
	be.PutUint32(sb[4:8], xfsTestBlock)
	be.PutUint64(sb[8:16], xfsTestBlocks)
	copy(sb[32:48], xfsTestUUID)
	be.PutUint64(sb[56:64], 128) // rootino
	be.PutUint32(sb[80:84], 1)
	be.PutUint32(sb[84:88], xfsTestBlocks)
	be.PutUint32(sb[88:92], 1)
	if v5 {
		be.PutUint16(sb[100:102], 0xb4a5)
	} else {
		be.PutUint16(sb[100:102], 0xb4a4)
	}
	be.PutUint16(sb[102:104], 512)
	if v5 {
		be.PutUint16(sb[104:106], 512)
		be.PutUint16(sb[106:108], 8)
	} else {
		be.PutUint16(sb[104:106], 256)
		be.PutUint16(sb[106:108], 16)
	}
	copy(sb[108:120], "testxfs")
	sb[120], sb[121] = 12, 9
	if v5 {
		sb[122] = 9
		sb[123] = 3
	} else {
		sb[122] = 8
		sb[123] = 4
	}
	sb[124] = 6
	sb[127] = 25
	// icount is ALLOCATED inodes (whole chunks), not used ones:
	// one 64-inode chunk with 9 inodes in use. Pinned by real
	// mkfs images (count=64 freecount=61) and enforced by
	// xfs_initialize_perag_data, which cries "AGF corruption"
	// when freecount > count.
	be.PutUint64(sb[128:136], 64)
	be.PutUint64(sb[136:144], 55)
	if v5 {
		be.PutUint64(sb[144:152], 43)
	} else {
		be.PutUint64(sb[144:152], 50)
	}
	be.PutUint32(sb[196:200], 1) // logsunit, as made by mkfs
	if v5 {
		// Feature slots pinned by sb diff against real mkfs:
		// @204 is bad_features2 (the v4-compat reject mask),
		// NOT compat; compat/ro/incompat/logincompat live at
		// 208/212/216/220. Writing them one slot early shifts
		// every value into its neighbor's field.
		be.PutUint32(sb[200:204], 0x18a) // features2
		be.PutUint32(sb[204:208], 0)     // bad_features2
		be.PutUint32(sb[208:212], 0)     // features_compat
		be.PutUint32(sb[212:216], 0x0f)  // features_ro_compat
		be.PutUint32(sb[216:220], 0x0b)  // features_incompat
		be.PutUint32(sb[220:224], 0)     // features_log_incompat
		be.PutUint32(sb[228:232], 4)     // copied value, meaning unknown
	} else {
		be.PutUint32(sb[200:204], 0x28a) // ftype set
		be.PutUint32(sb[204:208], 0x28a)
	}
	if v5 {
		xfsTestCRC(sb, 224)
	}
	// AGF at byte 512.
	agf := img[512:1024]
	be.PutUint32(agf[0:4], xfsMagicAGF)
	be.PutUint32(agf[4:8], 1)
	be.PutUint32(agf[12:16], xfsTestBlocks)
	be.PutUint32(agf[16:20], 1) // bno root
	be.PutUint32(agf[20:24], 2) // cnt root
	if v5 {
		be.PutUint32(agf[24:28], 4) // rmap root
	}
	be.PutUint32(agf[28:32], 1)
	be.PutUint32(agf[32:36], 1)
	if v5 {
		be.PutUint32(agf[36:40], 1)
	}
	be.PutUint32(agf[40:44], 1) // flfirst
	be.PutUint32(agf[44:48], 1) // fllast
	be.PutUint32(agf[48:52], 1) // flcount
	if v5 {
		be.PutUint32(agf[52:56], 43)
		be.PutUint32(agf[56:60], 40)
		copy(agf[64:80], xfsTestUUID)
		be.PutUint32(agf[80:84], 1)  // rmapblocks
		be.PutUint32(agf[84:88], 1)  // refcntblocks
		be.PutUint32(agf[88:92], 12) // refcnt root
		be.PutUint32(agf[92:96], 1)  // refcnt level
		xfsTestCRC(agf, 216)
	} else {
		be.PutUint32(agf[52:56], 50)
		be.PutUint32(agf[56:60], 49)
	}
	// AGI at byte 1024.
	agi := img[1024:1536]
	be.PutUint32(agi[0:4], xfsMagicAGI)
	be.PutUint32(agi[4:8], 1)
	be.PutUint32(agi[12:16], xfsTestBlocks)
	be.PutUint32(agi[16:20], 64) // allocated inodes: whole chunk, see sb icount
	be.PutUint32(agi[20:24], 3)  // ino root
	be.PutUint32(agi[24:28], 1)
	be.PutUint32(agi[28:32], 55)
	be.PutUint32(agi[32:36], 137) // newino
	be.PutUint32(agi[36:40], 0xFFFFFFFF)
	for i := 40; i < 296; i++ {
		agi[i] = 0xFF // empty unlinked buckets
	}
	if v5 {
		copy(agi[296:312], xfsTestUUID)
		be.PutUint32(agi[328:332], 11) // finobt root
		be.PutUint32(agi[332:336], 1)
		be.PutUint32(agi[336:340], 1) // copied shape, see notes
		be.PutUint32(agi[340:344], 1)
		xfsTestCRC(agi, 312)
	}
	// AGFL at byte 1536.
	if v5 {
		agfl := img[1536:2048]
		be.PutUint32(agfl[0:4], xfsMagicAGFL)
		copy(agfl[8:24], xfsTestUUID)
		for i := 36; i < 512; i++ {
			agfl[i] = 0xFF
		}
		be.PutUint32(agfl[36+1*4:], 5)
		xfsTestCRC(agfl, 32)
	} else {
		agfl := img[1536:2048]
		for i := range agfl {
			agfl[i] = 0xFF
		}
		be.PutUint32(agfl[1*4:], 5)
	}
	putBlk := func(n int, blk []byte) {
		copy(img[n*xfsTestBlock:], blk)
	}
	if v5 {
		putBlk(1, mkXFSBtreeLeaf(true, xfsMagicBnoV5, 8, u32rec(13, 3, 24, 40), 8))
		putBlk(2, mkXFSBtreeLeaf(true, xfsTestCntV5, 16, u32rec(13, 3, 24, 40), 8))
		putBlk(4, mkXFSBtreeLeaf(true, xfsTestRmapV5, 40, xfsRmapRecs(), 24))
		putBlk(11, mkXFSBtreeLeaf(true, xfsTestFinobtV5, 32, xfsInoRec(), 16))
		putBlk(3, mkXFSBtreeLeaf(true, xfsMagicInoV5, 24, xfsInoRec(), 16))
		putBlk(12, mkXFSBtreeLeaf(true, xfsTestRefcntV5, 48, nil, 12))
	} else {
		putBlk(1, mkXFSBtreeLeaf(false, xfsMagicBnoV4, 0, u32rec(4, 1, 15, 49), 8))
		putBlk(2, mkXFSBtreeLeaf(false, xfsTestCntV4, 0, u32rec(4, 1, 15, 49), 8))
		putBlk(3, mkXFSBtreeLeaf(false, xfsMagicInoV4, 0, xfsInoRec(), 16))
	}
	// bmbt leaf for inode 132 at block 8 (v5) / 12 (v4).
	bmbtBlk := nBlock(v5)
	putBlk(bmbtBlk, mkXFSBmbtLeaf(v5, uint64(bmbtBlk), 132, xfsExtentRec(0, uint64(data132Block(v5)), 1)))
	// File contents.
	copy(img[6*xfsTestBlock:], "hello")
	copy(img[7*xfsTestBlock:], "BDB wallet remnants bestblock orderposnext "+strings.Repeat("w", 60))
	copy(img[data132Block(v5)*xfsTestBlock:], "btree-mapped-residue defaultkey "+strings.Repeat("b", 22))
	copy(img[data135Block(v5)*xfsTestBlock:], "associated-residue defaultkey "+strings.Repeat("a", 13))
	// Inode chunk.
	inoVer := 2
	chunkBlk := 8
	if v5 {
		inoVer = 3
		chunkBlk = 16
	}
	putIno := func(num uint64, in []byte) {
		off := (chunkBlk*xfsTestBlock + int(num-128)*len(in))
		copy(img[off:], in)
	}
	rootSF := xfsShortform(128, true,
		xfsSFEntry{"hello.txt", 129, 1},
		xfsSFEntry{"live2.txt", 136, 1},
		xfsSFEntry{"sub", 134, 2})
	subSF := xfsShortform(128, true, xfsSFEntry{"wallet2.dat", 135, 1})
	putIno(128, mkXFSInode(inoVer, xfsModeDir|0x1FF, 2, uint64(len(rootSF)), xfsFmtLocal, 0, rootSF, 128))
	putIno(129, mkXFSInode(inoVer, xfsModeFile|0x1A4, 1, 5, xfsFmtExtents, 1, xfsExtentRec(0, 6, 1), 129))
	putIno(130, mkXFSInode(inoVer, xfsModeFile|0x1A4, 0, 100, xfsFmtExtents, 1, xfsExtentRec(0, 7, 1), 130))
	putIno(131, mkXFSInode(inoVer, xfsModeFile|0x1A4, 0, 21, xfsFmtLocal, 0, []byte("secret-inline-bytes!!"), 131))
	forkLen := 512 - 176
	if !v5 {
		forkLen = 256 - 100
	}
	putIno(132, mkXFSInode(inoVer, xfsModeFile|0x1A4, 0, 50, xfsFmtBtree, 1, xfsBmbtRoot(forkLen, uint64(bmbtBlk)), 132))
	putIno(133, mkXFSInode(inoVer, xfsModeFile|0x1A4, 0, 60, xfsFmtBtree, 1, []byte("XXXXbad-root-payload------------------------"), 133)) // bad level
	putIno(134, mkXFSInode(inoVer, xfsModeDir|0x1FF, 0, uint64(len(subSF)), xfsFmtLocal, 0, subSF, 134))
	putIno(135, mkXFSInode(inoVer, xfsModeFile|0x1A4, 0, 40, xfsFmtExtents, 1, xfsExtentRec(0, uint64(data135Block(v5)), 1), 135))
	putIno(136, mkXFSInode(inoVer, xfsModeFile|0x1A4, 1, 11, xfsFmtLocal, 0, []byte("live-inline"), 136))
	path := filepath.Join(t.TempDir(), "xfs.img")
	if err := os.WriteFile(path, img, 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

// xfsInoRec is the single inobt/finobt record: chunk at agino 128,
// all groups present, inodes 128-136 allocated.
func xfsInoRec() []byte {
	rec := make([]byte, 16)
	be := binary.BigEndian
	be.PutUint32(rec[0:4], 128)
	be.PutUint16(rec[4:6], 0)
	rec[6], rec[7] = 9, 55
	be.PutUint64(rec[8:16], 0xFFFFFFFFFFFFFE00)
	return rec
}

// xfsRmapRecs covers every allocated v5 block except the bmbt leaf
// (block 8), whose owner encoding is unpinned: rmap exists here
// only so xfs_db accepts the fixture (the parser never reads it).
func xfsRmapRecs() []byte {
	var out []byte
	var tmp [8]byte
	put := func(start, n uint32, owner uint64, off uint64) {
		be := binary.BigEndian
		be.PutUint32(tmp[0:4], start)
		be.PutUint32(tmp[4:8], n)
		out = append(out, tmp[:]...)
		be.PutUint64(tmp[:], owner)
		out = append(out, tmp[:]...)
		be.PutUint64(tmp[:], off)
		out = append(out, tmp[:]...)
	}
	put(0, 1, ^uint64(2), 0) // -3 static headers
	put(1, 1, ^uint64(4), 0) // -5 btree
	put(2, 1, ^uint64(4), 0)
	put(3, 1, ^uint64(5), 0) // -6 ino btree
	put(4, 1, ^uint64(4), 0)
	put(5, 1, ^uint64(4), 0) // AGFL stash
	put(6, 1, 129, 0)
	put(7, 1, 130, 0)
	put(9, 1, 132, 0)
	put(10, 1, 135, 0)
	put(11, 1, ^uint64(5), 0)
	put(12, 1, ^uint64(7), 0) // -8 refcountbt
	put(16, 8, ^uint64(6), 0) // -7 inode chunk
	return out
}

func nBlock(v5 bool) int {
	if v5 {
		return 8
	}
	return 12
}

func data132Block(v5 bool) int {
	if v5 {
		return 9
	}
	return 13
}

func data135Block(v5 bool) int {
	if v5 {
		return 10
	}
	return 14
}

// xfsBmbtRoot builds the in-fork btree root over a fork of forkLen
// bytes: level 1, one key, and the pointer in the capacity-sized
// array (XFS_BMDR_PTR_ADDR), no magic (xfs_bmdr_block).
func xfsBmbtRoot(forkLen int, blkno uint64) []byte {
	maxrecs := (forkLen - 4) / 16
	root := make([]byte, forkLen)
	be := binary.BigEndian
	be.PutUint16(root[0:2], 1)
	be.PutUint16(root[2:4], 1)
	be.PutUint64(root[4:12], 0)
	be.PutUint64(root[4+maxrecs*8:], blkno)
	return root
}

// mkXFSBmbtLeaf builds one file-extent-btree leaf block holding a
// single extent record. The v5 long header (64-bit siblings, block
// number, uuid, owner, crc, keys at 72) and the v4 long header
// (64-bit siblings, keys at 24) are both pinned by xfs_db typed
// print of crafted leaves.
func mkXFSBmbtLeaf(v5 bool, bno uint64, owner uint64, rec []byte) []byte {
	be := binary.BigEndian
	blk := make([]byte, xfsTestBlock)
	if v5 {
		be.PutUint32(blk[0:4], xfsMagicBmbtV5)
	} else {
		be.PutUint32(blk[0:4], xfsMagicBmbtV4)
	}
	be.PutUint16(blk[4:6], 0)
	be.PutUint16(blk[6:8], 1)
	if v5 {
		be.PutUint64(blk[8:16], ^uint64(0))
		be.PutUint64(blk[16:24], ^uint64(0))
		be.PutUint64(blk[24:32], bno)
		copy(blk[40:56], xfsTestUUID)
		be.PutUint64(blk[56:64], owner)
		copy(blk[72:], rec)
		xfsTestCRC(blk, 64)
		return blk
	}
	be.PutUint64(blk[8:16], 0xFFFFFFFFFFFFFFFF)
	be.PutUint64(blk[16:24], 0xFFFFFFFFFFFFFFFF)
	copy(blk[24:], rec)
	return blk
}

func openTestXFS(t *testing.T, path string) (*XFSVol, *os.File) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	vol, err := OpenXFS(f, 0)
	if err != nil {
		t.Fatalf("OpenXFS: %s", err)
	}
	return vol, f
}

func TestXFSDeletedWallet(t *testing.T) {
	vol, f := openTestXFS(t, buildTestXFS(t))
	entries, err := vol.Entries()
	if err != nil {
		t.Fatal(err)
	}
	byNote := map[string]FSEntry{}
	for _, e := range entries {
		byNote[e.Note] = e
	}
	// Seven files (128 root + 134 subdir are dirs, not emitted).
	if len(entries) != 7 {
		t.Fatalf("got %d entries %+v, want 7", len(entries), entries)
	}
	// Deleted extent-mapped wallet with content.
	w, ok := byNote["inode:130"]
	if !ok || !w.Deleted {
		t.Fatalf("inode 130 missing: %v", byNote)
	}
	if len(w.Extents) != 1 || w.Extents[0].Start != 7*xfsTestBlock || w.Extents[0].Len != 100 {
		t.Errorf("inode 130 extents %v, want block 7 trimmed to 100", w.Extents)
	}
	content := make([]byte, 100)
	if _, err := f.ReadAt(content, w.Extents[0].Start); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(content, []byte("orderposnext")) {
		t.Errorf("deleted extent content lost: %q", content)
	}
	// Deleted inline (local-format) file: exposed like a resident value.
	inl, ok := byNote["inode:131"]
	if !ok || !inl.Deleted || len(inl.Extents) != 1 || inl.Extents[0].Len != 21 {
		t.Fatalf("inode 131 inline wrong: %+v", inl)
	}
	raw := make([]byte, 21)
	if _, err := f.ReadAt(raw, inl.Extents[0].Start); err != nil {
		t.Fatal(err)
	}
	if string(raw) != "secret-inline-bytes!!" {
		t.Errorf("inline content %q", raw)
	}
	// bmbt-mapped file resolves through the extent btree.
	bb, ok := byNote["inode:132"]
	if !ok || !bb.Deleted || len(bb.Extents) != 1 || bb.Extents[0].Start != 9*xfsTestBlock {
		t.Fatalf("inode 132 bmbt wrong: %+v", bb)
	}
	// Bad bmbt root keeps a visibly degraded entry, never a silent loss.
	bad, ok := byNote["inode:133:btree-extents-unparsed"]
	if !ok || !bad.Deleted || len(bad.Extents) != 0 {
		t.Fatalf("inode 133 should be marked degraded: %+v", byNote)
	}
	// Name+content associated through the unlinked subdir.
	var assoc *FSEntry
	for i, e := range entries {
		if e.Name == "wallet2.dat" {
			assoc = &entries[i]
		}
	}
	if assoc == nil || !assoc.Deleted || len(assoc.Extents) != 1 {
		t.Fatalf("wallet2.dat association failed: %+v", assoc)
	}
	if assoc.Extents[0].Start != 10*xfsTestBlock {
		t.Errorf("wallet2.dat extent %v, want block 10", assoc.Extents)
	}
	// Live files keep names (tree walk) and content.
	h, ok := byNote["inode:129"]
	if !ok || h.Deleted || h.Name != "hello.txt" {
		t.Errorf("live hello.txt wrong: %+v", h)
	}
	l2, ok := byNote["inode:136"]
	if !ok || l2.Deleted || l2.Name != "live2.txt" || len(l2.Extents) != 1 {
		t.Errorf("live inline live2.txt wrong: %+v", l2)
	}
}

func TestXFSUnallocated(t *testing.T) {
	vol, _ := openTestXFS(t, buildTestXFS(t))
	free, err := vol.Unallocated()
	if err != nil {
		t.Fatal(err)
	}
	// AGFL stash (block 5) plus the two bnobt runs; nothing adjacent.
	want := []FSExtent{
		{Start: 5 * xfsTestBlock, Len: xfsTestBlock},
		{Start: 13 * xfsTestBlock, Len: 3 * xfsTestBlock},
		{Start: 24 * xfsTestBlock, Len: 40 * xfsTestBlock},
	}
	if len(free) != len(want) {
		t.Fatalf("free %v, want %v", free, want)
	}
	for i := range want {
		if free[i] != want[i] {
			t.Errorf("range %d: got %v want %v", i, free[i], want[i])
		}
	}
}

func TestXFSv4DeletedWallet(t *testing.T) {
	vol, f := openTestXFS(t, buildTestXFSv4(t))
	entries, err := vol.Entries()
	if err != nil {
		t.Fatal(err)
	}
	byNote := map[string]FSEntry{}
	for _, e := range entries {
		byNote[e.Note] = e
	}
	if len(entries) != 7 {
		t.Fatalf("got %d entries, want 7", len(entries))
	}
	w, ok := byNote["inode:130"]
	if !ok || !w.Deleted || len(w.Extents) != 1 || w.Extents[0].Start != 7*xfsTestBlock {
		t.Fatalf("v4 inode 130 wrong: %+v", w)
	}
	content := make([]byte, 100)
	if _, err := f.ReadAt(content, w.Extents[0].Start); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(content, []byte("orderposnext")) {
		t.Errorf("v4 deleted extent content lost: %q", content)
	}
	var assoc *FSEntry
	for i, e := range entries {
		if e.Name == "wallet2.dat" {
			assoc = &entries[i]
		}
	}
	if assoc == nil || assoc.Extents[0].Start != 14*xfsTestBlock {
		t.Fatalf("v4 wallet2.dat association failed: %+v", assoc)
	}
	if byNote["inode:129"].Name != "hello.txt" {
		t.Errorf("v4 live name wrong: %+v", byNote["inode:129"])
	}
}

func TestXFSv4Unallocated(t *testing.T) {
	vol, _ := openTestXFS(t, buildTestXFSv4(t))
	free, err := vol.Unallocated()
	if err != nil {
		t.Fatal(err)
	}
	// AGFL stash (block 5) merges with the adjacent bnobt run (4,1).
	want := []FSExtent{
		{Start: 4 * xfsTestBlock, Len: 2 * xfsTestBlock},
		{Start: 15 * xfsTestBlock, Len: 49 * xfsTestBlock},
	}
	if len(free) != len(want) {
		t.Fatalf("free %v, want %v", free, want)
	}
	for i := range want {
		if free[i] != want[i] {
			t.Errorf("range %d: got %v want %v", i, free[i], want[i])
		}
	}
}

func TestXFSRejectsGarbage(t *testing.T) {
	// Per-format FP bar: random bytes and repo prose are not volumes.
	rngData := make([]byte, 1<<20)
	for i := range rngData {
		rngData[i] = byte(i*31 + 7)
	}
	garbage := map[string][]byte{"random": rngData}
	for _, f := range []string{"../LICENSE", "../README.md", "../GOALS.md", "../main.go"} {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		garbage[f] = raw
	}
	for name, raw := range garbage {
		path := filepath.Join(t.TempDir(), "junk.img")
		if err := os.WriteFile(path, raw, 0644); err != nil {
			t.Fatal(err)
		}
		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		_, err = OpenXFS(f, 0)
		f.Close()
		if err == nil {
			t.Errorf("%s must not open as XFS", name)
		}
	}
	// Wrong version nibble and missing AGF magic refuse too.
	raw, err := os.ReadFile(buildTestXFS(t))
	if err != nil {
		t.Fatal(err)
	}
	mangle := func(off int, val byte) string {
		cp := append([]byte(nil), raw...)
		cp[off] = val
		p := filepath.Join(t.TempDir(), "mangled.img")
		if err := os.WriteFile(p, cp, 0644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	for _, tc := range []struct {
		name string
		off  int
		val  byte
	}{
		{"version nibble 3", 101, 0xB3},
		{"AGF magic", 512, 'Q'},
		{"AGI magic", 1024, 'Q'},
	} {
		f, err := os.Open(mangle(tc.off, tc.val))
		if err != nil {
			t.Fatal(err)
		}
		_, err = OpenXFS(f, 0)
		f.Close()
		if err == nil {
			t.Errorf("%s must refuse", tc.name)
		}
	}
}

func TestXFSRefusesCorruptFreespace(t *testing.T) {
	raw, err := os.ReadFile(buildTestXFS(t))
	if err != nil {
		t.Fatal(err)
	}
	// Wreck the first bnobt record's start block (past the AG end):
	// Unallocated must abort, never guess coverage.
	be := binary.BigEndian
	be.PutUint32(raw[1*xfsTestBlock+56:], 9999)
	path := filepath.Join(t.TempDir(), "corrupt.img")
	if err := os.WriteFile(path, raw, 0644); err != nil {
		t.Fatal(err)
	}
	vol, _ := openTestXFS(t, path)
	if _, err := vol.Unallocated(); err == nil {
		t.Fatal("corrupt bnobt must abort Unallocated")
	}
}

func TestXFSCorruptShortformDropsNamesKeepsContent(t *testing.T) {
	raw, err := os.ReadFile(buildTestXFS(t))
	if err != nil {
		t.Fatal(err)
	}
	// Corrupt the root shortform entry count (3 -> 9): names from
	// the root must vanish while every file's content survives.
	raw[16*xfsTestBlock+176] = 9
	path := filepath.Join(t.TempDir(), "corrupt.img")
	if err := os.WriteFile(path, raw, 0644); err != nil {
		t.Fatal(err)
	}
	vol, _ := openTestXFS(t, path)
	entries, err := vol.Entries()
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name == "hello.txt" || e.Name == "live2.txt" || e.Name == "sub" {
			t.Fatalf("corrupt root must yield no names, got %+v", e)
		}
		if e.Note == "inode:130" && len(e.Extents) != 1 {
			t.Fatalf("content must survive a corrupt dir: %+v", e)
		}
	}
	// The unlinked subdir still names its child.
	found := false
	for _, e := range entries {
		if e.Name == "wallet2.dat" {
			found = true
		}
	}
	if !found {
		t.Error("unlinked subdir names must survive root corruption")
	}
}

func TestXFSBtreeDescent(t *testing.T) {
	// White-box: a 3-level tree (root -> node -> two chained
	// leaves) must yield every record in leaf order.
	const bs = 4096
	img := make([]byte, 64*bs)
	be := binary.BigEndian
	mkNode := func(magic uint32, level uint16, keys, ptrs []uint32) []byte {
		blk := make([]byte, bs)
		be.PutUint32(blk[0:4], magic)
		be.PutUint16(blk[4:6], level)
		be.PutUint16(blk[6:8], uint16(len(keys)))
		be.PutUint32(blk[8:12], 0xFFFFFFFF)
		be.PutUint32(blk[12:16], 0xFFFFFFFF)
		p := 56
		for _, k := range keys {
			be.PutUint32(blk[p:], k)
			p += 8 // xfs_alloc_key_t carries startblock and blockcount
		}
		p = 56 + ((bs-56)/12)*8 // capacity-sized key array
		for _, q := range ptrs {
			be.PutUint32(blk[p:], q)
			p += 4
		}
		return blk
	}
	mkLeaf := func(recs []uint32, right uint32) []byte {
		blk := make([]byte, bs)
		be.PutUint32(blk[0:4], xfsMagicBnoV5)
		be.PutUint16(blk[6:8], uint16(len(recs)/2))
		be.PutUint32(blk[8:12], 0xFFFFFFFF)
		be.PutUint32(blk[12:16], right)
		p := 56
		for _, r := range recs {
			be.PutUint32(blk[p:], r)
			p += 4
		}
		return blk
	}
	// AGF: bno root 1, height 3.
	agf := img[512:1024]
	be.PutUint32(agf[0:4], xfsMagicAGF)
	be.PutUint32(agf[12:16], 64)
	be.PutUint32(agf[16:20], 1)
	be.PutUint32(agf[28:32], 3)
	copy(img[1*bs:], mkNode(xfsMagicBnoV5, 2, []uint32{0}, []uint32{5}))
	copy(img[5*bs:], mkNode(xfsMagicBnoV5, 1, []uint32{0, 50}, []uint32{2, 3}))
	copy(img[2*bs:], mkLeaf([]uint32{0, 10, 10, 10}, 3))
	copy(img[3*bs:], mkLeaf([]uint32{50, 14}, 0xFFFFFFFF))
	vol := &XFSVol{
		r: bytes.NewReader(img), base: 0, blockSize: bs,
		dblocks: 64, agCount: 1, agBlocks: 64,
	}
	recs, err := vol.btreeLeaves(0, 1, 3, 8, 8, xfsMagicBnoV4, xfsMagicBnoV5, "test")
	if err != nil {
		t.Fatal(err)
	}
	var got [][2]uint32
	for _, r := range recs {
		got = append(got, [2]uint32{be.Uint32(r[0:4]), be.Uint32(r[4:8])})
	}
	want := [][2]uint32{{0, 10}, {10, 10}, {50, 14}}
	if len(got) != len(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v want %v", got, want)
		}
	}
}

func TestXFSBmbtWalk(t *testing.T) {
	// White-box logic proof over the pinned v5 bmbt layout: a
	// root over two leaves must yield both extents merged, and a
	// bad child must fail closed. The oracle test's bmap
	// cross-check independently confirms the layout against
	// xfs_db.
	const bs = 4096
	img := make([]byte, 64*bs)
	be := binary.BigEndian
	leaf := func(recs ...[]byte) []byte {
		blk := make([]byte, bs)
		be.PutUint32(blk[0:4], xfsMagicBmbtV5)
		be.PutUint16(blk[6:8], uint16(len(recs)))
		p := 72
		for _, r := range recs {
			copy(blk[p:], r)
			p += 16
		}
		return blk
	}
	copy(img[10*bs:], leaf(xfsExtentRec(0, 20, 2)))
	copy(img[11*bs:], leaf(xfsExtentRec(2, 30, 1)))
	fork := make([]byte, 4+2*8+2*8)
	be.PutUint16(fork[0:2], 1)
	be.PutUint16(fork[2:4], 2)
	be.PutUint64(fork[20:28], 10)
	be.PutUint64(fork[28:36], 11)
	vol := &XFSVol{r: bytes.NewReader(img), blockSize: bs, dblocks: 64, agCount: 1, agBlocks: 64, agblklog: 6}
	ext, ok := vol.mapBmbt(fork, 3*bs)
	if !ok {
		t.Fatal("bmbt walk failed")
	}
	want := []FSExtent{{Start: 20 * bs, Len: 2 * bs}, {Start: 30 * bs, Len: bs}}
	if len(ext) != 2 || ext[0] != want[0] || ext[1] != want[1] {
		t.Fatalf("got %v want %v", ext, want)
	}
	// A bad child pointer fails closed.
	be.PutUint64(fork[20:28], 63)
	if _, ok := vol.mapBmbt(fork, 3*bs); ok {
		t.Fatal("bad bmbt child must fail closed")
	}
}

func TestXFSShortformShapes(t *testing.T) {
	mk := func(i8 bool, withFtype bool, entries ...xfsSFEntry) []byte {
		var out []byte
		out = append(out, byte(len(entries)))
		if i8 {
			out = append(out, 1)
			out = append(out, 0, 0, 0, 0, 0, 0, 0, 128)
		} else {
			out = append(out, 0, 0, 0, 0, 128)
		}
		for _, e := range entries {
			out = append(out, byte(len(e.name)), 0, 1)
			out = append(out, e.name...)
			if withFtype {
				out = append(out, e.ftype)
			}
			if i8 {
				var ino [8]byte
				binary.BigEndian.PutUint64(ino[:], uint64(e.ino))
				out = append(out, ino[:]...)
			} else {
				var ino [4]byte
				binary.BigEndian.PutUint32(ino[:], e.ino)
				out = append(out, ino[:]...)
			}
		}
		return out
	}
	good := mk(false, true, xfsSFEntry{"a.txt", 129, 1}, xfsSFEntry{"b", 130, 1})
	de := parseShortform(good, uint64(len(good)), 512, true)
	if len(de) != 2 || de[0].name != "a.txt" || de[0].ino != 129 || de[1].name != "b" {
		t.Fatalf("ftype shortform wrong: %+v", de)
	}
	// No-ftype shape validates under a false hint.
	plain := mk(false, false, xfsSFEntry{"a.txt", 129, 0})
	if de := parseShortform(plain, uint64(len(plain)), 512, false); len(de) != 1 {
		t.Fatalf("plain shortform wrong: %+v", de)
	}
	// ... and as a fallback when the hint says ftype (upgraded fs).
	if de := parseShortform(plain, uint64(len(plain)), 512, true); len(de) != 1 {
		t.Fatalf("hint fallback wrong: %+v", de)
	}
	// 8-byte inodes.
	wide := mk(true, true, xfsSFEntry{"w", 70000, 1})
	if de := parseShortform(wide, uint64(len(wide)), 1<<40, true); len(de) != 1 || de[0].ino != 70000 {
		t.Fatalf("i8 shortform wrong: %+v", de)
	}
	// Corrupt shapes yield nothing: bad count, truncation, bad
	// inode, size mismatch, implausible name.
	bad := append([]byte(nil), good...)
	bad[0] = 9
	if parseShortform(bad, uint64(len(bad)), 512, true) != nil {
		t.Error("bad count must yield nil")
	}
	if parseShortform(good[:len(good)-2], uint64(len(good)), 512, true) != nil {
		t.Error("truncation must yield nil")
	}
	zero := mk(false, true, xfsSFEntry{"a.txt", 0, 1})
	if parseShortform(zero, uint64(len(zero)), 512, true) != nil {
		t.Error("zero inode must yield nil")
	}
	if parseShortform(good, uint64(len(good))+1, 512, true) != nil {
		t.Error("size mismatch must yield nil")
	}
	slash := mk(false, true, xfsSFEntry{"a/b", 129, 1})
	if parseShortform(slash, uint64(len(slash)), 512, true) != nil {
		t.Error("implausible name must yield nil")
	}
	if parseShortform([]byte{0, 0, 0, 0, 0, 128}, 6, 512, true) != nil {
		t.Error("empty dir must yield nil entries")
	}
}

// TestXFSBlockDirDropsNamesKeepsContent pins the documented
// block/btree-directory gap: flipping the unlinked subdir's format
// byte from shortform to extents (then btree) must drop its names
// while the chunk scan still recovers the child's content. The
// mutated images keep valid inode CRCs so the parser exercises the
// format path, not a corruption path (the parser never reads CRCs).
func TestXFSBlockDirDropsNamesKeepsContent(t *testing.T) {
	raw, err := os.ReadFile(buildTestXFS(t))
	if err != nil {
		t.Fatal(err)
	}
	const ino134 = 16*xfsTestBlock + 6*512
	for _, format := range []byte{xfsFmtExtents, xfsFmtBtree} {
		cp := append([]byte(nil), raw...)
		cp[ino134+5] = format
		xfsTestCRC(cp[ino134:ino134+512], 100)
		path := filepath.Join(t.TempDir(), "xfs.img")
		if err := os.WriteFile(path, cp, 0644); err != nil {
			t.Fatal(err)
		}
		vol, _ := openTestXFS(t, path)
		sub, ok := vol.readInode(134)
		if !ok || !sub.isDir {
			t.Fatalf("format %d: subdir unreadable", format)
		}
		if sub.names != nil {
			t.Errorf("format %d: block dir must yield nil names, got %v", format, sub.names)
		}
		ents, err := vol.Entries()
		if err != nil {
			t.Fatal(err)
		}
		var child *FSEntry
		for i := range ents {
			if strings.Contains(ents[i].Note, "inode:135") {
				child = &ents[i]
			}
		}
		if child == nil {
			t.Fatalf("format %d: inode 135 content lost", format)
		}
		if len(child.Names) != 0 {
			t.Errorf("format %d: child must lose names, got %v", format, child.Names)
		}
		if !child.Deleted || len(child.Extents) == 0 {
			t.Errorf("format %d: child must stay deleted with content: %+v", format, child)
		}
		var rooted bool
		for i := range ents {
			for _, n := range ents[i].Names {
				if n == "hello.txt" {
					rooted = true
				}
			}
		}
		if !rooted {
			t.Errorf("format %d: root shortform names must survive", format)
		}
	}
}

// TestXFSFragmentedTrimKeepsHead pins logical-order trimming: a
// two-fragment file whose physical order reverses its logical order
// must keep the logical head bytes. Trimming in physical order keeps
// slack and drops real head content on every fragmented file with a
// non-block-multiple size.
func TestXFSFragmentedTrimKeepsHead(t *testing.T) {
	vol, _ := openTestXFS(t, buildTestXFS(t))
	bs := int64(xfsTestBlock)
	fork := append(xfsExtentRec(1, 5, 1), xfsExtentRec(0, 9, 1)...)
	got := vol.mapExtents(fork, uint64(bs+bs/2))
	want := []FSExtent{{Start: 5 * bs, Len: bs / 2}, {Start: 9 * bs, Len: bs}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("fragmented trim mismatch:\n got=%v\nwant=%v", got, want)
	}
}

// TestXFSClipLogical pins the logical clip's edges: holes contribute
// no bytes, mappings at or past EOF are stale and dropped, and
// overlapping (corrupt) mappings union instead of losing bytes.
func TestXFSClipLogical(t *testing.T) {
	vol, _ := openTestXFS(t, buildTestXFS(t))
	bs := uint64(xfsTestBlock)
	mk := func(off, start, n uint64) xfsLogExtent { return xfsLogExtent{off: off, start: start, n: n} }
	for _, tc := range []struct {
		name string
		recs []xfsLogExtent
		size uint64
		want []FSExtent
	}{
		{"hole", []xfsLogExtent{mk(0, 10, 1), mk(2, 12, 1)}, 3 * bs,
			[]FSExtent{{Start: int64(10 * bs), Len: int64(bs)}, {Start: int64(12 * bs), Len: int64(bs)}}},
		{"stale-tail", []xfsLogExtent{mk(0, 10, 1), mk(1, 11, 1)}, bs,
			[]FSExtent{{Start: int64(10 * bs), Len: int64(bs)}}},
		{"overlap", []xfsLogExtent{mk(0, 10, 2), mk(1, 11, 2)}, 3 * bs,
			[]FSExtent{{Start: int64(10 * bs), Len: int64(3 * bs)}}},
		{"mid-block", []xfsLogExtent{mk(0, 10, 1)}, bs / 2,
			[]FSExtent{{Start: int64(10 * bs), Len: int64(bs / 2)}}},
	} {
		if got := vol.clipLogical(tc.recs, tc.size); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s:\n got=%v\nwant=%v", tc.name, got, tc.want)
		}
	}
}

// TestXFSSparseChunkSkipsHoles pins the holemask granularity: each
// bit covers 4 inodes (XFS_INODES_PER_HOLEMASK_BIT), so a record
// with bits 0-1 set hides chunk inodes 0-7 and keeps 8-63.
func TestXFSSparseChunkSkipsHoles(t *testing.T) {
	raw, err := os.ReadFile(buildTestXFS(t))
	if err != nil {
		t.Fatal(err)
	}
	cp := append([]byte(nil), raw...)
	// Inobt leaf record at block 3, records start at 56: holemask
	// is the first u16 after startino.
	binary.BigEndian.PutUint16(cp[3*xfsTestBlock+56+4:], 0x0003)
	path := filepath.Join(t.TempDir(), "xfs.img")
	if err := os.WriteFile(path, cp, 0644); err != nil {
		t.Fatal(err)
	}
	vol, _ := openTestXFS(t, path)
	inos, err := vol.chunkStartinos(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(inos) != 56 || inos[0] != 136 {
		t.Errorf("sparse chunk must yield inodes 136-191, got %d starting at %d", len(inos), inos[0])
	}
	for _, ino := range inos {
		if ino < 136 || ino > 191 {
			t.Errorf("sparse chunk yields wrong inode %d", ino)
		}
	}
}

// TestXFSRefusesIncoherentGeometry pins fail-closed probing: block
// counts that disagree with each other (or overflow the volume's
// byte size) must refuse the volume, never produce wrapped offsets.
func TestXFSRefusesIncoherentGeometry(t *testing.T) {
	raw, err := os.ReadFile(buildTestXFS(t))
	if err != nil {
		t.Fatal(err)
	}
	mk := func(mut func([]byte)) string {
		cp := append([]byte(nil), raw...)
		mut(cp)
		xfsTestCRC(cp[0:512], 224)
		path := filepath.Join(t.TempDir(), "xfs.img")
		if err := os.WriteFile(path, cp, 0644); err != nil {
			t.Fatal(err)
		}
		return path
	}
	be := binary.BigEndian
	cases := map[string]string{
		"ag-exceeds-dblocks": mk(func(sb []byte) {
			be.PutUint32(sb[88:92], 1<<20) // agcount huge
			be.PutUint32(sb[84:88], 1<<20) // agblocks huge, dblocks 64
		}),
		"byte-size-overflows": mk(func(sb []byte) {
			be.PutUint64(sb[8:16], 1<<62) // dblocks*4096 overflows int64
		}),
		"dblocks-exceeds-ag-space": mk(func(sb []byte) {
			be.PutUint64(sb[8:16], 100) // dblocks 100 > 1 AG of 64
		}),
	}
	for name, path := range cases {
		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		_, err = OpenXFS(f, 0)
		f.Close()
		if err == nil {
			t.Errorf("%s: incoherent geometry must refuse", name)
		}
	}
}

// TestXFSRefusesCorruptAGFL pins loud AGFL failures: a bad v5 stash
// magic, an impossible stash count, or a stash window starting past
// the array must abort unallocated (coverage unknown), never silently
// drop or misplace blocks.
func TestXFSRefusesCorruptAGFL(t *testing.T) {
	raw, err := os.ReadFile(buildTestXFS(t))
	if err != nil {
		t.Fatal(err)
	}
	mk := func(mut func([]byte)) string {
		cp := append([]byte(nil), raw...)
		mut(cp)
		path := filepath.Join(t.TempDir(), "xfs.img")
		if err := os.WriteFile(path, cp, 0644); err != nil {
			t.Fatal(err)
		}
		return path
	}
	be := binary.BigEndian
	cases := map[string]string{
		"bad-magic": mk(func(img []byte) {
			be.PutUint32(img[1536:1540], 0)
		}),
		"wild-count": mk(func(img []byte) {
			be.PutUint32(img[512+48:512+52], 9999)
		}),
		"wild-first": mk(func(img []byte) {
			be.PutUint32(img[512+40:512+44], 9999)
		}),
	}
	for name, path := range cases {
		vol, _ := openTestXFS(t, path)
		if _, err := vol.Unallocated(); err == nil {
			t.Errorf("%s: corrupt AGFL must abort unallocated", name)
		}
	}
}

// freeBlockSet parses "agno agbno len" lines from freesp -d into
// the sorted set of free AG block numbers.
func freeBlockSet(t *testing.T, dump string) []int64 {
	t.Helper()
	set := map[int64]bool{}
	for _, l := range strings.Split(dump, "\n") {
		f := strings.Fields(l)
		if len(f) != 3 {
			continue
		}
		agno, err1 := strconv.ParseInt(f[0], 10, 64)
		start, err2 := strconv.ParseInt(f[1], 10, 64)
		n, err3 := strconv.ParseInt(f[2], 10, 64)
		if err1 != nil || err2 != nil || err3 != nil || agno != 0 || n <= 0 {
			continue
		}
		for i := int64(0); i < n; i++ {
			set[start+i] = true
		}
	}
	return sortedKeys(set)
}

// unallocBlockSet expands Unallocated byte extents into the sorted
// set of free AG block numbers (single-AG fixture).
func unallocBlockSet(t *testing.T, free []FSExtent) []int64 {
	t.Helper()
	set := map[int64]bool{}
	for _, e := range free {
		if e.Start%xfsTestBlock != 0 || e.Len%xfsTestBlock != 0 {
			t.Fatalf("unmerged odd extent %v", e)
		}
		for b := e.Start / xfsTestBlock; b < (e.Start+e.Len)/xfsTestBlock; b++ {
			set[b] = true
		}
	}
	return sortedKeys(set)
}

func sortedKeys(set map[int64]bool) []int64 {
	out := make([]int64, 0, len(set))
	for b := range set {
		out = append(out, b)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

func equalBlockSet(a, b []int64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestXFSOracleCrossCheck replays the hand-built fixtures through
// real xfs_db: superblock, AG headers, exact free extents, inode
// fields, shortform names, and the bmbt bmap decode. Skipped when
// xfs_db is absent (CI has no xfsprogs); run locally with xfsprogs
// on PATH. The bmap case is the format proof for the
// memory-sourced bmbt layout: xfs_db and the parser decode the
// same bytes independently.
func TestXFSOracleCrossCheck(t *testing.T) {
	xfsdb, err := exec.LookPath("xfs_db")
	if err != nil {
		if _, err2 := os.Stat("/sbin/xfs_db"); err2 == nil {
			xfsdb = "/sbin/xfs_db"
		} else if _, err2 := os.Stat("/usr/sbin/xfs_db"); err2 == nil {
			xfsdb = "/usr/sbin/xfs_db"
		} else {
			t.Skip("needs xfs_db (install xfsprogs to cross-check)")
		}
	}
	run := func(path string, cmds ...string) string {
		t.Helper()
		args := []string{"-r"}
		for _, c := range cmds {
			args = append(args, "-c", c)
		}
		args = append(args, path)
		// A confused xfs_db can spin instead of erroring (seen
		// during development); never hang the suite.
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, xfsdb, args...).CombinedOutput()
		if err != nil {
			t.Fatalf("xfs_db %v: %v\n%s", cmds, err, out)
		}
		return string(out)
	}
	v5 := buildTestXFS(t)
	sb := run(v5, "sb 0", "print blocksize dblocks agcount agblocks rootino versionnum inodesize")
	for _, want := range []string{
		"blocksize = 4096", "dblocks = 64", "agcount = 1", "agblocks = 64",
		"rootino = 128", "versionnum = 0xb4a5", "inodesize = 512",
	} {
		if !strings.Contains(sb, want) {
			t.Errorf("sb lacks %q:\n%s", want, sb)
		}
	}
	agf := run(v5, "agf 0", "print roots levels flfirst flcount freeblks longest refcntroot refcntlevel rmapblocks refcntblocks")
	for _, want := range []string{
		"roots[0-2] = 0:1 1:2 2:4", "levels[0-2] = 0:1 1:1 2:1",
		"flfirst = 1", "flcount = 1", "freeblks = 43", "longest = 40",
		"refcntroot = 12", "refcntlevel = 1", "rmapblocks = 1", "refcntblocks = 1",
	} {
		if !strings.Contains(agf, want) {
			t.Errorf("agf lacks %q:\n%s", want, agf)
		}
	}
	// Free BLOCKS must match my Unallocated exactly. Compared as
	// sets, not lines: freesp -d lists raw btree records plus
	// AGFL blocks unmerged, while Unallocated merges adjacency
	// (v4 block 5 sits in the AGFL next to btree record (4,1)).
	vol, _ := openTestXFS(t, v5)
	free, err := vol.Unallocated()
	if err != nil {
		t.Fatal(err)
	}
	dump := run(v5, "freesp -d -a 0")
	if got, want := freeBlockSet(t, dump), unallocBlockSet(t, free); !equalBlockSet(got, want) {
		t.Errorf("freesp block set mismatch:\n got=%v\nwant=%v\nraw:\n%s", got, want, dump)
	}
	ino := run(v5, "inode 130", "print core.nlinkv2 core.size core.format core.nextents")
	for _, want := range []string{"core.nlinkv2 = 0", "core.size = 100", "core.format = 2 (extents)", "core.nextents = 1"} {
		if !strings.Contains(ino, want) {
			t.Errorf("inode 130 lacks %q:\n%s", want, ino)
		}
	}
	// Full print decodes the ftype-carrying entries as u3.sfdir3:
	// xfs_db 6.6 selects that union member when INCOMPAT_FINOBT
	// is set (bit-bisected on this image: 0x1 decodes clean,
	// 0x0/0x2/0x4/0x8 fall back to the ftype-less sfdir2 and
	// misread every inumber). The fixture carries real-mkfs
	// incompat 0xb, so names and inumbers decode exact.
	sf := run(v5, "inode 128", "print")
	for _, want := range []string{`"hello.txt"`, `"live2.txt"`, `"sub"`, "inumber.i4 = 129", "inumber.i4 = 136", "inumber.i4 = 134"} {
		if !strings.Contains(sf, want) {
			t.Errorf("root shortform lacks %q:\n%s", want, sf)
		}
	}
	// The bmbt root and leaf, each decoded independently by
	// xfs_db: the root's capacity-sized pointer array must name
	// block 8, and the leaf must hold extent (0,9,1).
	root := run(v5, "inode 132", "print u3.bmbt")
	for _, want := range []string{"level = 1", "numrecs = 1", "1:[0]", "ptrs[1] = 8"} {
		if !strings.Contains(root, want) {
			t.Errorf("bmbt root lacks %q:\n%s", want, root)
		}
	}
	leaf := run(v5, "fsb 8", "type bmapbtd", "print")
	for _, want := range []string{"owner = 132", "(correct)", "1:[0,9,1,0]"} {
		if !strings.Contains(leaf, want) {
			t.Errorf("bmbt leaf lacks %q:\n%s", want, leaf)
		}
	}
	bmap := run(v5, "inode 132", "bmap")
	if !strings.Contains(bmap, "startblock 9") || !strings.Contains(bmap, "count 1") {
		t.Errorf("bmap disagrees on the bmbt file:\n%s", bmap)
	}
	// v4 flavor: version, exact free extents, a file, shortform names.
	v4 := buildTestXFSv4(t)
	sb4 := run(v4, "sb 0", "print versionnum inodesize inopblock")
	for _, want := range []string{"versionnum = 0xb4a4", "inodesize = 256", "inopblock = 16"} {
		if !strings.Contains(sb4, want) {
			t.Errorf("v4 sb lacks %q:\n%s", want, sb4)
		}
	}
	vol4, _ := openTestXFS(t, v4)
	free4, err := vol4.Unallocated()
	if err != nil {
		t.Fatal(err)
	}
	dump4 := run(v4, "freesp -d -a 0")
	if got, want := freeBlockSet(t, dump4), unallocBlockSet(t, free4); !equalBlockSet(got, want) {
		t.Errorf("v4 freesp block set mismatch:\n got=%v\nwant=%v\nraw:\n%s", got, want, dump4)
	}
	ino4 := run(v4, "inode 130", "print core.nlinkv2 core.size core.format")
	for _, want := range []string{"core.nlinkv2 = 0", "core.size = 100", "core.format = 2 (extents)"} {
		if !strings.Contains(ino4, want) {
			t.Errorf("v4 inode 130 lacks %q:\n%s", want, ino4)
		}
	}
	sf4 := run(v4, "inode 128", "print")
	for _, want := range []string{`"hello.txt"`, "inumber.i4 = 129"} {
		if !strings.Contains(sf4, want) {
			t.Errorf("v4 root shortform lacks %q:\n%s", want, sf4)
		}
	}
	leaf4 := run(v4, "fsb 12", "type bmapbtd", "print")
	for _, want := range []string{"1:[0,13,1,0]"} {
		if !strings.Contains(leaf4, want) {
			t.Errorf("v4 bmbt leaf lacks %q:\n%s", want, leaf4)
		}
	}
	bmap4 := run(v4, "inode 132", "bmap")
	if !strings.Contains(bmap4, "startblock 13") || !strings.Contains(bmap4, "count 1") {
		t.Errorf("v4 bmap disagrees on the bmbt file:\n%s", bmap4)
	}
	// Independently verify partially filled internal nodes. Pointers follow
	// capacity-sized key arrays in both short and long on-disk trees.
	raw, err := os.ReadFile(v5)
	if err != nil {
		t.Fatal(err)
	}
	be := binary.BigEndian
	const bs = xfsTestBlock
	node := mkXFSBtreeLeaf(true, xfsMagicBnoV5, 4*8, nil, 8)
	be.PutUint16(node[4:6], 1)
	be.PutUint16(node[6:8], 1)
	copy(node[56:64], u32rec(13, 3))
	be.PutUint32(node[56+((bs-56)/12)*8:], 1)
	xfsTestCRC(node, 52)
	copy(raw[4*bs:], node)
	be.PutUint32(raw[512+16:], 4)
	be.PutUint32(raw[512+28:], 2)
	xfsTestCRC(raw[512:1024], 216)
	node = mkXFSBmbtLeaf(true, 11, 132, nil)
	be.PutUint16(node[4:6], 1)
	be.PutUint64(node[72+((bs-72)/16)*8:], 8)
	xfsTestCRC(node, 64)
	copy(raw[11*bs:], node)
	const ino132 = 16*bs + 4*512
	fork := xfsBmbtRoot(336, 11)
	be.PutUint16(fork[:2], 2)
	copy(raw[ino132+176:ino132+512], fork)
	xfsTestCRC(raw[ino132:ino132+512], 100)
	deep := filepath.Join(t.TempDir(), "deep.img")
	if err := os.WriteFile(deep, raw, 0600); err != nil {
		t.Fatal(err)
	}
	deepVol, _ := openTestXFS(t, deep)
	deepFree, err := deepVol.Unallocated()
	if err != nil {
		t.Fatal(err)
	}
	deepDump := run(deep, "freesp -d -a 0")
	if got, want := freeBlockSet(t, deepDump), unallocBlockSet(t, deepFree); !equalBlockSet(got, want) {
		t.Errorf("deep freespace mismatch: got %v want %v\n%s", got, want, deepDump)
	}
	deepMap := run(deep, "inode 132", "bmap")
	in, ok := deepVol.readInode(132)
	if !strings.Contains(deepMap, "startblock 9") || !strings.Contains(deepMap, "count 1") || !ok || in.degraded != "" || !reflect.DeepEqual(in.extents, []FSExtent{{Start: 9 * bs, Len: 50}}) {
		t.Errorf("deep bmap mismatch: inode=%+v, ok=%v\n%s", in, ok, deepMap)
	}
}
