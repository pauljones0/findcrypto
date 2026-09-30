package detector

import (
	"encoding/binary"
	"fmt"
	"io"
	"sort"
)

// XFS parsing for the filesystem layer: superblock, allocation-group
// headers, the freespace (bnobt) and inode (inobt) B+trees, inode
// chunks (live and unlinked), shortform directories, extent maps, and
// bnobt-plus-AGFL unallocated ranges.
//
// Layouts are checked against xfs_db on v4 and v5 fixtures, including
// shortform entries, extent records, and internal bnobt/bmbt nodes.
// Sector geometry is also checked on real mkfs.xfs images. Encoded
// filesystem block numbers and fork offsets follow kernel libxfs's
// xfs_format.h; capacity-sized pointer arrays follow xfs_alloc_btree.h
// and xfs_bmap_btree.h. Sparse inode holemask order and granularity
// (4 inodes per bit, LSB first, set means absent) follow xfs_format.h;
// no real sparse chunk was available for an independent cross-check.
//
// XFS deletes names and content separately like ext: unlinking
// removes the directory entry (shortform compacts it away) and drops
// the link count while the inode core and its extent map linger until
// the chunk is reused. Recovery therefore yields unlinked-inode
// content (links=0) with names only when a surviving directory still
// references the inode. Inobt free bits are ignored on purpose:
// freeing an inode clears them while the core stays readable.
//
// Coverage notes, explicit:
//   - Directories in block or btree format contribute no names in
//     this version (their content is still recovered by the chunk
//     scan); shortform covers fresh and small filesystems exactly.
//   - AGFL-stashed blocks join the unallocated set, exactly as
//     xfs_db freesp counts them. A stash that cannot be read, has a
//     bad v5 magic, or names a wild window aborts like a corrupt
//     bnobt (coverage unknown); only a single out-of-range entry
//     value is skipped, since no such block exists to scan.

const (
	xfsMagicSB   = 0x58465342 // "XFSB"
	xfsMagicAGF  = 0x58414746 // "XAGF"
	xfsMagicAGI  = 0x58414749 // "XAGI"
	xfsMagicAGFL = 0x5841464c // "XAFL" (v5 only; v4 AGFL has no header)
	xfsMagicIno  = 0x494e     // "IN"

	xfsMagicBnoV4 = 0x41425442 // "ABTB"
	xfsMagicBnoV5 = 0x41423342 // "AB3B"
	xfsMagicInoV4 = 0x49414254 // "IABT"
	xfsMagicInoV5 = 0x49414233 // "IAB3"
	// bmbt magics, confirmed by the passing oracle bmap walks
	// (verifier-checked reads fail on a wrong magic).
	xfsMagicBmbtV4 = 0x424d4150 // "BMAP"
	xfsMagicBmbtV5 = 0x424d4133 // "BMA3"
)

const (
	xfsModeFile = 0x8000
	xfsModeDir  = 0x4000
	xfsModeMask = 0xF000
)

const (
	xfsFmtLocal   = 1
	xfsFmtExtents = 2
	xfsFmtBtree   = 3
)

// XFSVol is a parsed XFS superblock plus its image reader.
type XFSVol struct {
	r         io.ReaderAt
	base      int64
	blockSize int64
	sectSize  int64
	dblocks   int64 // total filesystem blocks
	agCount   int64
	agBlocks  int64
	rootino   uint64
	inodesize int64
	inopblock int64
	inopblog  uint8
	agblklog  uint8
	crc       bool // v5 layouts (inode v3 core, 56-byte btree headers)
	ftype     bool // directory entries carry a filetype byte
	maxino    uint64
	maxBytes  int64
}

// xfsFtypeBit marks filetype bytes in directory entries (superblock
// features2). v5 filesystems always use them; v4 may not. Pinned by
// diffing mkfs -n ftype=0/1 images (only this bit differs).
const xfsFtypeBit = 0x200

// OpenXFS validates the superblock at base plus the AG 0 header
// magics and returns the volume. Version nibbles 4 (v4, no crc) and
// 5 (v5, crc) are supported; anything older is refused loudly.
func OpenXFS(r io.ReaderAt, base int64) (*XFSVol, error) {
	var sb [512]byte
	if _, err := r.ReadAt(sb[:], base); err != nil {
		return nil, fmt.Errorf("cannot read superblock: %w", err)
	}
	be := binary.BigEndian
	if be.Uint32(sb[0:4]) != xfsMagicSB {
		return nil, fmt.Errorf("no XFS signature")
	}
	blockSize := int64(be.Uint32(sb[4:8]))
	if blockSize < 512 || blockSize > 65536 || blockSize&(blockSize-1) != 0 {
		return nil, fmt.Errorf("bad block size %d", blockSize)
	}
	sectSize := int64(be.Uint16(sb[102:104]))
	if sectSize < 512 || sectSize > 32768 || sectSize&(sectSize-1) != 0 {
		return nil, fmt.Errorf("bad sector size %d", sectSize)
	}
	if sectSize > blockSize {
		return nil, fmt.Errorf("sector size exceeds block size")
	}
	dblocks := int64(be.Uint64(sb[8:16]))
	agcount := int64(be.Uint32(sb[88:92]))
	agblocks := int64(be.Uint32(sb[84:88]))
	if dblocks <= 0 || agcount <= 0 || agblocks <= 0 {
		return nil, fmt.Errorf("bad geometry")
	}
	if agcount > 1<<20 || agblocks > 1<<32 {
		return nil, fmt.Errorf("implausible geometry")
	}
	// Coherence: every legal block offset must fit int64 and land
	// inside dblocks, so wrapped offsets are impossible. The AG
	// space must cover dblocks exactly (last AG partial or full),
	// and the volume's byte size must fit int64 alongside base.
	if (agcount-1)*agblocks >= dblocks || dblocks > agcount*agblocks {
		return nil, fmt.Errorf("ag geometry disagrees with dblocks")
	}
	if dblocks > (1<<63-1)/blockSize {
		return nil, fmt.Errorf("volume byte size overflows")
	}
	if base < 0 || dblocks*blockSize > (1<<63-1)-base {
		return nil, fmt.Errorf("volume end overflows")
	}
	rootino := be.Uint64(sb[56:64])
	inodesize := int64(be.Uint16(sb[104:106]))
	inopblock := int64(be.Uint16(sb[106:108]))
	if inodesize != 256 && inodesize != 512 && inodesize != 1024 && inodesize != 2048 {
		return nil, fmt.Errorf("bad inode size %d", inodesize)
	}
	if inopblock <= 0 || inopblock*inodesize != blockSize {
		return nil, fmt.Errorf("bad inodes per block %d", inopblock)
	}
	version := be.Uint16(sb[100:102])
	var crc bool
	switch version & 0xF {
	case 5:
		crc = true
		if features := be.Uint32(sb[216:220]); features & ^uint32(0xf) != 0 {
			return nil, fmt.Errorf("unsupported XFS incompatible features %#x", features)
		}
	case 4:
		crc = false
	default:
		return nil, fmt.Errorf("unsupported XFS version %d (want 4 or 5)", version&0xF)
	}
	if be.Uint64(sb[16:24]) != 0 {
		return nil, fmt.Errorf("XFS realtime volumes are unsupported")
	}
	// v5 implies filetype bytes (mkfs refuses -n ftype=0 with
	// crc); v4 reads the bit. Upgraded filesystems can mix
	// shapes, so this is only a hint: the shortform parser
	// accepts whichever shape validates exactly.
	ftype := crc || be.Uint32(sb[200:204])&xfsFtypeBit != 0
	v := &XFSVol{
		r: r, base: base, blockSize: blockSize, sectSize: sectSize,
		dblocks: dblocks, agCount: agcount, agBlocks: agblocks,
		rootino: rootino, inodesize: inodesize, inopblock: inopblock,
		inopblog: sb[123], agblklog: sb[124], crc: crc, ftype: ftype,
		maxBytes: dblocks * blockSize,
	}
	if v.inopblog > 32 || v.agblklog > 32 || v.inopblog+v.agblklog >= 64 {
		return nil, fmt.Errorf("bad geometry logs")
	}
	if int64(uint64(1)<<v.inopblog) != inopblock {
		return nil, fmt.Errorf("inopblog %d disagrees with inodes per block %d", v.inopblog, inopblock)
	}
	if v.agblklog < 1 || int64(uint64(1)<<v.agblklog) < agblocks {
		return nil, fmt.Errorf("agblklog %d disagrees with agblocks %d", v.agblklog, agblocks)
	}
	v.maxino = uint64(agcount) << (v.agblklog + v.inopblog)
	if rootino == 0 || rootino >= v.maxino {
		return nil, fmt.Errorf("bad root inode %d", rootino)
	}
	// The AG 0 header magics make a false probe near-impossible:
	// three independent signatures must all match.
	var hdr [4]byte
	if _, err := r.ReadAt(hdr[:], base+sectSize); err != nil || be.Uint32(hdr[:]) != xfsMagicAGF {
		return nil, fmt.Errorf("no XFS AGF signature")
	}
	if _, err := r.ReadAt(hdr[:], base+2*sectSize); err != nil || be.Uint32(hdr[:]) != xfsMagicAGI {
		return nil, fmt.Errorf("no XFS AGI signature")
	}
	return v, nil
}

// agLen returns the filesystem-block length of allocation group agno.
func (v *XFSVol) agLen(agno int64) int64 {
	if agno == v.agCount-1 {
		return v.dblocks - agno*v.agBlocks
	}
	return v.agBlocks
}

// agf holds the AGF fields the volume needs: the freespace root
// plus the AGFL window.
type agf struct {
	bnoRoot  uint32
	bnoLevel uint32 // tree height: 1 means the root is the only leaf
	flFirst  uint32
	flCount  uint32
}

func (v *XFSVol) readAGF(agno int64) (*agf, error) {
	var raw [64]byte
	if _, err := v.r.ReadAt(raw[:], v.base+agno*v.agBlocks*v.blockSize+v.sectSize); err != nil {
		return nil, fmt.Errorf("cannot read AG %d AGF: %w", agno, err)
	}
	be := binary.BigEndian
	if be.Uint32(raw[0:4]) != xfsMagicAGF {
		return nil, fmt.Errorf("bad AG %d AGF magic", agno)
	}
	if int64(be.Uint32(raw[8:12])) != agno {
		return nil, fmt.Errorf("AGF seqno mismatch in AG %d", agno)
	}
	if int64(be.Uint32(raw[12:16])) != v.agLen(agno) {
		return nil, fmt.Errorf("AG %d length mismatch", agno)
	}
	return &agf{
		bnoRoot:  be.Uint32(raw[16:20]),
		bnoLevel: be.Uint32(raw[28:32]),
		flFirst:  be.Uint32(raw[40:44]),
		flCount:  be.Uint32(raw[48:52]),
	}, nil
}

// agi holds the AGI inode-btree root.
type agi struct {
	inoRoot  uint32
	inoLevel uint32 // tree height: 1 means the root is the only leaf
}

func (v *XFSVol) readAGI(agno int64) (*agi, error) {
	var raw [40]byte
	if _, err := v.r.ReadAt(raw[:], v.base+agno*v.agBlocks*v.blockSize+2*v.sectSize); err != nil {
		return nil, fmt.Errorf("cannot read AG %d AGI: %w", agno, err)
	}
	be := binary.BigEndian
	if be.Uint32(raw[0:4]) != xfsMagicAGI {
		return nil, fmt.Errorf("bad AG %d AGI magic", agno)
	}
	if int64(be.Uint32(raw[8:12])) != agno {
		return nil, fmt.Errorf("AGI seqno mismatch in AG %d", agno)
	}
	return &agi{
		inoRoot:  be.Uint32(raw[20:24]),
		inoLevel: be.Uint32(raw[24:28]),
	}, nil
}

// xfsNullAGB is the null AG-relative block number (no sibling).
const xfsNullAGB = 0xFFFFFFFF

// btreeLeaves collects every leaf record of one AG short-pointer
// B+tree (bnobt or inobt): descend the left spine from the root,
// then chain leaves right via sibling pointers. No key comparison
// is needed, so key formats cannot mislead; every hop validates
// magic, version, level, and bounds, and a wrong keySize refuses
// loudly at the first child instead of misreading.
func (v *XFSVol) btreeLeaves(agno int64, root uint32, height uint32, keySize, recSize int, magicV4, magicV5 uint32, what string) ([][]byte, error) {
	if height < 1 || height > 8 {
		return nil, fmt.Errorf("AG %d %s has impossible height %d", agno, what, height)
	}
	if keySize != 4 && keySize != 8 {
		return nil, fmt.Errorf("AG %d %s has impossible key size %d", agno, what, keySize)
	}
	agLen := v.agLen(agno)
	agBase := v.base + agno*v.agBlocks*v.blockSize
	readBlk := func(agbno uint32) ([]byte, error) {
		if uint64(agbno) >= uint64(agLen) {
			return nil, fmt.Errorf("AG %d %s block %d out of range", agno, what, agbno)
		}
		buf := make([]byte, v.blockSize)
		if _, err := v.r.ReadAt(buf, agBase+int64(agbno)*v.blockSize); err != nil {
			return nil, fmt.Errorf("cannot read AG %d %s block %d: %w", agno, what, agbno, err)
		}
		return buf, nil
	}
	// headerOf validates one block and returns its level, record
	// count, and the offset where keys/records start.
	headerOf := func(buf []byte, agbno uint32) (level uint32, nrecs int, start int, err error) {
		magic := binary.BigEndian.Uint32(buf[0:4])
		switch magic {
		case magicV4:
			start = 16
		case magicV5:
			start = 56
		default:
			return 0, 0, 0, fmt.Errorf("AG %d %s block %d has bad magic %#x", agno, what, agbno, magic)
		}
		level = uint32(binary.BigEndian.Uint16(buf[4:6]))
		nrecs = int(binary.BigEndian.Uint16(buf[6:8]))
		maxRecs := (int(v.blockSize) - start) / recSize
		if level > 0 {
			maxRecs = (int(v.blockSize) - start) / (keySize + 4)
		}
		if nrecs < 0 || nrecs > maxRecs {
			return 0, 0, 0, fmt.Errorf("AG %d %s block %d has impossible count %d", agno, what, agbno, nrecs)
		}
		return level, nrecs, start, nil
	}
	blk, err := readBlk(root)
	if err != nil {
		return nil, err
	}
	level, nrecs, start, err := headerOf(blk, root)
	if err != nil {
		return nil, err
	}
	if level != height-1 {
		return nil, fmt.Errorf("AG %d %s root level %d disagrees with height %d", agno, what, level, height)
	}
	// Descend the left spine: ptrs[0] of each node.
	for level > 0 {
		maxNodeRecs := (int(v.blockSize) - start) / (keySize + 4)
		ptrsAt := start + maxNodeRecs*keySize
		if nrecs < 1 || nrecs > maxNodeRecs || ptrsAt+nrecs*4 > int(v.blockSize) {
			return nil, fmt.Errorf("AG %d %s node overruns its block", agno, what)
		}
		child := binary.BigEndian.Uint32(blk[ptrsAt : ptrsAt+4])
		blk, err = readBlk(child)
		if err != nil {
			return nil, err
		}
		var childStart int
		var childNrecs int
		var childLevel uint32
		childLevel, childNrecs, childStart, err = headerOf(blk, child)
		if err != nil {
			return nil, err
		}
		if childLevel != level-1 {
			return nil, fmt.Errorf("AG %d %s level jumps %d to %d", agno, what, level, childLevel)
		}
		level, nrecs, start = childLevel, childNrecs, childStart
	}
	// Chain the leaf level right.
	var out [][]byte
	hops := int64(0)
	for {
		hops++
		if hops > agLen+1 {
			return nil, fmt.Errorf("AG %d %s leaf chain loops", agno, what)
		}
		end := start + nrecs*recSize
		if end > int(v.blockSize) {
			return nil, fmt.Errorf("AG %d %s leaf overruns its block", agno, what)
		}
		for i := 0; i < nrecs; i++ {
			rec := make([]byte, recSize)
			copy(rec, blk[start+i*recSize:start+(i+1)*recSize])
			out = append(out, rec)
		}
		next := binary.BigEndian.Uint32(blk[12:16])
		if next == xfsNullAGB {
			return out, nil
		}
		blk, err = readBlk(next)
		if err != nil {
			return nil, err
		}
		var nextLevel uint32
		nextLevel, nrecs, start, err = headerOf(blk, next)
		if err != nil {
			return nil, err
		}
		if nextLevel != 0 {
			return nil, fmt.Errorf("AG %d %s leaf chain reaches level %d", agno, what, nextLevel)
		}
	}
}

// agflBlocks returns the stashed free blocks of the AGFL window:
// flCount entries starting at flFirst (modulo capacity). A stash
// that cannot be read, has a bad v5 magic, or names a window outside
// the array aborts like a corrupt bnobt (coverage unknown); only a
// single out-of-range entry value is skipped, since no such block
// exists to scan.
func (v *XFSVol) agflBlocks(agno int64, g *agf) ([]uint32, error) {
	var arrayOff int64
	var capEntries int64
	if v.crc {
		arrayOff, capEntries = 36, (512-36)/4
	} else {
		arrayOff, capEntries = 0, 512/4
	}
	if v.sectSize > 512 {
		// Larger sectors widen the stash array past the first
		// 512 bytes; capacity scales with the sector.
		capEntries = (v.sectSize - arrayOff) / 4
	}
	if capEntries < 1 || g.flCount > uint32(capEntries) || (g.flCount > 0 && g.flFirst >= uint32(capEntries)) {
		return nil, fmt.Errorf("AG %d AGFL window (%d+%d) exceeds capacity %d", agno, g.flFirst, g.flCount, capEntries)
	}
	raw := make([]byte, arrayOff+capEntries*4)
	base := v.base + agno*v.agBlocks*v.blockSize + 3*v.sectSize
	if _, err := v.r.ReadAt(raw, base); err != nil {
		return nil, fmt.Errorf("cannot read AG %d AGFL: %w", agno, err)
	}
	if v.crc && binary.BigEndian.Uint32(raw[0:4]) != xfsMagicAGFL {
		return nil, fmt.Errorf("bad AG %d AGFL magic", agno)
	}
	var out []uint32
	for i := uint32(0); i < g.flCount; i++ {
		slot := (g.flFirst + i) % uint32(capEntries)
		bno := binary.BigEndian.Uint32(raw[arrayOff+int64(slot)*4:])
		if uint64(bno) >= uint64(v.agLen(agno)) {
			continue
		}
		out = append(out, bno)
	}
	return out, nil
}

// xfsInode is the decoded subset of an inode core.
type xfsInode struct {
	num     uint64
	mode    uint16
	links   uint32
	size    uint64
	isDir   bool
	extents []FSExtent // file content (dirs: none in this version)
	names   []xfsDirent
	// degraded marks visibly incomplete content: btree-mapped files
	// whose extent btree would not validate keep their entry (never
	// a silent loss) with this suffix on the note.
	degraded string
}

// xfsDirent is one shortform directory entry.
type xfsDirent struct {
	ino  uint64
	name string
}

// inodeLoc maps an inode number to its image offset.
func (v *XFSVol) inodeLoc(ino uint64) (agno int64, abs int64, ok bool) {
	bits := v.agblklog + v.inopblog
	agno = int64(ino >> bits)
	if agno >= v.agCount {
		return 0, 0, false
	}
	agino := ino & (uint64(1)<<bits - 1)
	agbno := agino >> v.inopblog
	if int64(agbno) >= v.agLen(agno) {
		return 0, 0, false
	}
	off := int64(agino&(uint64(v.inopblock)-1)) * v.inodesize
	abs = v.base + (agno*v.agBlocks+int64(agbno))*v.blockSize + off
	return agno, abs, true
}

// readInode decodes inode ino. Unlinked rows decode identically; the
// caller decides deletion from the link count. Garbage rows (bad
// magic, version, mode, or geometry) report ok=false and are
// skipped, exactly like ext's unreadable rows.
func (v *XFSVol) readInode(ino uint64) (*xfsInode, bool) {
	_, abs, ok := v.inodeLoc(ino)
	if !ok {
		return nil, false
	}
	raw := make([]byte, v.inodesize)
	if _, err := v.r.ReadAt(raw, abs); err != nil {
		return nil, false
	}
	be := binary.BigEndian
	if be.Uint16(raw[0:2]) != xfsMagicIno {
		return nil, false
	}
	mode := be.Uint16(raw[2:4])
	if mode&xfsModeMask != xfsModeFile && mode&xfsModeMask != xfsModeDir {
		// Only files and directories carry recoverable
		// content or names; anything else is skipped.
		// (Symlinks use local/extents forks too, but their
		// tiny targets are covered by raw scanning; see the
		// FILESYSTEMS notes.)
		return nil, false
	}
	version := raw[4]
	var forkBase int64
	switch version {
	case 3:
		forkBase = 176
	case 2:
		forkBase = 100
	default:
		return nil, false
	}
	if forkBase >= v.inodesize {
		return nil, false
	}
	format := raw[5]
	links := be.Uint32(raw[16:20])
	size := be.Uint64(raw[56:64])
	if size > uint64(v.maxBytes) {
		return nil, false
	}
	forkOff := int64(raw[82]) * 8
	forkEnd := v.inodesize
	if raw[82] != 0 {
		if forkOff > v.inodesize-forkBase {
			return nil, false
		}
		forkEnd = forkBase + forkOff
	}
	in := &xfsInode{
		num: ino, mode: mode, links: links, size: size,
		isDir: mode&xfsModeMask == xfsModeDir,
	}
	fork := raw[forkBase:forkEnd]
	forkAbs := abs + forkBase
	switch format {
	case xfsFmtLocal:
		if in.isDir {
			in.names = parseShortform(fork, size, v.maxino, v.ftype)
			// A shortform that will not validate drops
			// this directory's names (nil); content is
			// unaffected since the chunk scan owns it.
		} else if size > 0 {
			if uint64(len(fork)) < size {
				return nil, false
			}
			// Inline file content, exposed exactly like
			// NTFS resident values: just the value bytes.
			in.extents = []FSExtent{{Start: forkAbs, Len: int64(size)}}
		}
	case xfsFmtExtents:
		if in.isDir {
			// Block-format directory: names unavailable
			// in this version (see the package note).
			break
		}
		nextents := be.Uint32(raw[76:80])
		if uint64(nextents) > uint64(len(fork))/16 {
			return nil, false
		}
		in.extents = v.mapExtents(fork[:nextents*16], size)
	case xfsFmtBtree:
		if in.isDir {
			break
		}
		ext, ok := v.mapBmbt(fork, size)
		if !ok {
			in.degraded = ":btree-extents-unparsed"
			break
		}
		in.extents = ext
	default:
		return nil, false
	}
	return in, true
}

// mapExtents decodes inline extent records to image-absolute,
// size-trimmed content ranges. Holes, unwritten preallocation gaps,
// and out-of-range records are skipped: holes have no content, and
// anything outside the volume is corruption, never data.
func (v *XFSVol) mapExtents(fork []byte, size uint64) []FSExtent {
	be := binary.BigEndian
	var recs []xfsLogExtent
	for o := 0; o+16 <= len(fork); o += 16 {
		l0 := be.Uint64(fork[o : o+8])
		l1 := be.Uint64(fork[o+8 : o+16])
		startoff := (l0 >> 9) & (uint64(1)<<54 - 1)
		startblock := ((l0 & 0x1FF) << 43) | (l1 >> 21)
		count := l1 & 0x1FFFFF
		physical, ok := v.fsbPhysical(startblock, count)
		if l0>>63 != 0 || !ok {
			continue
		}
		recs = append(recs, xfsLogExtent{off: startoff, start: physical, n: count})
	}
	return v.clipLogical(recs, size)
}

// XFS filesystem block numbers encode (AG number, AG-relative block),
// with a power-of-two stride even when AGs are smaller than that stride.
func (v *XFSVol) fsbPhysical(fsb, count uint64) (uint64, bool) {
	agno := fsb >> v.agblklog
	agbno := fsb & (uint64(1)<<v.agblklog - 1)
	if count == 0 || agno >= uint64(v.agCount) || agbno >= uint64(v.agLen(int64(agno))) || count > uint64(v.agLen(int64(agno)))-agbno {
		return 0, false
	}
	return agno*uint64(v.agBlocks) + agbno, true
}

// xfsLogExtent is one file mapping in logical space: file-block
// offset, physical start block, block count.
type xfsLogExtent struct {
	off   uint64
	start uint64
	n     uint64
}

// clipLogical sorts mappings by LOGICAL file offset and clips them
// to the file's [0,size) byte range, emitting image-absolute byte
// extents. The sort must be logical, not physical: trimming in
// physical order keeps slack and drops real head content on every
// fragmented file with a non-block-multiple size. Mappings starting
// at or past EOF are stale and dropped (sorted records make the
// first such mapping terminal); holes have no mapping and contribute
// no bytes. Overlapping mappings (corrupt) both survive; the trailing
// physical merge unions them. Callers pass size <= maxBytes (enforced
// by readInode against the coherence-checked geometry), so every
// product below is bounded by the volume size and cannot overflow.
func (v *XFSVol) clipLogical(recs []xfsLogExtent, size uint64) []FSExtent {
	sort.Slice(recs, func(i, j int) bool { return recs[i].off < recs[j].off })
	bs := uint64(v.blockSize)
	lastBlk := size / bs
	if size%bs != 0 {
		lastBlk++
	}
	var out []FSExtent
	for _, r := range recs {
		if r.off >= lastBlk {
			break
		}
		end := r.off + r.n
		if end > lastBlk {
			end = lastBlk
		}
		if end <= r.off {
			continue
		}
		// off < lastBlk bounds the head product by size; the
		// tail is size itself on the boundary block.
		startByte := r.off * bs
		endByte := end * bs
		if end == lastBlk {
			endByte = size
		}
		out = append(out, FSExtent{
			Start: v.base + int64(r.start)*v.blockSize,
			Len:   int64(endByte - startByte),
		})
	}
	return mergeExtents(out)
}

// mapBmbt walks a file-extent btree rooted in the inode fork by
// visiting every child of every node: no sibling pointers are
// needed, so their offsets cannot mislead. The in-fork root is a
// bare level/count header with no magic (confirmed by xfs_db typed
// print of a crafted fork plus the xfs_bmdr_block source); the
// full-block key offsets (72 v5, 24 v4) are pinned the same way.
// Every step validates level, count, bounds, and child magics, so
// anything unexpected fails closed (ok=false) instead of misreading.
func (v *XFSVol) mapBmbt(fork []byte, size uint64) ([]FSExtent, bool) {
	be := binary.BigEndian
	if len(fork) < 4 {
		return nil, false
	}
	level := int(be.Uint16(fork[0:2]))
	nrecs := int(be.Uint16(fork[2:4]))
	// Keys and pointers live in fork-capacity-sized arrays, not
	// nrecs-sized ones (XFS_BMDR_PTR_ADDR): maxrecs derives from
	// the fork length, exactly as xfs_bmdr_maxrecs computes it.
	maxrecs := (len(fork) - 4) / 16
	ptrsAt := 4 + maxrecs*8
	if level < 1 || level > 8 || nrecs < 1 || nrecs > maxrecs || ptrsAt+nrecs*8 > len(fork) {
		return nil, false
	}
	// Full-block key offset by version: v5 long blocks carry
	// 64-bit siblings, block number, lsn, uuid, owner, and crc
	// before keys at 72; v4 long blocks carry 64-bit siblings
	// before keys at 24. Both pinned by xfs_db typed print of
	// crafted leaves (records decode exact).
	keyOffset := func(blk []byte) (int, bool) {
		switch be.Uint32(blk[0:4]) {
		case xfsMagicBmbtV4:
			return 24, true
		case xfsMagicBmbtV5:
			return 72, true
		default:
			return 0, false
		}
	}
	var recs []xfsLogExtent
	visited := int64(0)
	var visit func(blkno uint64, wantLvl int) bool
	visit = func(blkno uint64, wantLvl int) bool {
		visited++
		if visited > v.dblocks+1 || wantLvl < 0 || wantLvl > 8 {
			return false
		}
		physical, ok := v.fsbPhysical(blkno, 1)
		if !ok {
			return false
		}
		blk := make([]byte, v.blockSize)
		if _, err := v.r.ReadAt(blk, v.base+int64(physical)*v.blockSize); err != nil {
			return false
		}
		start, ok := keyOffset(blk)
		if !ok {
			return false
		}
		if int(be.Uint16(blk[4:6])) != wantLvl {
			return false
		}
		n := int(be.Uint16(blk[6:8]))
		if n < 1 || start+n*16 > int(v.blockSize) {
			return false
		}
		if wantLvl == 0 {
			for i := 0; i < n; i++ {
				rec := blk[start+i*16 : start+(i+1)*16]
				l0 := be.Uint64(rec[0:8])
				l1 := be.Uint64(rec[8:16])
				startoff := (l0 >> 9) & (uint64(1)<<54 - 1)
				startblock := ((l0 & 0x1FF) << 43) | (l1 >> 21)
				count := l1 & 0x1FFFFF
				physical, ok := v.fsbPhysical(startblock, count)
				if l0>>63 != 0 || !ok {
					continue
				}
				recs = append(recs, xfsLogExtent{off: startoff, start: physical, n: count})
			}
			return true
		}
		ptrsAt := start + ((int(v.blockSize)-start)/16)*8
		for i := 0; i < n; i++ {
			child := be.Uint64(blk[ptrsAt+i*8 : ptrsAt+(i+1)*8])
			if !visit(child, wantLvl-1) {
				return false
			}
		}
		return true
	}
	for i := 0; i < nrecs; i++ {
		child := be.Uint64(fork[ptrsAt+i*8 : ptrsAt+(i+1)*8])
		if !visit(child, level-1) {
			return nil, false
		}
	}
	return v.clipLogical(recs, size), true
}

// parseShortform decodes a shortform directory image: header
// (count, i8count, parent) plus count entries of namelen, offset,
// name, optional ftype, and inode. The hint names the expected
// ftype shape, but upgraded filesystems mix shapes, so both are
// tried: the accepted shape must consume exactly size bytes with
// all-valid entries (the hint wins a draw that only empty
// directories can produce); otherwise the directory yields no
// names (nil). Empty directories carry no entries and no ambiguity.
func parseShortform(fork []byte, size uint64, maxino uint64, ftypeHint bool) []xfsDirent {
	if len(fork) < 2 {
		return nil
	}
	count := int(fork[0])
	i8 := fork[1] != 0
	inoLen := 4
	if i8 {
		inoLen = 8
	}
	hdrLen := 2 + inoLen
	if len(fork) < hdrLen {
		return nil
	}
	if count == 0 {
		return nil
	}
	try := func(withFtype bool) ([]xfsDirent, bool) {
		var out []xfsDirent
		p := hdrLen
		for i := 0; i < count; i++ {
			if p+1+2 > len(fork) {
				return nil, false
			}
			nlen := int(fork[p])
			p += 1 + 2 // namelen + hash offset
			if nlen < 1 || nlen > 255 || p+nlen > len(fork) {
				return nil, false
			}
			name := string(fork[p : p+nlen])
			if !plausibleName(name) {
				return nil, false
			}
			p += nlen
			if withFtype {
				if p+1 > len(fork) {
					return nil, false
				}
				p++
			}
			if p+inoLen > len(fork) {
				return nil, false
			}
			var ino uint64
			if i8 {
				ino = binary.BigEndian.Uint64(fork[p : p+8])
			} else {
				ino = uint64(binary.BigEndian.Uint32(fork[p : p+4]))
			}
			if ino == 0 || ino >= maxino {
				return nil, false
			}
			p += inoLen
			out = append(out, xfsDirent{ino: ino, name: name})
		}
		if uint64(p) != size {
			return nil, false
		}
		return out, true
	}
	with, okWith := try(true)
	without, okWithout := try(false)
	if ftypeHint {
		if okWith {
			return with
		}
		if okWithout {
			return without
		}
		return nil
	}
	if okWithout {
		return without
	}
	if okWith {
		return with
	}
	return nil
}

// xfsChunkInodes is the inode count of one inode chunk record.
const xfsChunkInodes = 64

// chunkStartinos returns the starting inode number of every inode
// chunk in the AG: one record per allocated chunk, sparse groups
// (holemask) excluded. A malformed record is skipped like ext's
// unreadable rows; a malformed tree aborts (chunks unknown means
// coverage unknown).
func (v *XFSVol) chunkStartinos(agno int64) ([]uint64, error) {
	g, err := v.readAGI(agno)
	if err != nil {
		return nil, err
	}
	recs, err := v.btreeLeaves(agno, g.inoRoot, g.inoLevel, 4, 16,
		xfsMagicInoV4, xfsMagicInoV5, "inobt")
	if err != nil {
		return nil, err
	}
	bits := v.agblklog + v.inopblog
	maxAgino := uint64(v.agLen(agno)) << v.inopblog
	var out []uint64
	for _, rec := range recs {
		startino := uint64(binary.BigEndian.Uint32(rec[0:4]))
		holemask := binary.BigEndian.Uint16(rec[4:6])
		if startino+xfsChunkInodes > maxAgino {
			continue
		}
		for i := uint64(0); i < xfsChunkInodes; i++ {
			// Each holemask bit covers 4 inodes
			// (XFS_INODES_PER_HOLEMASK_BIT in xfs_format.h);
			// a set bit means that group is a hole, proved
			// by XFS_INOBT_HOLEMASK_FULL == 0 (a full chunk
			// has every group present, so set means absent).
			// Bit order is LSB-first by mask convention
			// (no sparse chunk was available to pin it
			// empirically); a wrong order would surface as
			// skipped-then-garbage rows, never misread ones.
			if holemask&(1<<(i/4)) != 0 {
				continue
			}
			out = append(out, (uint64(agno)<<bits)+startino+i)
		}
	}
	return out, nil
}

// Entries enumerates files with names where known: live files via
// the directory tree from the root, unlinked inodes by chunk scan
// (content without names unless a surviving directory still
// references them). Directories in block or btree format contribute
// no names in this version; their files' content is still recovered
// by the chunk scan.
func (v *XFSVol) Entries() ([]FSEntry, error) {
	names := map[uint64][]string{} // ino -> dir names
	seenDir := map[uint64]bool{}
	var walk func(ino uint64, depth int)
	walk = func(ino uint64, depth int) {
		if depth > 32 || seenDir[ino] {
			return
		}
		seenDir[ino] = true
		in, ok := v.readInode(ino)
		if !ok || !in.isDir {
			return
		}
		for _, de := range in.names {
			names[de.ino] = append(names[de.ino], de.name)
			if child, ok := v.readInode(de.ino); ok && child.isDir {
				walk(de.ino, depth+1)
			}
		}
	}
	walk(v.rootino, 0)
	// Unlinked directories are not reachable from the root; scan
	// for them so their deleted children keep names.
	for agno := int64(0); agno < v.agCount; agno++ {
		inos, err := v.chunkStartinos(agno)
		if err != nil {
			return nil, err
		}
		for _, ino := range inos {
			in, ok := v.readInode(ino)
			if !ok || !in.isDir || in.links != 0 {
				continue
			}
			walk(ino, 0)
		}
	}

	var out []FSEntry
	for agno := int64(0); agno < v.agCount; agno++ {
		inos, err := v.chunkStartinos(agno)
		if err != nil {
			return nil, err
		}
		for _, ino := range inos {
			in, ok := v.readInode(ino)
			if !ok || in.isDir {
				continue
			}
			note := fmt.Sprintf("inode:%d", ino)
			if in.degraded != "" {
				note += in.degraded
			}
			out = append(out, FSEntry{
				Name:    firstName(names[ino]),
				Names:   names[ino],
				Size:    int64(in.size),
				Deleted: in.links == 0,
				Extents: in.extents,
				Note:    note,
			})
		}
	}
	return out, nil
}

// Unallocated returns free-block byte ranges from the per-AG
// freespace trees plus the AGFL stash windows: exactly what xfs_db
// freesp reports. Any corruption in the authoritative tree aborts;
// coverage is never guessed.
func (v *XFSVol) Unallocated() ([]FSExtent, error) {
	var all []FSExtent
	for agno := int64(0); agno < v.agCount; agno++ {
		g, err := v.readAGF(agno)
		if err != nil {
			return nil, err
		}
		recs, err := v.btreeLeaves(agno, g.bnoRoot, g.bnoLevel, 8, 8,
			xfsMagicBnoV4, xfsMagicBnoV5, "bnobt")
		if err != nil {
			return nil, err
		}
		agLen := uint64(v.agLen(agno))
		agBase := v.base + agno*v.agBlocks*v.blockSize
		for _, rec := range recs {
			start := uint64(binary.BigEndian.Uint32(rec[0:4]))
			n := uint64(binary.BigEndian.Uint32(rec[4:8]))
			if n == 0 || start >= agLen || start+n > agLen {
				return nil, fmt.Errorf("AG %d bnobt record (%d,%d) out of range", agno, start, n)
			}
			all = append(all, FSExtent{
				Start: agBase + int64(start)*v.blockSize,
				Len:   int64(n) * v.blockSize,
			})
		}
		stash, err := v.agflBlocks(agno, g)
		if err != nil {
			return nil, err
		}
		for _, bno := range stash {
			all = append(all, FSExtent{
				Start: agBase + int64(bno)*v.blockSize,
				Len:   v.blockSize,
			})
		}
	}
	return mergeExtents(all), nil
}
