package cgv2

import (
	"os"
	"path/filepath"
	"testing"
)

func BenchmarkFillStatStruct(b *testing.B) {
	statContent := `anon 1234567890
file 9876543210
kernel 123456
kernel_stack 65536
pagetables 32768
sec_pagetables 16384
percpu 8192
sock 4096
vmalloc 2048
shmem 1024
file_mapped 512
file_dirty 256
file_writeback 128
swapcached 64
anon_thp 32
file_thp 16
shmem_thp 8
inactive_anon 4
active_anon 2
inactive_file 1
active_file 1024
unevictable 2048
slab_reclaimable 4096
slab_unreclaimable 8192
slab 12288
workingset_refault_anon 100
workingset_refault_file 200
workingset_activate_anon 300
workingset_activate_file 400
workingset_restore_anon 500
workingset_restore_file 600
workingset_nodereclaim 700
pgfault 10000
pgmajfault 1000
pgrefill 2000
pgscan 3000
pgsteal 4000
pgactivate 5000
pgdeactivate 6000
pglazyfree 7000
pglazyfreed 8000
thp_fault_alloc 100
thp_collapse_alloc 50`

	tmpDir := b.TempDir()
	memStatPath := filepath.Join(tmpDir, "memory.stat")
	if err := os.WriteFile(memStatPath, []byte(statContent), 0644); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()

	for b.Loop() {
		ms, err := fillStatStruct(tmpDir)
		if err != nil {
			b.Fatal(err)
		}
		_ = ms
	}
}
