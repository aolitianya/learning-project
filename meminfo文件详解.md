
*MemTotal:       498364224 kB*

*MemFree:        341371712 kB*

*MemAvailable:   431430528 kB*

*Buffers:            3456 kB*

*Cached:         89801856 kB*

*SwapCached:            0 kB*

Active:         36263872 kB
Inactive:       78312192 kB
Active(anon):   24965120 kB
Inactive(anon):   212352 kB
Active(file):   11298752 kB
Inactive(file): 78099840 kB
Unevictable:           0 kB
Mlocked:               0 kB
SwapTotal:       4194240 kB
SwapFree:        4194240 kB
Dirty:               512 kB
Writeback:             0 kB
AnonPages:      24776320 kB
Mapped:           157504 kB
Shmem:            406720 kB
Slab:           11619072 kB
SReclaimable:    3734336 kB
SUnreclaim:      7884736 kB
KernelStack:       34128 kB
PageTables:        69632 kB
NFS_Unstable:          0 kB
Bounce:                0 kB
WritebackTmp:          0 kB
CommitLimit:    240269120 kB
Committed_AS:   59814336 kB
VmallocTotal:   549755813888 kB
VmallocUsed:           0 kB
VmallocChunk:          0 kB
HardwareCorrupted:     0 kB
AnonHugePages:         0 kB
ShmemHugePages:        0 kB
ShmemPmdMapped:        0 kB
CmaTotal:       25165824 kB
CmaFree:        25165824 kB
HugePages_Total:   12800
HugePages_Free:    12800
HugePages_Rsvd:        0
HugePages_Surp:        0
Hugepagesize:       2048 kB
'''

上述信息由fs/proc/meminfo.c文件中meminfo_proc_show函数打印
static int meminfo_proc_show(struct seq_file *m, void *v)
{
	struct sysinfo i;
	unsigned long committed;
	long cached;
	long available;
	unsigned long pages[NR_LRU_LISTS];
	int lru;

	si_meminfo(&i);
	si_swapinfo(&i);
	committed = percpu_counter_read_positive(&vm_committed_as);

	cached = global_node_page_state(NR_FILE_PAGES) -
			total_swapcache_pages() - i.bufferram;
	if (cached < 0)
		cached = 0;

	for (lru = LRU_BASE; lru < NR_LRU_LISTS; lru++)
		pages[lru] = global_node_page_state(NR_LRU_BASE + lru);

	available = si_mem_available();

	show_val_kb(m, "MemTotal:       ", i.totalram);
	show_val_kb(m, "MemFree:        ", i.freeram);
	show_val_kb(m, "MemAvailable:   ", available);
	show_val_kb(m, "Buffers:        ", i.bufferram);
	show_val_kb(m, "Cached:         ", cached);
	show_val_kb(m, "SwapCached:     ", total_swapcache_pages());
	show_val_kb(m, "Active:         ", pages[LRU_ACTIVE_ANON] +
					   pages[LRU_ACTIVE_FILE]);
	show_val_kb(m, "Inactive:       ", pages[LRU_INACTIVE_ANON] +
					   pages[LRU_INACTIVE_FILE]);
	show_val_kb(m, "Active(anon):   ", pages[LRU_ACTIVE_ANON]);
	show_val_kb(m, "Inactive(anon): ", pages[LRU_INACTIVE_ANON]);
	show_val_kb(m, "Active(file):   ", pages[LRU_ACTIVE_FILE]);
	show_val_kb(m, "Inactive(file): ", pages[LRU_INACTIVE_FILE]);
	show_val_kb(m, "Unevictable:    ", pages[LRU_UNEVICTABLE]);
	show_val_kb(m, "Mlocked:        ", global_zone_page_state(NR_MLOCK));

#ifdef CONFIG_HIGHMEM
	show_val_kb(m, "HighTotal:      ", i.totalhigh);
	show_val_kb(m, "HighFree:       ", i.freehigh);
	show_val_kb(m, "LowTotal:       ", i.totalram - i.totalhigh);
	show_val_kb(m, "LowFree:        ", i.freeram - i.freehigh);
#endif

#ifndef CONFIG_MMU
	show_val_kb(m, "MmapCopy:       ",
		    (unsigned long)atomic_long_read(&mmap_pages_allocated));
#endif

	show_val_kb(m, "SwapTotal:      ", i.totalswap);
	show_val_kb(m, "SwapFree:       ", i.freeswap);
	show_val_kb(m, "Dirty:          ",
		    global_node_page_state(NR_FILE_DIRTY));
	show_val_kb(m, "Writeback:      ",
		    global_node_page_state(NR_WRITEBACK));
	show_val_kb(m, "AnonPages:      ",
		    global_node_page_state(NR_ANON_MAPPED));
	show_val_kb(m, "Mapped:         ",
		    global_node_page_state(NR_FILE_MAPPED));
	show_val_kb(m, "Shmem:          ", i.sharedram);
	show_val_kb(m, "Slab:           ",
		    global_node_page_state(NR_SLAB_RECLAIMABLE) +
		    global_node_page_state(NR_SLAB_UNRECLAIMABLE));

	show_val_kb(m, "SReclaimable:   ",
		    global_node_page_state(NR_SLAB_RECLAIMABLE));
	show_val_kb(m, "SUnreclaim:     ",
		    global_node_page_state(NR_SLAB_UNRECLAIMABLE));
	seq_printf(m, "KernelStack:    %8lu kB\n",
		   global_zone_page_state(NR_KERNEL_STACK_KB));
	show_val_kb(m, "PageTables:     ",
		    global_zone_page_state(NR_PAGETABLE));
#ifdef CONFIG_QUICKLIST
	show_val_kb(m, "Quicklists:     ", quicklist_total_size());
#endif

	show_val_kb(m, "NFS_Unstable:   ",
		    global_node_page_state(NR_UNSTABLE_NFS));
	show_val_kb(m, "Bounce:         ",
		    global_zone_page_state(NR_BOUNCE));
	show_val_kb(m, "WritebackTmp:   ",
		    global_node_page_state(NR_WRITEBACK_TEMP));
	show_val_kb(m, "CommitLimit:    ", vm_commit_limit());
	show_val_kb(m, "Committed_AS:   ", committed);
	seq_printf(m, "VmallocTotal:   %8lu kB\n",
		   (unsigned long)VMALLOC_TOTAL >> 10);
	show_val_kb(m, "VmallocUsed:    ", 0ul);
	show_val_kb(m, "VmallocChunk:   ", 0ul);

#ifdef CONFIG_MEMORY_FAILURE
	seq_printf(m, "HardwareCorrupted: %5lu kB\n",
		   atomic_long_read(&num_poisoned_pages) << (PAGE_SHIFT - 10));
#endif

#ifdef CONFIG_TRANSPARENT_HUGEPAGE
	show_val_kb(m, "AnonHugePages:  ",
		    global_node_page_state(NR_ANON_THPS) * HPAGE_PMD_NR);
	show_val_kb(m, "ShmemHugePages: ",
		    global_node_page_state(NR_SHMEM_THPS) * HPAGE_PMD_NR);
	show_val_kb(m, "ShmemPmdMapped: ",
		    global_node_page_state(NR_SHMEM_PMDMAPPED) * HPAGE_PMD_NR);
#endif

#ifdef CONFIG_CMA
	show_val_kb(m, "CmaTotal:       ", totalcma_pages);
	show_val_kb(m, "CmaFree:        ",
		    global_zone_page_state(NR_FREE_CMA_PAGES));
#endif

	hugetlb_report_meminfo(m);

	arch_report_meminfo(m);

	return 0;
}

MemTotal：可用物理内存大小，是实际的物理内存条的总大小减去fireware和kernel本身占用的内存，即能够被kernel使用的内存总大小
MemFree：空闲内存大小，即free中的free大小
MemAvailable：可用内存大小，MemFree表示的是当前空闲的内存，但是在系统中还有一些内存虽然已经被使用但是可以被释放掉，如cache、buffer、slab中的部分，这些可回收的内存大小加上MemFree的大小才是系统的可用内存大小，即MemAvailable，MemAvailable·是一个估计值，因为一部分内存还没有被回收，这只是根据内核算法估算出来的结果，所以并不精确。
Buffers:块设备使用的缓存，包括直接读写块设备、以及文件系统的的元数据所使用的缓存
Cached:文件缓存
Buffers+Cached = Active(file)+Inactive(file)+Shmem
SwapCached：交换分区上占用的空间
Active：Active(anon) + Active(file)，活跃的缓存大小
Inactive：Inactive(anon) +Inactive(file) 不活跃的缓存大小
Active(anon)/Inactive(anon)/Active(file)/Inactive(file):anon表示匿名内存，file表示文件内存，active表示最近使用过的内存，inactive表示最近没有使用的内存。当内存释放的时候，会优先释放inactive的内存空间。
Unevictable：不能够被释放的内存
Mlocked：被mlock()系统调用锁定的内存大小
SwapTotal：swap分区的大小
SwapFree：swap分区未使用的大小
Dirty：脏数据，尚未写入到磁盘中的数据大小
Writeback：正在写入的脏数据大小
AnonPages：匿名页的大小
Mapped：正在被进程关联的文件缓存大小
Shmem：tmpfs文件系统使用的内存和共享缓存大小
Slab：slab分配器使用的内存大小，等于SReclaimable+Sunreclaim
SReclaimable：Slab中不活跃的对象，可以被回收的容量
Sunreclaim：Slab中活跃的对象，不能被回收的容量
KernelStack：内核使用的堆栈大小，当前系统进程越多，kernelstack的值就越大
PageTables：页表使用的内存空间大小
NFS_Unstable：发送给NFS server但是还没有写入硬盘的缓存
Bounce：跳转buffer
WritebackTmp：
CommitLimit：允许超过的虚拟内存大小
Committed_AS：
VmallocTotal：理论上虚拟内存空间的总大小
VmallocUsed：固定为0
VmallocChunk：固定为0
HardwareCorrupted：系统检测到内存上存在的硬件故障，会把有故障的页删除掉不再使用，HardwareCorrupted上就记录了删除掉的内存页大小
AnonHugePages：透明大页使用量
ShmemHugePages：
ShmemPmdMapped：
CmaTotal：
CmaFree：
HugePage_Total：分配的大页内存大小
HugePage_Free：空闲的大页内存大小
HugePages_Rsvd：
HugePages_Surp：
Hugepagesize：大页大小

下面我们来对其中一些难于理解的项进行详细的解释说明
1. MemTotal
物理内存大小。MemTotal并不等于所有内存条内存容量之和，是因为在系统加电之后，firmware和kernel本身需要占用一些内存，这些占用的内存不会被统计到meminfo文件当中，因此MemTotal表示的内存大小是去掉了这些内存之后剩余可供系统使用的物理内存总大小，在系统运行过程中，MemTotal的值固定不变。
2. MemAvailable
可用内存大小。MemFree表示的是当前系统的空闲内存大小，而MemAvailable表示的是当前系统的可用内存大小，这两个的含义是不同的。MemFree表示完全没有被使用的内存，但是实际上来说我们能够使用的内存不仅仅是现在还没有被使用的内存，还包括目前已经被使用但是可以被回收的内存，这部分内存加上MemFree才是我们实际可用的内存，cache、buffer、slab等其中都有一部分内存可以被回收，MemAvailable就是MemFree加上这部分可回收的内存之后的结果，当然因为这部分可回收的内存当前还没有被回收，因此只能够通过算法来估算出这部分内存的大小，所以MemAvailable是一个估算值，并不是真实的统计值。
3. Buffers
直接对块设备进行读写操作使用的缓存。主要包括：直接读写块设备，文件系统元数据（比如superblock，不包括文件系统中文件的元数据）。它与Cached的区别在于，Cached表示的普通文件的缓存。
Buffers占用的内存存在于lru list中，会被统计到Active(file)或者Inactive(file)中。
4. Cached
Cached是所有的文件缓存，Cached是Mapped的超集。Cached中不仅包含了mapped的页面，也包含了unmapped的页面。当一个文件不再和进程关联之后，在pagecache中的页面不会被马上回收，仍然存在于Cached中，还保留在lru list上，但是Mapped不再统计这部分内存。
Cached还包含tmpfs中文件，以及shared memory，因为shared memory在内核中也是基于tmpfs来实现的。
5. SwapCached
匿名页在必要的情况下，会被交换到Swap中，shared memory和tmpfs虽然不是匿名页，但是它们没有磁盘文件，所以也是需要交换分区的，为了方便说明，在这里我们将匿名页、shared memory和tmpfs统称为匿名页。因此SwapCached中可能包含有AnonPages和Shmem。SwapCached可以理解为是交换区设备的page cache，只不过page cache对应的是一个个的文件，而swapcached对应的是一个个交换区设备。
并不是每一个匿名也都在swap cache中，只有以下情况中匿名页才在swap cache中：
1）匿名页即将被交换到swap分区上，这只存在于很短的一个时间段中，因为紧接着就会发生pageout将匿名页写入交换分区，并且从swap cache中删除；
2）曾经被写入到swap分区现在又被加载到内存中的页会存在与swap cache，直到页面中的内容发生变化，或者原来用过的交换分区空间被回收。
SwapCached实际的含义是：系统中有多少匿名页曾经被swap-out，现在又被swap-in并且swap-in之后页面中的内容一直没有发生变化。也就是说，如果这些页需要被重新swap-out的话，是不需要进行IO操作的。
需要注意的是，SwapCached和Cache是互斥的，二者没有交叉。当然SwapCached也是存在于lru list中的，它和AnonPages或者Shmem有交集。
6. Active
lru list组中active list对应的内存大小，这主要包括pagecache和用户进程的内存，不包括kernel stack和hugepages。active list中是最近被访问的内存页。
Active(anon)和Active(file)分别对应LRU_ACTIVE_ANON和LRU_ACTIVE_FILE这两个lru list，分别表示活跃的文件内存页和匿名页，它们的加和等于Active。文件页对应着进程的代码、映射的文件，匿名页对应的是如进程的堆、栈等内存。文件页在内存不足的情况下可以直接写入到磁盘上，直接进行pageout，不需要使用到交换分区swap，而匿名页在内存不足的情况下因为没有硬盘对应的文件，所以只能够写入到交换区swap中，称为swapout。
7. Inactive
lru list组中inactive list对应的内存大小，也是包括pagecache和用户进程使用的内存，不包括kernel stack和hugepages。Inactive list中是最近没有被访问的内存页，也是内存自动回收机制能够回收的部分。
Inactive(anon)和Inactive(file)分别对应LRU_INACTIVE_ANON和LRU_INACTIVE_FILE这两个例如list，分别表示最近一段时间没有被访问的匿名页和文件页内存，他们的加和等于Inactive。
8. Unevictable
Unevictable对应的是LRU_UNEVICTABLE链表中内存的大小，unevictable lru list上是不能够pageout和swapout的内存页。
9. Mlocked
Mlocked统计的是被mlock()系统调用锁定的内存大小，被锁定的内存因为不能够pageout/swapout，它是存在于LRU_UNEVICTABLE链表上。当然LRU_UNEVICTABLE链表上不仅包含Mlocked的内存。
10. Dirty
Dirty并未完全包括系统中所有的dirty pages，系统上所有的dirty pages应该还包括NFS_Unstable和Writeback，NFS_Unstable是发送给了NFS Server当时没有写入磁盘的缓存页，Writeback是正准备写磁盘的缓存。
11. AnonPages
AnonPages统计了匿名页。需要注意的是，shared memory和tmpfs不属于匿名页，而是属于Cached。Anonymous pages是和用户进程相关联的，一旦进程退出了，匿名页也就被释放了，不像是page cache，进程退出后仍然可以存在于缓存中。
AnonPages中包含了THP使用的内存。
12. Mapped
Mapped是Cached的一个子集。Cache中包含了文件的缓存页，这些缓存页有一些是与正在运行的进程相关联的，如共享库、可执行文件等，有一些是当前不在使用的文件。与进程相关联的文件使用的缓存页就被统计到Mapped中。
进程所占的内存分为anonymous pages和file backed pages，所以理论上来讲：
所有进程占用的PSS之和 = Mapped + AnonPages
13. Shmem
Shmem统计中的内存是shared memory和tmpfs、devtmpfs之和，所有的tmpfs文件系统使用的空间都算入共享内存中。devtmpfs是/dev文件系统类型，也属于一种内存文件系统。
shared memory存在于shmget、shm_open和mmap(…MAP_ANONYMOUS|MAP_SHARED…)系统调用。
由于shared memory也是基于tmpfs实现的，所以这部分内存不算是匿名内存，虽然mmap使用了匿名内存标识符，因此shmem这部分内存被统计到了Cached或者Mapped中。但是shmem这部分内存存在于anon lru list中或者在unevictable lru list中，而不是在file lru list中，这一点需要注意。
14. Slab
Slab是分配块内存时使用的，详细的slab信息可以在/proc/slabinfo中看到，SReclaimable和SUnreclaim中包含了slab中可回收内存和不可回收内存，它们的加和应该等于Slab的值。
15. KernelStack
KernelStack是操作系统内核使用的栈空间，每一个用户线程都会被分配一个内核栈，内核栈是属于用户线程的，但是只有通过系统调用进入内核态之后才会使用到。KernelStack的内存不在LRU list中管理，也没有包含进进程的RSS和PSS中进行统计。
16. PageTables
PageTables用于记录虚拟地址和物理地址的对应关系，随着内存地址分配的增多，PageTables占用的内存也会增加。
17. NFS_Unstable
NFS_Unstable记录了发送给NFS server但是还没有写入硬盘的缓存。
18. Bounce
有些老设备只能够访问低端内存，比如16M以下的内存，当应用程序发出一个IO请求，DMA的目的地址却是高端内存时，内核将低端内存中分配一个临时buffer作为跳转，把位于高端内存的缓存数据复制到bounce中，这种额外的数据拷贝会降低性能，同时也会占用额外的内存。
19. AnonHugePages
AnonHugePages统计的是THP内存，而不是Hugepages内存。AnonHugePages占用的内存是被统计到进程的RSS和PSS中的。
20. CommitLimit
Commit相关内存涉及到进程申请虚拟内存溢出的问题。
当进程需要使用物理内存的时候，实际上内核给分配的仅仅是一段虚拟内存，只有当进程需要对内存进行操作的时候才会在缺页中断处理中对应分配物理内存，进程使用的物理内存是有限的，虚拟内存也是有限的，当操作系统使用了过多的虚拟内存的时候，也会差生问题，这个时候需要通过overcommit机制来判断。在/proc/sys/vm/下面有几个相关的参数：
overcommit_memory：overcommit情况发生时的处理策略，可以设置为0,1,2
0：OVERCOMMIT_GUESS 根据具体情况进行处理
1：OVERCOMMIT_ALWAYS 无论进程使用了多少虚拟内存都不进行控制，即允许overcommit出现
2：OVERCOMMIT_NEVER 不允许overcommit出现
在overcommit_memory中如果设置为2，那么系统将不会允许overcommit存在，如何判断当前是否发生了overcommit呢？就是判断当前使用内存是否超过了CommitLimit的限制。
当用户进程在申请内存的时候，内核会调用__vm_enough_memory函数来验证是否允许分配这段虚拟内存，代码如下：
/*
 * Check that a process has enough memory to allocate a new virtual
 * mapping. 0 means there is enough memory for the allocation to
 * succeed and -ENOMEM implies there is not.
 *
 * We currently support three overcommit policies, which are set via the
 * vm.overcommit_memory sysctl.  See Documentation/vm/overcommit-accounting
 *
 * Strict overcommit modes added 2002 Feb 26 by Alan Cox.
 * Additional code 2002 Jul 20 by Robert Love.
 *
 * cap_sys_admin is 1 if the process has admin privileges, 0 otherwise.
 *
 * Note this is a helper function intended to be used by LSMs which
 * wish to use this logic.
 */
int __vm_enough_memory(struct mm_struct *mm, long pages, int cap_sys_admin)
{
	long free, allowed, reserve;

	VM_WARN_ONCE(percpu_counter_read(&vm_committed_as) <
			-(s64)vm_committed_as_batch * num_online_cpus(),
			"memory commitment underflow");

	vm_acct_memory(pages);

	/*
	 * Sometimes we want to use more memory than we have
	 */
	if (sysctl_overcommit_memory == OVERCOMMIT_ALWAYS)
		return 0;

	if (sysctl_overcommit_memory == OVERCOMMIT_GUESS) {
		free = global_zone_page_state(NR_FREE_PAGES);
		free += global_node_page_state(NR_FILE_PAGES);

		/*
		 * shmem pages shouldn't be counted as free in this
		 * case, they can't be purged, only swapped out, and
		 * that won't affect the overall amount of available
		 * memory in the system.
		 */
		free -= global_node_page_state(NR_SHMEM);

		free += get_nr_swap_pages();

		/*
		 * Any slabs which are created with the
		 * SLAB_RECLAIM_ACCOUNT flag claim to have contents
		 * which are reclaimable, under pressure.  The dentry
		 * cache and most inode caches should fall into this
		 */
		free += global_node_page_state(NR_SLAB_RECLAIMABLE);

		/*
		 * Leave reserved pages. The pages are not for anonymous pages.
		 */
		if (free <= totalreserve_pages)
			goto error;
		else
			free -= totalreserve_pages;

		/*
		 * Reserve some for root
		 */
		if (!cap_sys_admin)
			free -= sysctl_admin_reserve_kbytes >> (PAGE_SHIFT - 10);

		if (free > pages)
			return 0;

		goto error;
	}

    // OVERCOMMIT_NEVER
	allowed = vm_commit_limit();
	/*
	 * Reserve some for root
	 */
	if (!cap_sys_admin)
		allowed -= sysctl_admin_reserve_kbytes >> (PAGE_SHIFT - 10);

	/*
	 * Don't let a single process grow so big a user can't recover
	 */
	if (mm) {
		reserve = sysctl_user_reserve_kbytes >> (PAGE_SHIFT - 10);
		allowed -= min_t(long, mm->total_vm / 32, reserve);
	}

	if (percpu_counter_read_positive(&vm_committed_as) < allowed)
		return 0;
error:
	vm_unacct_memory(pages);

	return -ENOMEM;
}

如果sysctl中的overcommit_memory参数设置的是OVERCOMMIT_ALWAYS，那么此函数直接返回0，表示不做任何限制。
如果overcommit_memory参数设置的是OVERCOMMIT_GUESS，那么此函数将会根据当前的状况进行判断。
第75行，如果overcommit_memory参数设置的是OVERCOMMIT_NEVER，那么会通过vm_commit_limit()函数来获得一个基本的值allowed表示允许使用的内存，当然如果当前进程是一个普通进程，那么我们还需要额外保留一部分内存sysctl_admin_reserve_kbytes用于root用户的紧急操作，第80行。当然，除了留给root用户的内存外，我们还需要给用户留一些空闲内存来保证用户可以进行操作，第86行，这些内存的大小取决于sysctl_user_reserve_kbytes和单一进程的total virtual memory。（sysctl_admin_reserve_kbytes受内核参数/proc/sys/vm/admin_reserve_kbytes控制，
    sysctl_user_reserve_kbytes受内核参数/proc/sys/vm/user_reserve_kbytes控制）。第91行，vm_committed_as表示的是当前系统中已经申请的虚拟内存大小，allowed表示的是允许的虚拟内存大小，如果vs_committed_as超过了overcommit的上限allowed，则申请虚拟内存失败。
21. Committed_AS
当前已经申请的虚拟内存的大小。
22. VmallocTotal、VmallocUsed、VmallocChunk
VmallocTotal：可用虚拟内存总大小，内核中常量
VmallocUsed：内核常量0
VmallocChunk：内核常量0
可以在/proc/vmallocinfo中看到所有的vmalloc操作。一些驱动或者模块都有可能会使用vmalloc来分配内存。
grep vmalloc /proc/vmallocinfo | awk '{total+=$2}; END {print total}'
23. HardwareCorrupted
当系统检测到内存的硬件故障时，会把有问题的页面删除掉，不再使用，/proc/meminfo中的HardwareCorrupted统计了删除掉的内存页的总大小。相应的代码参见 mm/memory-failure.c: memory_failure()
24. AnonHugePages
AnonHugePages统计的是透明大页的使用。它和大页不同，大页不会被统计到RSS/PSS
中，而AnonHugePages则存在于RSS/PSS中，并且它完全包含在AnonPages中
25. HugePages_Total、HugePages_Free、HugePages_Rsvd、HugePages_Surp
Hugepages在/proc/meminfo中是独立统计的，既不会进入rss/pss中，也不计入lru active/inactive，	也不会被计入cache/buffer。如果进程使用hugepages，它的rss/pss也不增加。
THP和hugepages是不同的，THP的统计值是在/proc/meminfo中的AnonHugePages，在/proc/pid/smaps中也有单个进程的统计，这个统计值和进程的rss/pss是有重叠的，如果用户进程使用了THP，那么进程的RSS/PSS也会增加，这和Hugepages是不同的。
HugePages_Total对应内核参数vm.nr_hugepages，也可以在运行的系统之上直接修改，修改的结果会立即影响到空闲内存的大小，因为HugePages在内核上是独立管理的，只要被定义，无论是否被使用，都不再属于free memory。当用户程序申请Hugepages的时候，其实是reserve了一块内存，并没有被真正使用，此时/proc/meminfo中的HugePages_Rsvd会增加，并且HugePages_Free不会减少。只有当用户程序真正写入Hugepages的时候，才会被消耗掉，此时HugePages_Free会减少，HugePages_Rsvd也会减少。

内核使用内存
slab + VmallocUsed + PageTables + KernelStack + HardwareCorrupted + Bounce + X
X表示直接通过alloc_pages/__get_free_pages分配的内存，这部分内存没有在/proc/meminfo中统计。

用户使用内存
用户使用内存可以有几种不同的统计方式：
1. 根据lru进行统计
Active + Inactive + Unevictable + HugePages_Total * Hugepagesize
2. 根据cache统计
当SwapCached为0的时候，用户进程使用的内存主要包括普通文件缓存Cached、块设备缓存Buffers、匿名页AnonPages和大页
Cached + AnonPages + Buffers + HugePages_Total * Hugepagesize
当SwapCached不是0 的时候，SwapCached中可能包含Shmem和AnonPages，这时候SwapCached有一部分可能与AnonPages重叠。
3. 根据RSS/PSS统计
所有进程使用PSS加和加上unmapped的部分、再加上buffer和hugepages
∑Pss + （Cached - mapped） + Buffers + (HugePages_Total * Hugepagesize)
所有进程使用的Pss可以通过将/proc/pid/smaps中的Pss加和得到。



内存黑洞
我们在统计系统使用内存的时候，常常想到将meminfo中的各个项加和到一起，但是实际上Linux kernel并没有滴水不漏的统计所有的内存分配，因此在meminfo中看到的内存并不是系统使用的所有内存信息。
在Kernel中，动态分配内存有以下几个入口：
alloc_pages/__get_free_pages:以页大小为单位的内存分配
vmalloc:以字节为单位分配虚拟地址连续的内存块
slab kmalloc：以字节为单位分配的物理地址连续的内存
在上述几个入口中，以slab分配的内存会被精确的统计到/proc/slabinfo中和/proc/meminfo的slab中，以vmalloc分配的内存会被统计到/proc/vmallocinfo中，以及/proc/meminfo的VmallocUsed中。但是通过alloc_pages分配的内存却没有精确的统计，除非调用alloc_pages的内核模块或者驱动程序主动进行统计。一个常见的现象就是，在VMWare ESX宿主机会通过guest balloon driver（vmware_balloon module）占用guest的内存，有时会占用的太多会造成guest无内存可用，这个时候查看guest的/proc/meminfo只能够看到MemFree很少，但是看不到内存的取向，这就是因为Balloon driver通过alloc_pages分配内存，但是没有在meminfo中留下统计值，所以很难追踪。

参考：
内核代码：https://elixir.bootlin.com/linux/v4.14.49/source/mm/util.c#L550
meminfo文件详解：https://blog.csdn.net/majianting/article/details/85259558
/proc/meminfo之谜：http://linuxperf.com/?p=142
overcommit相关参数：http://www.wowotech.net/linux_kenrel/overcommit.html


