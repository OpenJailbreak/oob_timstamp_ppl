//
//  ppl_bypass.h
//  Brandon Azad
//
#ifndef OOB_TIMESTAMP__PPL_BYPASS__H_
#define OOB_TIMESTAMP__PPL_BYPASS__H_

#include <stdbool.h>
#include <stdint.h>

/*
 * kernel_ppl_bypass
 *
 * Description:
 * 	Initialize the kernel PPL bypass.
 */
bool kernel_ppl_bypass(void);

/*
 * physical_window_map
 *
 * Description:
 * 	Map the specified physical address with the given L3 TTE template and return the resulting
 * 	mapping. Only one mapping can be active at a time.
 */
void *physical_window_map(uint64_t phys_addr, uint64_t l3_tte);

#endif
