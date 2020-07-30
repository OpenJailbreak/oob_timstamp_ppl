/*
 * oob_timestamp.h
 * Brandon Azad
 */
#ifndef OOB_TIMESTAMP__OOB_TIMESTAMP__H_
#define OOB_TIMESTAMP__OOB_TIMESTAMP__H_

/*
 * oob_timestamp
 *
 * Description:
 * 	Run the oob_timestamp exploit to obtain the kernel task port. If the system has already
 * 	been exploited, no action is performed.
 *
 * 	The kernel task port is configured as expected by kernel_init().
 */
void oob_timestamp(void);

#endif
