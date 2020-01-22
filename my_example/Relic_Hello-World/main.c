/*
 * Copyright (C) 2014 Freie Universität Berlin
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     examples
 * @{
 *
 * @file
 * @brief       Relic Hello World application
 *
 * @author      Max Pengrin <max.pengrin@hft-stuttgart.de
 *
 * @}
 */

#include <stdio.h>
#include <assert.h>
#include "relic.h"


int main(void)
{
	//core_init();
	//subtraction();

	puts("Relic libary says: \"Hello World!\"");

	printf("You are running RIOT on a(n) %s board.\n", RIOT_BOARD);
	printf("This board features a(n) %s MCU.\n", RIOT_MCU);
	
	return 0;
}

