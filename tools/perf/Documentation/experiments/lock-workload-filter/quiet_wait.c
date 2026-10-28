// SPDX-License-Identifier: GPL-2.0-only
#include <time.h>

int main(void)
{
	struct timespec delay = {4, 0};

	return nanosleep(&delay, 0);
}
