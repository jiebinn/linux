// SPDX-License-Identifier: GPL-2.0
/*
 * C2C Function Browser - function-level cacheline sharing analysis
 *
 * Displays a 3-level hierarchy showing which functions share cachelines:
 *   Level 1: Primary functions sorted by HITM cycles percentage
 *   Level 2: Other functions sharing cachelines with the level-1 function
 *   Level 3: Specific shared cachelines between each pair of functions
 *
 * Uses c2c_hist_entry->hists to build the hierarchy without adding any
 * per-entry state to the existing c2c data structures.
 */

#include <errno.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <linux/list.h>
#include <linux/rbtree.h>
#include <linux/zalloc.h>

#include "../browser.h"
#include "../helpline.h"
#include "../keysyms.h"
#include "../libslang.h"
#include "../ui.h"
#include "../../util/addr_location.h"
#include "../../util/cacheline.h"
#include "../../util/debug.h"
#include "../../util/hist.h"
#include "../../util/map.h"
#include "../../util/mem-events.h"
#include "../../util/mem-info.h"
#include "../../util/sort.h"
#include "../../util/symbol.h"
#include "../../util/thread.h"
#include "../../c2c.h"
#include "hists.h"

struct perf_c2c_ext {
	struct c2c_hists	function_hists;
	/* Cached across all level-1 entries; 0 means "not yet computed". */
	u64			total_cycles;
};

static struct perf_c2c_ext c2c_ext __maybe_unused;

struct c2c_function_browser {
	struct hist_browser	hb;
	struct hists		*hists;
};

__maybe_unused
static inline u64 c2c_hitm_count(const struct c2c_stats *stats)
{
	return stats->rmt_hitm + stats->lcl_hitm;
}

__maybe_unused
static inline bool symbol_name_equal(struct symbol *a, struct symbol *b)
{
	return a && b && strcmp(a->name, b->name) == 0;
}

__maybe_unused
static inline u64 hist_entry__iaddr(struct hist_entry *he)
{
	if (he->mem_info)
		return mem_info__iaddr(he->mem_info)->addr;
	return he->ms.sym ? he->ms.sym->start : 0;
}

int perf_c2c__browse_function_view(struct hists *hists __maybe_unused)
{
	return 0;
}
