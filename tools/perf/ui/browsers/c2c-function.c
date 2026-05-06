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

static int symbol_width(struct hists *hists, struct sort_entry *se)
{
	int width = hists__col_len(hists, se->se_width_idx);

	if (!c2c.symbol_full && width > SYMBOL_WIDTH)
		width = SYMBOL_WIDTH;

	return width;
}

static struct c2c_dimension dim_function_view;

/*
 * c2c_width - Calculate width for a C2C column in function view
 */
static int c2c_width(struct perf_hpp_fmt *fmt,
		     struct perf_hpp *hpp __maybe_unused,
		     struct hists *hists)
{
	struct c2c_fmt *c2c_fmt;
	struct c2c_dimension *dim;

	c2c_fmt = container_of(fmt, struct c2c_fmt, fmt);
	dim = c2c_fmt->dim;

	if (dim == &dim_function_view)
		return symbol_width(hists, dim->se);

	return dim->width;
}

static int c2c_header(struct perf_hpp_fmt *fmt, struct perf_hpp *hpp,
		      struct hists *hists, int line, int *span)
{
	struct c2c_fmt *c2c_fmt;
	struct c2c_dimension *dim;
	const char *text = NULL;
	int width = c2c_width(fmt, hpp, hists);

	c2c_fmt = container_of(fmt, struct c2c_fmt, fmt);
	dim = c2c_fmt->dim;

	if (dim->header.line[line].text)
		text = dim->header.line[line].text;

	if (span) {
		if (*span) {
			(*span)--;
			return 0;
		}

		*span = dim->header.line[line].span;
	}

	if (!text)
		text = "";

	return scnprintf(hpp->buf, hpp->size, "%*s", width, text);
}

/*
 * Return the total cycles for a c2c_hist_entry (rmt_hitm + lcl_hitm + other loads).
 */
__maybe_unused
static u64 c2c_hist_entry__cycles(struct c2c_hist_entry *c2c_he)
{
	u64 cycles_rmt, cycles_lcl, cycles_load, other_load, total_hitm;

	cycles_rmt = avg_stats(&c2c_he->cstats.rmt_hitm) * c2c_he->stats.rmt_hitm;
	cycles_lcl = avg_stats(&c2c_he->cstats.lcl_hitm) * c2c_he->stats.lcl_hitm;
	total_hitm = (u64)c2c_he->stats.rmt_hitm + c2c_he->stats.lcl_hitm;
	other_load = (c2c_he->stats.load >= total_hitm) ? c2c_he->stats.load - total_hitm : 0;
	cycles_load = avg_stats(&c2c_he->cstats.load) * other_load;

	return cycles_rmt + cycles_lcl + cycles_load;
}

/* Sum c2c_hist_entry__cycles() across all level-1 entries. */
__maybe_unused
static u64 c2c_ext__total_cycles(void)
{
	struct rb_node *nd;
	u64 total = 0;

	for (nd = rb_first_cached(&c2c_ext.function_hists.hists.entries); nd;
	     nd = rb_next(nd)) {
		struct hist_entry *he = rb_entry(nd, struct hist_entry, rb_node);
		struct c2c_hist_entry *c2c_he = container_of(he, struct c2c_hist_entry, he);

		total += c2c_hist_entry__cycles(c2c_he);
	}
	return total;
}

/* Sum child entries' store counts under a level-1 hist_entry. */
__maybe_unused
static u64 hist_entry__child_stores(struct hist_entry *he)
{
	struct rb_node *nd;
	u64 sum = 0;

	for (nd = rb_first_cached(&he->hroot_out); nd; nd = rb_next(nd)) {
		struct hist_entry *child = rb_entry(nd, struct hist_entry, rb_node);
		struct c2c_hist_entry *c2c_child =
			container_of(child, struct c2c_hist_entry, he);

		sum += (u64)c2c_child->stats.store;
	}
	return sum;
}

static int
total_stores_entry(struct perf_hpp_fmt *fmt, struct perf_hpp *hpp,
		   struct hist_entry *he)
{
	struct c2c_hist_entry *c2c_he = container_of(he, struct c2c_hist_entry, he);
	int width = c2c_width(fmt, hpp, he->hists);
	u64 total;

	/* L1 shows the sum of sharing-function stores; L2/L3 show their own. */
	total = he->parent_he ? (u64)c2c_he->stats.store : hist_entry__child_stores(he);

	return scnprintf(hpp->buf, hpp->size, "%*" PRIu64, width, total);
}

/*
 * cacheline_symbol_entry - Render cacheline address for function view
 */
static int
cacheline_symbol_entry(struct perf_hpp_fmt *fmt, struct perf_hpp *hpp,
		       struct hist_entry *he)
{
	int width = c2c_width(fmt, hpp, he->hists);
	char buf[24];
	u64 addr;

	/* Only show the address on level-3 (leaf) cacheline entries. */
	if (he->depth < 2 || !he->leaf || !he->mem_info)
		return scnprintf(hpp->buf, hpp->size, "%*s", width, "");

	addr = cl_address(mem_info__daddr(he->mem_info)->addr, chk_double_cl);
	scnprintf(buf, sizeof(buf), "0x%" PRIx64, addr);

	return scnprintf(hpp->buf, hpp->size, "%*s", width, buf);
}

/* Render the code (instruction) address for level-1 and level-2 entries. */
static int
iaddr_symbol_entry(struct perf_hpp_fmt *fmt, struct perf_hpp *hpp,
		   struct hist_entry *he)
{
	int width = c2c_width(fmt, hpp, he->hists);
	int iaddr_width, ret;
	char buf[24];
	u64 addr = 0;

	/* Hide for cacheline (level-3) entries. */
	if (he->parent_he && he->parent_he->parent_he)
		return scnprintf(hpp->buf, hpp->size, "%*s", width, "");

	if (he->mem_info)
		addr = mem_info__iaddr(he->mem_info)->addr;

	ret = scnprintf(hpp->buf, hpp->size, "%s", he->unfolded ? "- " : "+ ");
	advance_hpp(hpp, ret);

	iaddr_width = width - ret;
	if (iaddr_width <= 0)
		return ret;

	scnprintf(buf, sizeof(buf), "0x%" PRIx64, addr);
	ret += scnprintf(hpp->buf, hpp->size, "%*.*s", iaddr_width, iaddr_width, buf);
	return ret;
}

/*
 * symbol_view_entry - Render symbol name for function view with expansion indicators
 */
static int
symbol_view_entry(struct perf_hpp_fmt *fmt, struct perf_hpp *hpp,
		  struct hist_entry *he)
{
	int width = c2c_width(fmt, hpp, he->hists);
	int sym_width;
	int ret;
	char symbuf[512];
	const char *prefix;

	/* Hide Symbol for cacheline entries */
	if (he->parent_he && he->parent_he->parent_he)
		return scnprintf(hpp->buf, hpp->size, "%*s", width, "");

	prefix = he->unfolded ? "- " : "+ ";

	ret = scnprintf(hpp->buf, hpp->size, "%s", prefix);
	advance_hpp(hpp, ret);

	sym_width = width - ret;

	if (sym_width <= 0)
		return ret;

	if (sort_sym.se_snprintf) {
		sort_sym.se_snprintf(he, symbuf, sizeof(symbuf), sym_width);
	} else {
		const char *name = he->ms.sym ? he->ms.sym->name : "[unknown]";

		scnprintf(symbuf, sizeof(symbuf), "%s", name);
	}

	ret += scnprintf(hpp->buf, hpp->size, "%-*.*s", sym_width, sym_width, symbuf);
	return ret;
}

/*
 * cycles_percent_entry - Render cycles percentage column
 */
static int
cycles_percent_entry(struct perf_hpp_fmt *fmt, struct perf_hpp *hpp,
		     struct hist_entry *he)
{
	struct c2c_hist_entry *c2c_he;
	int width = c2c_width(fmt, hpp, he->hists);
	u64 fn_cycles, total_cycles;
	const char *prefix;
	double pct;
	int ret;

	/* Hide Cycles Percent for child functions and cachelines. */
	if (he->parent_he)
		return scnprintf(hpp->buf, hpp->size, "%*s", width, "");

	c2c_he = container_of(he, struct c2c_hist_entry, he);
	fn_cycles = c2c_hist_entry__cycles(c2c_he);
	total_cycles = c2c_ext.total_cycles;
	pct = total_cycles > 0 ? (double)fn_cycles / total_cycles * 100.0 : 0.0;

	/* Add folded sign only for level-1 entries */
	prefix = he->unfolded ? "- " : "+ ";
	ret = scnprintf(hpp->buf, hpp->size, "%s", prefix);
	advance_hpp(hpp, ret);

	ret += scnprintf(hpp->buf, hpp->size, "%*.2f%%", width - ret - 1, pct);
	return ret;
}

/*
 * cycles_percent_cmp - Comparison function for cycles percentage sorting
 */
static int64_t
cycles_percent_cmp(struct perf_hpp_fmt *fmt __maybe_unused,
		   struct hist_entry *left, struct hist_entry *right)
{
	struct c2c_hist_entry *c2c_left = container_of(left, struct c2c_hist_entry, he);
	struct c2c_hist_entry *c2c_right = container_of(right, struct c2c_hist_entry, he);
	u64 cycles_left = c2c_hist_entry__cycles(c2c_left);
	u64 cycles_right = c2c_hist_entry__cycles(c2c_right);

	return (cycles_left > cycles_right) - (cycles_left < cycles_right);
}

/*
 * iaddr_symbol_cmp - Comparison function for instruction address sorting
 */
static int64_t
iaddr_symbol_cmp(struct perf_hpp_fmt *fmt __maybe_unused,
		 struct hist_entry *left, struct hist_entry *right)
{
	return sort__iaddr_cmp(left, right);
}

static int64_t
empty_cmp(struct perf_hpp_fmt *fmt __maybe_unused,
	  struct hist_entry *left __maybe_unused,
	  struct hist_entry *right __maybe_unused)
{
	return 0;
}

/*
 * total_stores_cmp - Comparison function for total stores sorting
 */
static int64_t
total_stores_cmp(struct perf_hpp_fmt *fmt __maybe_unused,
		 struct hist_entry *left, struct hist_entry *right)
{
	struct c2c_hist_entry *c2c_left = container_of(left, struct c2c_hist_entry, he);
	struct c2c_hist_entry *c2c_right = container_of(right, struct c2c_hist_entry, he);
	u64 left_store = (u64)c2c_left->stats.store;
	u64 right_store = (u64)c2c_right->stats.store;

	return (left_store > right_store) - (left_store < right_store);
}

/*
 * Function view dimensions
 */
static struct c2c_dimension dim_cycles_percent = {
	.header		= HEADER_BOTH("HITM ", "cycles"),
	.name		= "cycles_percent",
	.cmp		= cycles_percent_cmp,
	.entry		= cycles_percent_entry,
	.width		= 9,
};

static struct c2c_dimension dim_total_stores = {
	.header		= HEADER_BOTH("Store", "count"),
	.name		= "total_stores",
	.cmp		= total_stores_cmp,
	.entry		= total_stores_entry,
	.width		= 7,
};

static struct c2c_dimension dim_cacheline_symbol = {
	.header		= HEADER_LOW("Cacheline"),
	.name		= "cacheline_symbol",
	.cmp		= empty_cmp,
	.entry		= cacheline_symbol_entry,
	.width		= 18,
};

static struct c2c_dimension dim_iaddr_symbol = {
	.header		= HEADER_LOW("Code address"),
	.name		= "iaddr_symbol",
	.cmp		= iaddr_symbol_cmp,
	.entry		= iaddr_symbol_entry,
	.width		= 20,
};

static struct c2c_dimension dim_function_view = {
	.header		= HEADER_LOW("Symbol"),
	.name		= "symbol_view",
	.se		= &sort_sym,
	.cmp		= empty_cmp,
	.entry		= symbol_view_entry,
	.width		= SYMBOL_WIDTH,
};

static struct c2c_dimension *function_view_dimensions[] = {
	&dim_iaddr_symbol,
	&dim_cycles_percent,
	&dim_total_stores,
	&dim_cacheline_symbol,
	&dim_function_view,
	NULL,
};

__maybe_unused
static struct c2c_dimension *get_function_dimension(const char *name)
{
	unsigned int i;

	for (i = 0; function_view_dimensions[i]; i++) {
		struct c2c_dimension *dim = function_view_dimensions[i];

		if (!strcmp(dim->name, name))
			return dim;
	}

	return NULL;
}

__maybe_unused
static struct c2c_fmt *get_function_format(const char *name)
{
	struct c2c_dimension *dim = get_function_dimension(name);
	struct c2c_fmt *c2c_fmt;
	struct perf_hpp_fmt *fmt;

	if (!dim)
		return NULL;

	c2c_fmt = zalloc(sizeof(*c2c_fmt));
	if (!c2c_fmt)
		return NULL;

	fmt = &c2c_fmt->fmt;

	c2c_fmt->dim = dim;
	INIT_LIST_HEAD(&fmt->list);
	INIT_LIST_HEAD(&fmt->sort_list);

	fmt->cmp	= dim->cmp;
	fmt->sort	= dim->cmp;
	fmt->color	= dim->color;
	fmt->entry	= dim->entry;
	fmt->header	= c2c_header;
	fmt->width	= c2c_width;
	fmt->collapse	= dim->cmp;
	fmt->equal	= fmt_equal;
	fmt->free	= fmt_free;

	return c2c_fmt;
}

int perf_c2c__browse_function_view(struct hists *hists __maybe_unused)
{
	return 0;
}
