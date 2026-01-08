// SPDX-License-Identifier: GPL-2.0
/**
 * C2C Symbol Browser - Display symbol-level cacheline sharing analysis
 * 
 * This file contains the symbol view implementation for C2C analysis,
 * including:
 * - Symbol histogram building and management
 * - Cacheline-to-symbol index for efficient lookups
 * - Symbol association building (finding related symbols)
 * - Symbol browser UI components
 */

#include <unistd.h>
#include <linux/list.h>
#include <linux/bitmap.h>
#include <linux/rbtree.h>
#include <linux/zalloc.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include "addr_location.h"
#include "ui/browsers/hists.h"
#include "util/mem-events.h"
#include "util/mem2node.h"
#include "util/hist.h"
#include "util/symbol.h"
#include "util/tool.h"
#include "../../c2c.h"
#include "util/session.h"
#include "util/env.h"
#include "util/map.h"
#include "util/maps.h"
#include "util/sort.h"
#include "util/mem-info.h"
#include "util/cacheline.h"
#include "util/debug.h"
#include "util/thread.h"

#define HITM_COUNT(stats) ((stats)->rmt_hitm + (stats)->lcl_hitm)

#define HEX_STR(__s, __v)				\
({							\
	scnprintf(__s, sizeof(__s), "0x%" PRIx64, __v);	\
	__s;						\
})

#define HEADER_LOW(__h)			\
	{				\
		.line[1] = {		\
			.text = __h,	\
		},			\
	}

#define HEADER_BOTH(__h0, __h1)		\
	{				\
		.line[0] = {		\
			.text = __h0,	\
		},			\
		.line[1] = {		\
			.text = __h1,	\
		},			\
	}

struct perf_c2c_ext c2c_ext;

#define SYMBOL_WIDTH 30
#define C2C_HEADER_MAX 2

struct c2c_header {
	struct {
		const char *text;
		int	    span;
	} line[C2C_HEADER_MAX];
};

struct c2c_dimension {
	struct c2c_header	 header;
	const char		*name;
	int			 width;
	struct sort_entry	*se;

	int64_t (*cmp)(struct perf_hpp_fmt *fmt,
		       struct hist_entry *, struct hist_entry *);
	int   (*entry)(struct perf_hpp_fmt *fmt, struct perf_hpp *hpp,
		       struct hist_entry *he);
	int   (*color)(struct perf_hpp_fmt *fmt, struct perf_hpp *hpp,
		       struct hist_entry *he);
};

struct c2c_fmt {
	struct perf_hpp_fmt	 fmt;
	struct c2c_dimension	*dim;
};

/* Forward declarations for functions used before their definitions */
static int c2c_width(struct perf_hpp_fmt *fmt, struct perf_hpp *hpp, struct hists *hists);
static uint64_t get_total_cycles_all_symbols(void);
static int c2c_symbol_hists__init(struct c2c_hists *hists, const char *sort,
				 int nr_header_lines, struct perf_env *env);
static int c2c_symbol_hists__reinit(struct c2c_hists *c2c_hists,
				   const char *output, const char *sort,
				   struct perf_env *env);
static void free_child_entries(struct hist_entry *parent_he);

/**
 * c2c_he_ext_zalloc - Allocate extended histogram entry for symbol view
 * @size: Size needed for hist_entry including dynamic callchain data
 *
 * Returns: Pointer to hist_entry within allocated c2c_hist_entry_ext, or NULL on failure
 */
static void *c2c_he_ext_zalloc(size_t size)
{
	struct c2c_hist_entry_ext *c2c_he_ext;

	/* Allocate extended structure plus space for hist_entry dynamic data
	 * size contains the space needed for hist_entry's dynamic part (callchain)
	 * sizeof(*c2c_he_ext) already includes the static hist_entry size
	 */
	c2c_he_ext = zalloc(size + sizeof(*c2c_he_ext));
	if (!c2c_he_ext)
		return NULL;

	/* Initialize extended fields first (they come before c2c_he in the structure) */
	INIT_LIST_HEAD(&c2c_he_ext->related_symbols);

	c2c_he_ext->c2c_he.cpuset = bitmap_zalloc(c2c.cpus_cnt);
	if (!c2c_he_ext->c2c_he.cpuset)
		goto out_free;

	c2c_he_ext->c2c_he.nodeset = bitmap_zalloc(c2c.nodes_cnt);
	if (!c2c_he_ext->c2c_he.nodeset)
		goto out_free;

	c2c_he_ext->c2c_he.node_stats = zalloc(c2c.nodes_cnt * sizeof(*c2c_he_ext->c2c_he.node_stats));
	if (!c2c_he_ext->c2c_he.node_stats)
		goto out_free;

	init_stats(&c2c_he_ext->c2c_he.cstats.lcl_hitm);
	init_stats(&c2c_he_ext->c2c_he.cstats.rmt_hitm);
	init_stats(&c2c_he_ext->c2c_he.cstats.lcl_peer);
	init_stats(&c2c_he_ext->c2c_he.cstats.rmt_peer);
	init_stats(&c2c_he_ext->c2c_he.cstats.load);

	return &c2c_he_ext->c2c_he.he;

out_free:
	zfree(&c2c_he_ext->c2c_he.nodeset);
	zfree(&c2c_he_ext->c2c_he.cpuset);
	free(c2c_he_ext);
	return NULL;
}

/**
 * c2c_he_ext_free - Free extended histogram entry for symbol view
 * @he: Pointer to hist_entry to free
 */
static void c2c_he_ext_free(void *he)
{
	struct c2c_hist_entry_ext *c2c_he_ext;

	c2c_he_ext = container_of(he, struct c2c_hist_entry_ext, c2c_he.he);

	/* Free base c2c_hist_entry */
	if (c2c_he_ext->c2c_he.hists) {
		hists__delete_entries(&c2c_he_ext->c2c_he.hists->hists);
		zfree(&c2c_he_ext->c2c_he.hists);
	}

	/* Free child entries first */
	free_child_entries((struct hist_entry *)he);

	/* Free all fields */
	zfree(&c2c_he_ext->c2c_he.nodeset);
	zfree(&c2c_he_ext->c2c_he.cpuset);
	zfree(&c2c_he_ext->c2c_he.nodestr);
	zfree(&c2c_he_ext->c2c_he.node_stats);

	if (!list_empty(&c2c_he_ext->related_symbols)) {
		struct related_symbol *rel_sym, *tmp;
		list_for_each_entry_safe(rel_sym, tmp, &c2c_he_ext->related_symbols, list) {
			list_del(&rel_sym->list);
			free(rel_sym);
		}
	}

	/* Free the extended structure */
	free(c2c_he_ext);
}

/* Entry operations for symbol view (uses extended histogram entries) */
static struct hist_entry_ops c2c_symbol_entry_ops = {
	.new	= c2c_he_ext_zalloc,
	.free	= c2c_he_ext_free,
};

/*
 * Entry functions for symbol view columns
 * These functions render individual cells in the symbol browser table
 */

/**
 * total_stores_entry - Render total stores column for symbol view
 */
static int
total_stores_entry(struct perf_hpp_fmt *fmt, struct perf_hpp *hpp,
		   struct hist_entry *he)
{
	struct c2c_hist_entry_ext *c2c_he_ext = container_of(he, struct c2c_hist_entry_ext, c2c_he.he);
	uint64_t total = (uint64_t)c2c_he_ext->c2c_he.stats.store;
	int width = c2c_width(fmt, hpp, he->hists);
	char buf[32];
	const char *indent;
	char indicator;

	/* Hide Stores for parent symbols */
	if (!he->parent_he)
		return scnprintf(hpp->buf, hpp->size, "%-*s", width, "");

	/* Build the stores string with proper indentation and folding indicator */
	indent = he->parent_he->parent_he ? "        " : "      ";
	indicator = he->has_children ? (he->unfolded ? '-' : '+') : ' ';

	if (he->has_children) {
		snprintf(buf, sizeof(buf), "%s%c %" PRIu64, indent, indicator, total);
	} else {
		snprintf(buf, sizeof(buf), "%s  %" PRIu64, indent, total);
	}

	return scnprintf(hpp->buf, hpp->size, "%-*s", width, buf);
}

/**
 * cacheline_symbol_entry - Render cacheline address for symbol view
 */
static int
cacheline_symbol_entry(struct perf_hpp_fmt *fmt, struct perf_hpp *hpp,
		       struct hist_entry *he)
{
	uint64_t addr = 0;
	int width = c2c_width(fmt, hpp, he->hists);
	char buf[20];

	/* Only display for cacheline entries - these are leaf nodes under related symbols */
	if (he->depth < 2 || !he->leaf)
		return scnprintf(hpp->buf, hpp->size, "%-*s", width, "");

	if (he->mem_info)
		addr = cl_address(mem_info__daddr(he->mem_info)->addr, chk_double_cl);

	return scnprintf(hpp->buf, hpp->size, "%-*s", width, HEX_STR(buf, addr));
}

/**
 * iaddr_symbol_entry - Render code address for symbol view with hierarchy indicators
 */
static int
iaddr_symbol_entry(struct perf_hpp_fmt *fmt, struct perf_hpp *hpp,
		   struct hist_entry *he)
{
	uint64_t addr = 0;
	int width = c2c_width(fmt, hpp, he->hists);
	char buf[32], hex_buf[20];

	if (he->mem_info)
		addr = mem_info__iaddr(he->mem_info)->addr;

	/* Hide Code address for entries with grandparent (cacheline level) */
	if (he->parent_he && he->parent_he->parent_he)
		return scnprintf(hpp->buf, hpp->size, "%-*s", width, "");

	/* Build the address string with proper indentation and folding indicator */
	if (he->parent_he) {
		/* Child entries (depth 1) */
		if (he->has_children) {
			snprintf(buf, sizeof(buf), "    %c %s",
				 he->unfolded ? '-' : '+', HEX_STR(hex_buf, addr));
		} else {
			snprintf(buf, sizeof(buf), "      %s", HEX_STR(hex_buf, addr));
		}
	} else {
		/* Top-level entries (depth 0) */
		if (he->has_children) {
			snprintf(buf, sizeof(buf), "%c %s",
				 he->unfolded ? '-' : '+', HEX_STR(hex_buf, addr));
		} else {
			snprintf(buf, sizeof(buf), "  %s", HEX_STR(hex_buf, addr));
		}
	}

	return scnprintf(hpp->buf, hpp->size, "%-*s", width, buf);
}

/**
 * symbol_view_entry - Render symbol name for symbol view with expansion indicators
 */
static int
symbol_view_entry(struct perf_hpp_fmt *fmt, struct perf_hpp *hpp,
		 struct hist_entry *he)
{
	const char *symname = he->ms.sym ? he->ms.sym->name : "[unknown]";
	int width = c2c_width(fmt, hpp, he->hists);
	char buf[KSYM_NAME_LEN];

	/* Hide Symbol for cacheline entries */
	if (he->parent_he && he->parent_he->parent_he)
		return scnprintf(hpp->buf, hpp->size, "%*s", width, "");
	else if (he->parent_he) {
		/* Child entries (depth 1) */
		if (he->has_children) {
			snprintf(buf, sizeof(buf), "    %c %s",
				 he->unfolded ? '-' : '+', symname);
		} else {
			snprintf(buf, sizeof(buf), "      %s", symname);
		}
	} else {
		/* Top-level entries (depth 0) */
		if (he->has_children) {
			snprintf(buf, sizeof(buf), "%c %s",
				 he->unfolded ? '-' : '+', symname);
		} else {
			snprintf(buf, sizeof(buf), "  %s", symname);
		}
	}

	return scnprintf(hpp->buf, hpp->size, "%-*s", width, buf);
}

/**
 * cycles_percent_entry - Render cycles percentage column
 */
static int
cycles_percent_entry(struct perf_hpp_fmt *fmt, struct perf_hpp *hpp,
		     struct hist_entry *he)
{
	struct c2c_hist_entry_ext *c2c_he;
	int width = c2c_width(fmt, hpp, he->hists);
	uint64_t symbol_cycles;
	uint64_t total_cycles;
	double pct;

	/* Hide Cycles Percent for child symbols and cachelines */
	if (he->parent_he)
		return scnprintf(hpp->buf, hpp->size, "%*s", width, "");

	c2c_he = container_of(he, struct c2c_hist_entry_ext, c2c_he.he);
	{
		uint64_t cycles_rmt, cycles_lcl, cycles_load, other_load, total_hitm;
		cycles_rmt = avg_stats(&c2c_he->c2c_he.cstats.rmt_hitm) * c2c_he->c2c_he.stats.rmt_hitm;
		cycles_lcl = avg_stats(&c2c_he->c2c_he.cstats.lcl_hitm) * c2c_he->c2c_he.stats.lcl_hitm;
		/* Prevent unsigned underflow by checking before subtraction */
		total_hitm = (uint64_t)c2c_he->c2c_he.stats.rmt_hitm + c2c_he->c2c_he.stats.lcl_hitm;
		other_load = (c2c_he->c2c_he.stats.load >= total_hitm) ? c2c_he->c2c_he.stats.load - total_hitm : 0;
		cycles_load = avg_stats(&c2c_he->c2c_he.cstats.load) * other_load;
		symbol_cycles = cycles_rmt + cycles_lcl + cycles_load;
	}

	total_cycles = get_total_cycles_all_symbols();
	pct = total_cycles > 0 ? (double)symbol_cycles / total_cycles * 100.0 : 0.0;

	return scnprintf(hpp->buf, hpp->size, "%*.2f%%", width-1, pct);
}

/**
 * cycles_percent_cmp - Comparison function for cycles percentage sorting
 */
static int64_t
cycles_percent_cmp(struct perf_hpp_fmt *fmt __maybe_unused,
		   struct hist_entry *left, struct hist_entry *right)
{
	struct c2c_hist_entry_ext *c2c_left = container_of(left, struct c2c_hist_entry_ext, c2c_he.he);
	struct c2c_hist_entry_ext *c2c_right = container_of(right, struct c2c_hist_entry_ext, c2c_he.he);
	uint64_t cycles_left, cycles_right;

	{
		uint64_t cycles_rmt, cycles_lcl, cycles_load, other_load, total_hitm;
		cycles_rmt = avg_stats(&c2c_left->c2c_he.cstats.rmt_hitm) * c2c_left->c2c_he.stats.rmt_hitm;
		cycles_lcl = avg_stats(&c2c_left->c2c_he.cstats.lcl_hitm) * c2c_left->c2c_he.stats.lcl_hitm;
		total_hitm = (uint64_t)c2c_left->c2c_he.stats.rmt_hitm + c2c_left->c2c_he.stats.lcl_hitm;
		other_load = (c2c_left->c2c_he.stats.load >= total_hitm) ? c2c_left->c2c_he.stats.load - total_hitm : 0;
		cycles_load = avg_stats(&c2c_left->c2c_he.cstats.load) * other_load;
		cycles_left = cycles_rmt + cycles_lcl + cycles_load;
	}
	{
		uint64_t cycles_rmt, cycles_lcl, cycles_load, other_load, total_hitm;
		cycles_rmt = avg_stats(&c2c_right->c2c_he.cstats.rmt_hitm) * c2c_right->c2c_he.stats.rmt_hitm;
		cycles_lcl = avg_stats(&c2c_right->c2c_he.cstats.lcl_hitm) * c2c_right->c2c_he.stats.lcl_hitm;
		total_hitm = (uint64_t)c2c_right->c2c_he.stats.rmt_hitm + c2c_right->c2c_he.stats.lcl_hitm;
		other_load = (c2c_right->c2c_he.stats.load >= total_hitm) ? c2c_right->c2c_he.stats.load - total_hitm : 0;
		cycles_load = avg_stats(&c2c_right->c2c_he.cstats.load) * other_load;
		cycles_right = cycles_rmt + cycles_lcl + cycles_load;
	}

	return (int64_t)cycles_left - (int64_t)cycles_right;
}

/**
 * iaddr_symbol_cmp - Comparison function for instruction address sorting in symbol view
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

/**
 * total_stores_cmp - Comparison function for total stores sorting in symbol view
 */
static int64_t
total_stores_cmp(struct perf_hpp_fmt *fmt __maybe_unused,
		 struct hist_entry *left, struct hist_entry *right)
{
	struct c2c_hist_entry_ext *c2c_left = container_of(left, struct c2c_hist_entry_ext, c2c_he.he);
	struct c2c_hist_entry_ext *c2c_right = container_of(right, struct c2c_hist_entry_ext, c2c_he.he);

	return (uint64_t)c2c_left->c2c_he.stats.store -
	       (uint64_t)c2c_right->c2c_he.stats.store;
}

/**
 * struct grand_item - Grandchild entry for sorting
 * @grand_c2c: C2C histogram entry extension for the grandchild
 * @grand_he: Histogram entry for the grandchild
 * @stores: Store count for sorting
 */
struct grand_item {
	struct c2c_hist_entry_ext	*grand_c2c;
	struct hist_entry	*grand_he;
	u64			 stores;
};

/**
 * related_symbol_cmp - Compare related symbols by store count (descending)
 */
static int related_symbol_cmp(const void *a, const void *b)
{
	const struct related_symbol *sym_a = *(const struct related_symbol **)a;
	const struct related_symbol *sym_b = *(const struct related_symbol **)b;

	if (sym_b->stats.store > sym_a->stats.store)
		return 1;
	else if (sym_b->stats.store < sym_a->stats.store)
		return -1;
	return 0;
}

/**
 * grand_item_cmp - Compare grand items by store count (descending)
 */
static int grand_item_cmp(const void *a, const void *b)
{
	const struct grand_item *item_a = (const struct grand_item *)a;
	const struct grand_item *item_b = (const struct grand_item *)b;

	if (item_b->stores > item_a->stores)
		return 1;
	else if (item_b->stores < item_a->stores)
		return -1;
	return 0;
}

/* Helper function to merge two stats structures */
static void merge_stats(struct stats *dest, struct stats *src)
{
	double delta;

	if (src->n == 0)
		return;

	if (dest->n == 0) {
		*dest = *src;
		return;
	}

	delta = src->mean - dest->mean;
	dest->M2 += src->M2 + delta * delta * dest->n * src->n / (dest->n + src->n);
	dest->mean = (dest->mean * dest->n + src->mean * src->n) / (dest->n + src->n);
	dest->n += src->n;

	/* Update min/max */
	if (src->max > dest->max)
		dest->max = src->max;
	if (src->min < dest->min)
		dest->min = src->min;
}

/* Function to merge compute_stats during symbol aggregation */
static void c2c_add_cstats(struct compute_stats *dest, struct compute_stats *src)
{
	merge_stats(&dest->rmt_hitm, &src->rmt_hitm);
	merge_stats(&dest->lcl_hitm, &src->lcl_hitm);
	merge_stats(&dest->rmt_peer, &src->rmt_peer);
	merge_stats(&dest->lcl_peer, &src->lcl_peer);
	merge_stats(&dest->load, &src->load);
}

/**
 * init_grandchild_hist_entry - Initialize a grandchild hist_entry for symbol view
 * @grand_he: The grandchild hist_entry to initialize
 * @grand_c2c: The corresponding c2c_hist_entry_ext
 * @cl_entry: Cacheline entry containing base information
 * @child_he: Parent hist_entry (the symbol child)
 * @child_access: Symbol access data for statistics
 *
 * Returns: 0 on success, negative value on memory allocation failure
 */
static int init_grandchild_hist_entry(struct hist_entry *grand_he,
				     struct c2c_hist_entry_ext *grand_c2c,
				     struct cacheline_symbol_entry *cl_entry,
				     struct hist_entry *child_he,
				     struct symbol_access *child_access)
{
	/* Basic initialization */
	INIT_LIST_HEAD(&grand_c2c->related_symbols);

	/* Copy map_symbol from cacheline entry, but clear sym to print cacheline address */
	memcpy(&grand_he->ms, &cl_entry->he_cl->ms, sizeof(struct map_symbol));
	grand_he->ms.sym = NULL;

	/* Copy thread and CPU information from cacheline entry */
	grand_he->mem_info = mem_info__get(cl_entry->he_cl->mem_info);
	grand_he->thread = cl_entry->he_cl->thread;
	grand_he->cpumode = cl_entry->he_cl->cpumode;
	grand_he->cpu = cl_entry->he_cl->cpu;
	grand_he->socket = cl_entry->he_cl->socket;

	/* Hierarchy setup */
	grand_he->parent_he = child_he;
	grand_he->depth = child_he->depth + 1;
	grand_he->leaf = true;
	grand_he->hists = &c2c_ext.symbol_hists.hists;
	grand_he->filtered = false;
	grand_he->unfolded = false;
	grand_he->has_children = false;
	grand_he->nr_rows = 0;
	grand_he->row_offset = 0;

	/* Initialize stat structures */
	memset(&grand_he->stat, 0, sizeof(grand_he->stat));
	grand_he->hroot_in = RB_ROOT_CACHED;
	grand_he->hroot_out = RB_ROOT_CACHED;
	INIT_LIST_HEAD(&grand_he->pairs.node);

	/* Set hierarchy pointers */
	grand_he->hpp_list = &c2c_ext.symbol_hists.list;

	/* Copy statistics from symbol access data */
	memcpy(&grand_c2c->c2c_he.stats, &child_access->stats, sizeof(grand_c2c->c2c_he.stats));
	memcpy(&grand_c2c->c2c_he.cstats, &child_access->cstats, sizeof(grand_c2c->c2c_he.cstats));

	/* Calculate display statistics */
	grand_he->stat.nr_events = HITM_COUNT(&grand_c2c->c2c_he.stats) +
				   grand_c2c->c2c_he.stats.lcl_peer + grand_c2c->c2c_he.stats.rmt_peer;
	grand_he->stat.period = grand_he->stat.nr_events;
	grand_he->stat.weight1 = HITM_COUNT(&grand_c2c->c2c_he.stats);

	/* Initialize stat_acc for callchain accumulation if needed */
	if (symbol_conf.cumulate_callchain) {
		grand_he->stat_acc = calloc(1, sizeof(struct he_stat));
		if (!grand_he->stat_acc)
			return -ENOMEM;
		memcpy(grand_he->stat_acc, &grand_he->stat, sizeof(struct he_stat));
	}

	return 0;
}

/**
 * cleanup_grandchild_entry - Clean up resources for a grandchild hist_entry
 * @grand_he: The grandchild hist_entry to clean up
 * @grand_c2c: The corresponding c2c_hist_entry_ext
 */
static void cleanup_grandchild_entry(struct hist_entry *grand_he,
				     struct c2c_hist_entry_ext *grand_c2c)
{
	if (grand_he->mem_info)
		mem_info__put(grand_he->mem_info);
	if (grand_he->stat_acc)
		free(grand_he->stat_acc);
	free(grand_c2c);
}

/**
 * cleanup_grandchildren_items - Clean up all items in the grandchildren array
 * @items: Array of grand_item structures
 * @items_cnt: Number of items in the array
 * @current_he: Current hist_entry being constructed (can be NULL)
 * @current_c2c: Current c2c_hist_entry_ext being constructed (can be NULL)
 */
static void cleanup_grandchildren_items(struct grand_item *items, int items_cnt,
					struct hist_entry *current_he,
					struct c2c_hist_entry_ext *current_c2c)
{
	/* Clean up the current entry being constructed if provided */
	if (current_he && current_c2c)
		cleanup_grandchild_entry(current_he, current_c2c);

	/* Clean up all previously allocated grand_c2c structures */
	for (int j = 0; j < items_cnt; j++) {
		cleanup_grandchild_entry(items[j].grand_he, items[j].grand_c2c);
	}
	free(items);
}

/**
 * validate_and_prepare_entries - Validate and prepare for populating symbol children
 * @he: Histogram entry to validate
 *
 * Returns the c2c_hist_entry_ext if valid, NULL otherwise
 */
static struct c2c_hist_entry_ext *validate_and_prepare_entries(struct hist_entry *he)
{
	struct c2c_hist_entry_ext *c2c_he;
	struct rb_root_cached *root;

	if (!he || !he->has_children)
		return NULL;

	root = &he->hroot_out;

	/* If already populated, return */
	if (!RB_EMPTY_ROOT(&root->rb_root))
		return NULL;

	c2c_he = container_of(he, struct c2c_hist_entry_ext, c2c_he.he);

	/* Ensure related_symbols list is valid */
	if (list_empty(&c2c_he->related_symbols)) {
		he->has_children = false;  /* Reset inconsistent state */
		return NULL;
	}

	return c2c_he;
}

/**
 * sort_related_symbols_by_stores - Sort related symbols by stores descending
 * @c2c_he: C2C histogram entry containing related symbols
 * @num_rel_out: Output parameter for number of related symbols
 *
 * Returns allocated array of sorted related_symbol pointers, or NULL on error.
 * Caller must free the returned array.
 */
static struct related_symbol **sort_related_symbols_by_stores(struct c2c_hist_entry_ext *c2c_he,
							      int *num_rel_out)
{
	struct related_symbol *rel_sym;
	struct related_symbol **sorted = NULL;
	int num_rel = 0, idx = 0;

	/* Count related symbols and allocate array in one pass */
	list_for_each_entry(rel_sym, &c2c_he->related_symbols, list)
		num_rel++;

	if (num_rel == 0) {
		*num_rel_out = 0;
		return NULL;
	}

	sorted = calloc(num_rel, sizeof(*sorted));
	if (!sorted) {
		*num_rel_out = 0;
		return NULL;
	}

	/* Fill array in the same pass */
	list_for_each_entry(rel_sym, &c2c_he->related_symbols, list)
		sorted[idx++] = rel_sym;

	/* Sort by stats.store descending */
	qsort(sorted, num_rel, sizeof(*sorted), related_symbol_cmp);

	*num_rel_out = num_rel;
	return sorted;
}

/**
 * create_symbol_child_entry - Create and initialize a symbol child entry
 * @parent_he: Parent histogram entry
 * @rel_sym: Related symbol to create entry for
 *
 * Returns the created hist_entry or NULL on error
 */
static struct hist_entry *create_symbol_child_entry(struct hist_entry *parent_he,
						    struct related_symbol *rel_sym)
{
	struct c2c_hist_entry_ext *child_c2c_he, *child_c2c;
	struct hist_entry *child_he;

	if (!rel_sym || !rel_sym->sym)
		return NULL;

	/* Allocate child hist_entry - simplified version for symbol children */
	child_c2c_he = zalloc(sizeof(*child_c2c_he));
	if (!child_c2c_he)
		return NULL;

	/* Initialize the related_symbols list */
	INIT_LIST_HEAD(&child_c2c_he->related_symbols);

	child_he = &child_c2c_he->c2c_he.he;

	/* Complete initialization - copy parent's map_symbol structure first */
	memcpy(&child_he->ms, &parent_he->ms, sizeof(struct map_symbol));
	/* Then override the symbol and address */
	child_he->ms.sym = rel_sym->sym;

	/* Create a synthetic mem_info to store the iaddr for proper display */
	if (parent_he->mem_info) {
		child_he->mem_info = mem_info__clone(parent_he->mem_info);
		if (child_he->mem_info) {
			/* Set the instruction address to the related symbol's iaddr */
			mem_info__iaddr(child_he->mem_info)->addr = rel_sym->iaddr;
		}
	}

	/* Copy essential fields from parent */
	child_he->thread = parent_he->thread;
	child_he->cpumode = parent_he->cpumode;
	child_he->cpu = parent_he->cpu;
	child_he->socket = parent_he->socket;

	/* Set hierarchy fields */
	child_he->parent_he = parent_he;
	child_he->depth = parent_he->depth + 1;
	child_he->leaf = false; /* it can have grandchildren (cachelines) */
	/* In symbol view, all entries should use symbol_hists */
	child_he->hists = &c2c_ext.symbol_hists.hists;
	child_he->filtered = false;  /* Make sure it's not filtered out */
	child_he->unfolded = false;
	child_he->has_children = false; /* Will be set to true only if grandchildren are added */
	child_he->has_no_entry = false;
	child_he->nr_rows = 0;
	child_he->row_offset = 0;

	/* Initialize stats properly */
	memset(&child_he->stat, 0, sizeof(child_he->stat));

	/* Set stat values based on c2c stats */
	child_he->stat.nr_events = HITM_COUNT(&rel_sym->stats) +
				   rel_sym->stats.rmt_peer + rel_sym->stats.lcl_peer;
	child_he->stat.period = child_he->stat.nr_events;

	/* These weight fields are used by some columns */
	child_he->stat.weight1 = HITM_COUNT(&rel_sym->stats);

	/* Initialize stat_acc - allocate if needed */
	if (symbol_conf.cumulate_callchain) {
		child_he->stat_acc = calloc(1, sizeof(struct he_stat));
		if (child_he->stat_acc)
			memcpy(child_he->stat_acc, &child_he->stat, sizeof(struct he_stat));
	}

	/* Initialize rb trees */
	child_he->hroot_in = RB_ROOT_CACHED;
	child_he->hroot_out = RB_ROOT_CACHED;

	/* Initialize pairs list */
	INIT_LIST_HEAD(&child_he->pairs.node);

	/* Initialize hierarchy pointers */
	child_he->hpp_list = &c2c_ext.symbol_hists.list;

	/* Copy c2c stats - this is what c2c columns use */
	child_c2c = container_of(child_he, struct c2c_hist_entry_ext, c2c_he.he);
	memcpy(&child_c2c->c2c_he.stats, &rel_sym->stats, sizeof(rel_sym->stats));
	memcpy(&child_c2c->c2c_he.cstats, &rel_sym->cstats, sizeof(rel_sym->cstats));
	INIT_LIST_HEAD(&child_c2c->related_symbols);

	/* Build cacheline grandchildren under each related symbol child */
	child_c2c->c2c_he.hists = NULL;

	return child_he;
}

/**
 * build_cacheline_symbol_index - Build index mapping cachelines to accessing symbols
 *
 * Creates an optimized index structure for looking up which symbols
 * access each cacheline. This is used for building symbol associations
 * and populating child entries efficiently.
 */
static void build_cacheline_symbol_index(void)
{
	struct rb_node *nd_cl;
	int index = 0;

	/* Return early if already built */
	if (c2c_ext.cacheline_index_built)
		return;

	/* Free existing index if any */
	if (c2c_ext.cacheline_index) {
		for (int i = 0; i < c2c_ext.cacheline_index_size; i++) {
			struct symbol_access *sa = c2c_ext.cacheline_index[i].symbol_accesses;

			while (sa) {
				struct symbol_access *next = sa->next;

				free(sa);
				sa = next;
			}
		}
		free(c2c_ext.cacheline_index);
		c2c_ext.cacheline_index = NULL;
	}

	/* Build index in single pass with dynamic array growth */
	c2c_ext.cacheline_index_size = 0;
	c2c_ext.cacheline_index_capacity = 64; /* Start with reasonable size */

	c2c_ext.cacheline_index = malloc(c2c_ext.cacheline_index_capacity * sizeof(struct cacheline_symbol_entry));
	if (!c2c_ext.cacheline_index) {
		c2c_ext.cacheline_index_size = 0;
		return;
	}

	nd_cl = rb_first_cached(&c2c.hists.hists.entries);
	while (nd_cl) {
		struct hist_entry *he_cl;

		/* Grow array if needed */
		if (index >= c2c_ext.cacheline_index_capacity) {
			struct cacheline_symbol_entry *new_index;
			int cleanup_i;

			c2c_ext.cacheline_index_capacity *= 2;
			new_index = realloc(c2c_ext.cacheline_index,
				c2c_ext.cacheline_index_capacity * sizeof(struct cacheline_symbol_entry));
			if (!new_index) {
				/* Cleanup on allocation failure */
				for (cleanup_i = 0; cleanup_i < c2c_ext.cacheline_index_size; cleanup_i++) {
					struct symbol_access *sa = c2c_ext.cacheline_index[cleanup_i].symbol_accesses;

					while (sa) {
						struct symbol_access *next = sa->next;

						free(sa);
						sa = next;
					}
				}
				free(c2c_ext.cacheline_index);
				c2c_ext.cacheline_index = NULL;
				c2c_ext.cacheline_index_size = 0;
				return;
			}
			c2c_ext.cacheline_index = new_index;
		}

		he_cl = rb_entry(nd_cl, struct hist_entry, rb_node);

		c2c_ext.cacheline_index[index].he_cl = he_cl;
		c2c_ext.cacheline_index[index].c2c_he_cl = container_of(he_cl, struct c2c_hist_entry, he);
		c2c_ext.cacheline_index[index].symbol_accesses = NULL;

		/* Build symbol access list for this cacheline with proper aggregation */
		if (container_of(he_cl, struct c2c_hist_entry, he)->hists &&
		    container_of(he_cl, struct c2c_hist_entry, he)->hists->hists.entries.rb_root.rb_node) {
			struct rb_node *nd_d = rb_first_cached(&container_of(he_cl, struct c2c_hist_entry, he)->hists->hists.entries);

			while (nd_d) {
				struct hist_entry *he_d = rb_entry(nd_d, struct hist_entry, rb_node);

				if (he_d->ms.sym && !he_d->filtered) {
					uint64_t iaddr_d = he_d->mem_info ? mem_info__iaddr(he_d->mem_info)->addr : he_d->ms.sym->start;
					struct symbol_access *cur = c2c_ext.cacheline_index[index].symbol_accesses;
					bool merged = false;

					/* Check if we already have an entry for this symbol+iaddr combination */
					while (cur) {
						if (symbol_name_equal(cur->sym, he_d->ms.sym) && cur->iaddr == iaddr_d) {
							/* Aggregate statistics */
							c2c_add_stats(&cur->stats, &container_of(he_d, struct c2c_hist_entry, he)->stats);
							c2c_add_cstats(&cur->cstats, &container_of(he_d, struct c2c_hist_entry, he)->cstats);
							merged = true;
							break;
						}
						cur = cur->next;
					}

					/* Create new entry if not found */
					if (!merged) {
						struct symbol_access *sa = malloc(sizeof(struct symbol_access));

						if (sa) {
							sa->sym = he_d->ms.sym;
							sa->iaddr = iaddr_d;
							sa->map = he_d->ms.map;
							sa->maps = he_d->ms.maps;
							memcpy(&sa->stats, &container_of(he_d, struct c2c_hist_entry, he)->stats, sizeof(sa->stats));
							memcpy(&sa->cstats, &container_of(he_d, struct c2c_hist_entry, he)->cstats, sizeof(sa->cstats));
							sa->next = c2c_ext.cacheline_index[index].symbol_accesses;
							c2c_ext.cacheline_index[index].symbol_accesses = sa;
						}
					}
				}
				nd_d = rb_next(nd_d);
			}
		}

		index++;
		c2c_ext.cacheline_index_size = index;  /* Update size as we go */
		nd_cl = rb_next(nd_cl);
	}

	/* Mark as built to prevent redundant calls */
	c2c_ext.cacheline_index_built = true;
}

/**
 * populate_cacheline_grandchildren - Populate cacheline grandchildren for a symbol child
 * @parent_he: Top-level parent histogram entry
 * @child_he: Child histogram entry (related symbol)
 * @rel_sym: Related symbol structure
 *
 * Returns the number of grandchildren created
 */
static int populate_cacheline_grandchildren(struct hist_entry *parent_he,
					    struct hist_entry *child_he,
					    struct related_symbol *rel_sym)
{
	struct rb_root_cached *groot = &child_he->hroot_out;
	/* temp array to sort grandchildren by Stores */
	struct grand_item *items = NULL;

	int items_cnt = 0, items_cap = 0;
	u64 parent_iaddr = parent_he->mem_info ? mem_info__iaddr(parent_he->mem_info)->addr :
			   (parent_he->ms.sym ? parent_he->ms.sym->start : 0);

	/* Use the pre-built index instead of traversing all cachelines */
	for (int i = 0; i < c2c_ext.cacheline_index_size; i++) {
		struct cacheline_symbol_entry *cl_entry = &c2c_ext.cacheline_index[i];
		struct symbol_access *parent_access = NULL, *child_access = NULL;

		/* Check if both parent and child symbols access this cacheline */
		for (struct symbol_access *sa = cl_entry->symbol_accesses; sa; sa = sa->next) {
			if (symbol_name_equal(sa->sym, parent_he->ms.sym) && sa->iaddr == parent_iaddr)
				parent_access = sa;
			else if (symbol_name_equal(sa->sym, rel_sym->sym) && sa->iaddr == rel_sym->iaddr)
				child_access = sa;

			/* Early exit if both found */
			if (parent_access && child_access)
				break;
		}

		if (parent_access && child_access) {
			struct c2c_hist_entry_ext *grand_c2c = zalloc(sizeof(*grand_c2c));
			struct hist_entry *grand_he;
			u64 child_stores = child_access->stats.store;

			if (!grand_c2c) {
				cleanup_grandchildren_items(items, items_cnt, NULL, NULL);
				return 0;
			}

			grand_he = &grand_c2c->c2c_he.he;

			/* Initialize grandchild hist_entry using helper function */
			if (init_grandchild_hist_entry(grand_he, grand_c2c, cl_entry,
						       child_he, child_access) != 0) {
				cleanup_grandchildren_items(items, items_cnt, grand_he, grand_c2c);
				return 0;
			}

			/* push into temp array */
			if (items_cnt == items_cap) {
				int new_cap = items_cap ? items_cap * 2 : 8;
				struct grand_item *ni = realloc(items, new_cap * sizeof(*items));

				if (!ni) {
					cleanup_grandchildren_items(items, items_cnt, grand_he, grand_c2c);
					return 0;  /* All items were cleaned up, return 0 */
				}
				items = ni;
				items_cap = new_cap;
			}
			items[items_cnt].grand_c2c = grand_c2c;
			items[items_cnt].grand_he = grand_he;
			items[items_cnt].stores = child_stores;
			items_cnt++;
		}
	}

	/* sort by stores desc using qsort */
	if (items_cnt > 0)
		qsort(items, items_cnt, sizeof(struct grand_item), grand_item_cmp);

	/* insert in order */
	for (int a = 0; a < items_cnt; a++) {
		struct rb_node **p = &groot->rb_root.rb_node;
		struct rb_node *parent = NULL;
		bool leftmost = true;

		while (*p != NULL) {
			parent = *p;
			p = &parent->rb_right;
			leftmost = false;
		}
		rb_link_node(&items[a].grand_he->rb_node, parent, p);
		rb_insert_color_cached(&items[a].grand_he->rb_node, groot, leftmost);
	}

	/* mark child has_children only if any grandchildren were added */
	child_he->has_children = items_cnt > 0;
	if (items_cnt > 0) {
		/* Update nr_rows to include grandchildren count */
		child_he->nr_rows = items_cnt;
	}

	free(items);
	return items_cnt;
}

/**
 * populate_symbol_children - Create child entries for a symbol
 * @he: Parent histogram entry to populate
 *
 * Creates child entries (related symbols) under the given parent entry.
 * Each child represents a symbol that shares a cacheline with the parent.
 */
static void populate_symbol_children(struct hist_entry *he)
{
	struct c2c_hist_entry_ext *c2c_he;
	struct related_symbol **sorted;
	struct rb_root_cached *root;
	struct rb_node **p, *parent;
	bool leftmost;
	int count = 0, num_rel, i;

	/* Validate and prepare entries */
	c2c_he = validate_and_prepare_entries(he);
	if (!c2c_he)
		return;

	root = &he->hroot_out;

	/* Sort related symbols by stores descending */
	sorted = sort_related_symbols_by_stores(c2c_he, &num_rel);
	if (!sorted)
		return;

	/* Create and populate child entries */
	for (i = 0; i < num_rel; i++) {
		struct hist_entry *child_he;
		struct related_symbol *rel_sym = sorted[i];

		/* Create child entry */
		child_he = create_symbol_child_entry(he, rel_sym);
		if (!child_he)
			continue;

		/* Populate grandchildren (cachelines) */
		populate_cacheline_grandchildren(he, child_he, rel_sym);

		/* Insert child into the parent's tree */
		p = &root->rb_root.rb_node;
		parent = NULL;
		leftmost = true;
		while (*p != NULL) {
			parent = *p;
			p = &parent->rb_right;
			leftmost = false;
		}

		rb_link_node(&child_he->rb_node, parent, p);
		rb_insert_color_cached(&child_he->rb_node, root, leftmost);

		count++;
	}

	free(sorted);

	/* Update parent's nr_rows and has_children flag */
	if (count > 0) {
		he->nr_rows = count;
		he->has_children = true;
	} else {
		he->nr_rows = 0;
		he->has_children = false;
	}
}

/**
 * build_symbol_associations - Build associations between symbols sharing cachelines
 *
 * Logic: When multiple symbols access the same cacheline (false sharing),
 * they are considered related. The association count increases by 1 for
 * each shared cacheline between two symbols.
 */
static void build_symbol_associations(void)
{
	struct rb_node *nd_sym;
	struct hist_entry *he_sym;
	struct c2c_hist_entry_ext *c2c_he_sym;
	int cl_idx;

	/*
	 * Algorithm:
	 * 1. For each cacheline that has HITM events
	 * 2. Look at its detailed access records
	 * 3. Find all symbols that accessed it with HITM
	 * 4. Create associations between these symbols
	 */

	/* Phase 1: Use cached index to find symbol conflicts efficiently */
	/* Build cacheline index (will only build once due to internal flag) */
	build_cacheline_symbol_index();

	/* Iterate through cached index instead of rb-tree */
	for (cl_idx = 0; cl_idx < c2c_ext.cacheline_index_size; cl_idx++) {
		struct cacheline_symbol_entry *cl_entry = &c2c_ext.cacheline_index[cl_idx];
		struct symbol_addr_pair {
			struct symbol *sym;
			uint64_t iaddr;
		} *symbols_with_hitm = NULL;
		int symbol_count = 0;
		int symbol_capacity = 0;
		struct symbol_access *sa;
		int i, j;

		/* Skip cachelines without HITM events */
		if (HITM_COUNT(&cl_entry->c2c_he_cl->stats) == 0)
			continue;

		/* Collect all (symbol, address) pairs that accessed this cacheline with HITM */
		for (sa = cl_entry->symbol_accesses; sa; sa = sa->next) {
			if (sa->sym && HITM_COUNT(&sa->stats) > 0) {
				uint64_t iaddr = sa->iaddr ? sa->iaddr : sa->sym->start;
				/* Add (symbol, iaddr) pair to list if not already there */
				bool found = false;

				for (i = 0; i < symbol_count; i++) {
					if (symbol_name_equal(symbols_with_hitm[i].sym, sa->sym) &&
					    symbols_with_hitm[i].iaddr == iaddr) {
						found = true;
						break;
					}
				}

				if (!found) {
					if (symbol_count >= symbol_capacity) {
						struct symbol_addr_pair *new_symbols;
						int new_capacity = symbol_capacity ? symbol_capacity * 2 : 4;

						new_symbols = realloc(symbols_with_hitm,
								    new_capacity * sizeof(struct symbol_addr_pair));
						if (!new_symbols) {
							/* Memory allocation failed, skip this symbol */
							continue;
						}
						symbols_with_hitm = new_symbols;
						symbol_capacity = new_capacity;
					}
					if (symbols_with_hitm) {
						symbols_with_hitm[symbol_count].sym = sa->sym;
						symbols_with_hitm[symbol_count].iaddr = iaddr;
						symbol_count++;
					}
				}
			}
		}

		/* Create associations between all symbols that conflict on this cacheline */
		if (symbol_count > 1) {
			for (i = 0; i < symbol_count; i++) {
				/* Find symbol entry in symbol_hists */
				nd_sym = rb_first_cached(&c2c_ext.symbol_hists.hists.entries);
				while (nd_sym) {
					he_sym = rb_entry(nd_sym, struct hist_entry, rb_node);
					/* Match parent entry by BOTH symbol and code address */
					{
						uint64_t parent_iaddr = 0;

						if (he_sym->mem_info)
							parent_iaddr = mem_info__iaddr(he_sym->mem_info)->addr;
						else if (he_sym->ms.sym)
							parent_iaddr = he_sym->ms.sym->start;

						if (symbol_name_equal(he_sym->ms.sym, symbols_with_hitm[i].sym) &&
							parent_iaddr == symbols_with_hitm[i].iaddr) {
							c2c_he_sym = container_of(he_sym, struct c2c_hist_entry_ext, c2c_he.he);

							/* Add all other symbols as related */
							for (j = 0; j < symbol_count; j++) {
								if (i != j) {
									struct related_symbol *rel_sym;
									bool exists = false;

									/* Check if already added (compare both sym and iaddr) */
									list_for_each_entry(rel_sym, &c2c_he_sym->related_symbols, list) {
										if (symbol_name_equal(rel_sym->sym, symbols_with_hitm[j].sym) &&
											rel_sym->iaddr == symbols_with_hitm[j].iaddr) {
											exists = true;
											break;
										}
									}

									if (!exists) {
										rel_sym = zalloc(sizeof(*rel_sym));
										if (rel_sym) {
											rel_sym->sym = symbols_with_hitm[j].sym;
											rel_sym->iaddr = symbols_with_hitm[j].iaddr;
											/* zalloc already zeros memory, no need for memset */
											list_add_tail(&rel_sym->list, &c2c_he_sym->related_symbols);
										}
									}
								}
							}

							/* Mark as having children */
							if (!list_empty(&c2c_he_sym->related_symbols)) {
								he_sym->has_children = true;
								he_sym->unfolded = false;
								he_sym->leaf = false;
							}

							break;
						}
					}
					nd_sym = rb_next(nd_sym);
				}
			}
		}

		free(symbols_with_hitm);
	}

	/* Phase 2: Aggregate stats for related symbols using cached index */
	nd_sym = rb_first_cached(&c2c_ext.symbol_hists.hists.entries);
	while (nd_sym) {
		struct related_symbol *rel_sym;

		he_sym = rb_entry(nd_sym, struct hist_entry, rb_node);
		c2c_he_sym = container_of(he_sym, struct c2c_hist_entry_ext, c2c_he.he);

		/* For each related symbol, aggregate stats from shared cachelines using cached index */
		list_for_each_entry(rel_sym, &c2c_he_sym->related_symbols, list) {
			/* Precompute parent's iaddr once */
			uint64_t parent_iaddr = he_sym->mem_info ?
				mem_info__iaddr(he_sym->mem_info)->addr :
				(he_sym->ms.sym ? he_sym->ms.sym->start : 0);

			/* Use cached index instead of nested rb_next loops */
			for (cl_idx = 0; cl_idx < c2c_ext.cacheline_index_size; cl_idx++) {
				struct cacheline_symbol_entry *cl_entry = &c2c_ext.cacheline_index[cl_idx];
				struct symbol_access *sa_inner;
				bool target_found = false;

				/* First pass: check if target symbol accessed this cacheline */
				for (sa_inner = cl_entry->symbol_accesses; sa_inner; sa_inner = sa_inner->next) {
					if (symbol_name_equal(sa_inner->sym, he_sym->ms.sym) && sa_inner->iaddr == parent_iaddr) {
						target_found = true;
						break;
					}
				}

				if (!target_found)
					continue;

				/* Second pass: aggregate related symbol stats */
				for (sa_inner = cl_entry->symbol_accesses; sa_inner; sa_inner = sa_inner->next) {
					if (symbol_name_equal(sa_inner->sym, rel_sym->sym) && sa_inner->iaddr == rel_sym->iaddr) {
						c2c_add_stats(&rel_sym->stats, &sa_inner->stats);
						c2c_add_cstats(&rel_sym->cstats, &sa_inner->cstats);
					}
				}
			}
		}

		nd_sym = rb_next(nd_sym);
	}

	/* Phase 3: Create child entries for symbols with associations */
	nd_sym = rb_first_cached(&c2c_ext.symbol_hists.hists.entries);
	while (nd_sym) {
		he_sym = rb_entry(nd_sym, struct hist_entry, rb_node);
		if (he_sym->has_children)
			populate_symbol_children(he_sym);
		nd_sym = rb_next(nd_sym);
	}
}


/**
 * get_total_cycles_all_symbols - Calculate total cycles for all symbols
 *
 * Returns the total cycles across all symbols, using cached value if available
 */
static uint64_t get_total_cycles_all_symbols(void)
{
	struct rb_node *nd;
	uint64_t total_cycles = 0;

	/* Use cached value if available to avoid O(n) scan per row */
	if (c2c_ext.symbol_total_cycles_valid)
		return c2c_ext.symbol_total_cycles;

	nd = rb_first_cached(&c2c_ext.symbol_hists.hists.entries);
	while (nd) {
		struct hist_entry *he = rb_entry(nd, struct hist_entry, rb_node);
		struct c2c_hist_entry_ext *c2c_he = container_of(he, struct c2c_hist_entry_ext, c2c_he.he);
		uint64_t cycles_rmt, cycles_lcl, cycles_load, other_load, total_hitm, symbol_cycles;

		cycles_rmt = avg_stats(&c2c_he->c2c_he.cstats.rmt_hitm) * c2c_he->c2c_he.stats.rmt_hitm;
		cycles_lcl = avg_stats(&c2c_he->c2c_he.cstats.lcl_hitm) * c2c_he->c2c_he.stats.lcl_hitm;
		/* Prevent unsigned underflow by checking before subtraction */
		total_hitm = (uint64_t)c2c_he->c2c_he.stats.rmt_hitm + c2c_he->c2c_he.stats.lcl_hitm;
		other_load = (c2c_he->c2c_he.stats.load >= total_hitm) ? c2c_he->c2c_he.stats.load - total_hitm : 0;
		cycles_load = avg_stats(&c2c_he->c2c_he.cstats.load) * other_load;

		symbol_cycles = cycles_rmt + cycles_lcl + cycles_load;
		total_cycles += symbol_cycles;
		nd = rb_next(nd);
	}

	c2c_ext.symbol_total_cycles = total_cycles;
	c2c_ext.symbol_total_cycles_valid = true;
	return total_cycles;
}

/**
 * build_symbol_hists - Build symbol-level histograms from cacheline data
 * @env: Perf environment containing symbol tables
 *
 * Returns: 0 on success, negative error code on failure
 */
static int build_symbol_hists(void)
{
	struct rb_node *next;
	struct hist_entry *he_sym;
	struct c2c_hist_entry_ext *c2c_he_sym;
	struct addr_location al;
	struct perf_sample sample = {};
	struct thread *synthetic_thread = NULL;
	int ret, i;

	/* Invalidate cached total cycles before (re)building symbol histograms */
	c2c_ext.symbol_total_cycles_valid = false;
	c2c_ext.symbol_total_cycles = 0;

	next = rb_first_cached(&c2c.hists.hists.entries);

	/* Clean up previous symbol hists entries before initializing */
	hists__delete_entries(&c2c_ext.symbol_hists.hists);

	/* Initialize symbol hists with sort by iaddr (code address) and symbol_view */
	ret = c2c_symbol_hists__init(&c2c_ext.symbol_hists, "iaddr_symbol,symbol_view", 2, NULL);
	if (ret)
		return ret;

	/* Setup output fields for symbol view - sorted by cycles percentage (descending) */
	ret = c2c_symbol_hists__reinit(&c2c_ext.symbol_hists,
		"cycles_percent,total_stores,iaddr_symbol,symbol_view,cacheline_symbol",
		"cycles_percent", NULL);
	if (ret)
		return ret;

	/* Get first thread for consistent aggregation */
	if (next) {
		struct hist_entry *first_he = rb_entry(next, struct hist_entry, rb_node);

		synthetic_thread = first_he->thread;
	}

	/* Build cacheline index (will only build once due to internal flag) */
	build_cacheline_symbol_index();

	if (c2c_ext.cacheline_index_size == 0) {
		ui__error("Cacheline index is empty, cannot build symbol hists\n");
		return -1;
	}

	/* Directly create histogram entries from cached symbol_access data */
	for (i = 0; i < c2c_ext.cacheline_index_size; i++) {
		struct cacheline_symbol_entry *cl_entry = &c2c_ext.cacheline_index[i];
		struct symbol_access *sa = cl_entry->symbol_accesses;

		/* Process all symbol accesses for this cacheline */
		while (sa) {
			if (sa->sym) {
				/* Create mem_info with proper instruction address for display */
				struct mem_info *mi_display = mem_info__new();

				if (mi_display) {
					mem_info__iaddr(mi_display)->addr = sa->iaddr;
					mem_info__iaddr(mi_display)->ms.maps = sa->maps;
					mem_info__iaddr(mi_display)->ms.map = sa->map;
					mem_info__iaddr(mi_display)->ms.sym = sa->sym;
					/* Set data address to 0 for consistent display */
					mem_info__daddr(mi_display)->addr = 0;
				}

				/* Create consistent address location for symbol aggregation */
				addr_location__init(&al);
				al.thread = thread__get(synthetic_thread);
				al.maps = maps__get(sa->maps);
				al.map = map__get(sa->map);
				al.sym = sa->sym;
				al.addr = sa->iaddr;
				al.level = PERF_RECORD_MISC_KERNEL;
				al.cpumode = PERF_RECORD_MISC_KERNEL;
				al.cpu = 0;
				al.socket = 0;
				al.filtered = 0;

				/* Create sample with consistent values */
				sample.period = 1;
				sample.weight = 1;
				sample.ip = sa->iaddr;
				sample.pid = synthetic_thread ? thread__pid(synthetic_thread) : 0;
				sample.tid = synthetic_thread ? thread__tid(synthetic_thread) : 0;
				sample.cpu = 0;
				sample.time = 0;
				sample.addr = 0;
				sample.id = 0;

				/* Add entry to histogram with mem_info for proper address display */
				he_sym = hists__add_entry_ops(&c2c_ext.symbol_hists.hists,
							      &c2c_symbol_entry_ops,
							      &al, NULL, NULL, mi_display,
							      NULL, &sample, true);

				addr_location__exit(&al);
				if (mi_display)
					mem_info__put(mi_display);

				if (he_sym) {
					c2c_he_sym = container_of(he_sym, struct c2c_hist_entry_ext, c2c_he.he);

					/* Accumulate stats from cached symbol_access across cachelines */
					c2c_add_stats(&c2c_he_sym->c2c_he.stats, &sa->stats);
					c2c_add_cstats(&c2c_he_sym->c2c_he.cstats, &sa->cstats);
					c2c_add_stats(&c2c_ext.symbol_hists.stats, &sa->stats);

					hists__inc_nr_samples(&c2c_ext.symbol_hists.hists, he_sym->filtered);
					he_sym->hpp_list = &c2c_ext.symbol_hists.list;
				}
			}
			sa = sa->next;
		}
	}

	/* Resort symbol hists */
	hists__collapse_resort(&c2c_ext.symbol_hists.hists, NULL);
	hists__output_resort(&c2c_ext.symbol_hists.hists, NULL);

	/* Enable hierarchy support for symbol view to allow multi-level display */
	c2c_ext.symbol_hists.hists.symbol_filter_str = NULL;
	c2c_ext.symbol_hists.hists.socket_filter = -1;

	/* Initialize the hist browser fields needed for hierarchy */
	c2c_ext.symbol_hists.hists.nr_hpp_node = 0;

	/* Build symbol associations after hists are complete */
	build_symbol_associations();

	/* Precompute and cache total cycles to speed up percent rendering */
	(void)get_total_cycles_all_symbols();

	return 0;
}

/**
 * c2c_symbol_browser__title - Generate title for symbol browser
 */
static int c2c_symbol_browser__title(struct hist_browser *browser,
			      char *bf, size_t size)
{
	scnprintf(bf, size,
		  "Shared Data Symbols Table     "
		  "(%lu entries, sorted on Cycles Percent)",
		  browser->nr_non_filtered_entries);
	return 0;
}

/**
 * c2c_symbol_browser__new - Create new symbol browser instance
 */
static struct c2c_symbol_browser *c2c_symbol_browser__new(struct hists *hists)
{
	struct c2c_symbol_browser *browser;

	if (!hists)
		return NULL;

	browser = zalloc(sizeof(*browser));
	if (!browser)
		return NULL;

	/* Store references */
	browser->hists = hists;

	/* Initialize base histogram browser */
	hist_browser__init(&browser->hb, hists);

	/* Configure browser for symbol view */
	browser->hb.title = c2c_symbol_browser__title;
	browser->hb.c2c_filter = true;
	browser->hb.show_headers = true;
	browser->hb.min_pcnt = 0.0;

	return browser;
}

/**
 * c2c_symbol_browser__delete - Free symbol browser
 */
static void c2c_symbol_browser__delete(struct c2c_symbol_browser *browser)
{
	if (browser) {
		/* Base browser cleanup is handled by hist_browser__delete */
		free(browser);
	}
}

/**
 * c2c_symbol_browser__handle_expand - Handle expand/collapse operation
 */
static int c2c_symbol_browser__handle_expand(struct c2c_symbol_browser *browser)
{
	struct hist_entry *he = browser->hb.he_selection;

	if (!he || !he->has_children)
		return 0;

	/* Create child entries if not already done */
	if (RB_EMPTY_ROOT(&he->hroot_out.rb_root)) {
		/* Ensure index is built for interactive use */
		build_cacheline_symbol_index();
		populate_symbol_children(he);
	}

	/* Toggle the folded state only if children were actually created */
	if (he->has_children)
		he->unfolded = !he->unfolded;

	/* Update the browser to reflect hierarchy changes */
	ui_browser__update_nr_entries(&browser->hb.b, browser->hb.hists->nr_entries);
	browser->hb.b.seek(&browser->hb.b, SEEK_SET, 0);

	return 0;
}

/**
 * c2c_symbol_browser__browse_cacheline_detail - Handle cacheline detail view
 */
static int c2c_symbol_browser__browse_cacheline_detail(struct c2c_symbol_browser *browser,
					       struct hist_entry *he_selection,
					       struct hists *hists)
{
	struct rb_node *nd;
	u64 cl_addr = 0;

	(void)browser; /* Suppress unused parameter warning */

	if (!he_selection || !he_selection->parent_he || !he_selection->parent_he->parent_he)
		return -1;

	/* Get the cacheline address from the grandchild */
	if (he_selection->mem_info && mem_info__daddr(he_selection->mem_info))
		cl_addr = cl_address(mem_info__daddr(he_selection->mem_info)->addr, chk_double_cl);
	else
		return -1;

	/* Find the cacheline entry in the main hists */
	nd = rb_first_cached(&hists->entries);
	while (nd) {
		struct hist_entry *he_cl = rb_entry(nd, struct hist_entry, rb_node);

		if (he_cl->mem_info && mem_info__daddr(he_cl->mem_info)) {
			u64 this_cl = cl_address(mem_info__daddr(he_cl->mem_info)->addr, chk_double_cl);

			if (this_cl == cl_addr) {
				/* Found the cacheline, call the browse function */
				return perf_c2c__browse_cacheline(he_cl);
			}
		}
		nd = rb_next(nd);
	}

	return -1; /* Cacheline not found */
}

/**
 * perf_c2c__browse_symbol_view - Browse symbol view with TAB key support
 * @hists: Main cacheline histograms
 *
 * Returns: 0 on success, negative error code on failure
 */
int perf_c2c__browse_symbol_view(struct hists *hists)
{
	struct c2c_symbol_browser *sym_browser = NULL;
	int key = -1;
	int ret;
	static const char help[] =
	" d             Display details (cacheline details for selected item)\n"
	" e/+             Expand/collapse related symbols\n"
	" q             Quit\n";

	/* Build symbol hists */
	ret = build_symbol_hists();
	if (ret) {
		ui__error("Failed to build symbol view (ret=%d)\n", ret);
		return ret;
	}

	/* Create symbol browser */
	sym_browser = c2c_symbol_browser__new(&c2c_ext.symbol_hists.hists);
	if (sym_browser == NULL)
		return -1;

	/* reset abort key so that it can get Ctrl-C as a key */
	SLang_reset_tty();
	SLang_init_tty(0, 0, 0);

	ui_browser__update_nr_entries(&sym_browser->hb.b, sym_browser->hb.nr_non_filtered_entries);

	while (1) {
		key = hist_browser__run(&sym_browser->hb, "? - help", true, 0);

		switch (key) {
		case 'q':
			goto out;
		case 'd':
			c2c_symbol_browser__browse_cacheline_detail(sym_browser, sym_browser->hb.he_selection, hists);
			break;
		case 'e':
		case '+':
			c2c_symbol_browser__handle_expand(sym_browser);
			break;
		case '?':
			ui_browser__help_window(&sym_browser->hb.b, help);
			break;
		default:
			break;
		}
	}

out:
	c2c_symbol_browser__delete(sym_browser);
	return 0;
}

/**
 * free_child_entries - Free child entries of a histogram entry
 * @parent_he: Parent histogram entry whose children to free
 *
 * Recursively frees all child entries and their associated resources
 * including related symbols, histograms, and memory info.
 */
static void free_child_entries(struct hist_entry *parent_he)
{
	struct rb_node *nd;
	struct hist_entry *child_he;
	struct c2c_hist_entry_ext *child_c2c_he;

	if (RB_EMPTY_ROOT(&parent_he->hroot_out.rb_root))
		return;

	nd = rb_first_cached(&parent_he->hroot_out);
	while (nd) {
		struct rb_node *next = rb_next(nd);

		child_he = rb_entry(nd, struct hist_entry, rb_node);
		child_c2c_he = container_of(child_he, struct c2c_hist_entry_ext, c2c_he.he);

		if (child_he->stat_acc)
			zfree(&child_he->stat_acc);

		if (child_he->mem_info)
			mem_info__put(child_he->mem_info);

		/* Free child's hists */
		if (child_c2c_he->c2c_he.hists) {
			hists__delete_entries(&child_c2c_he->c2c_he.hists->hists);
			zfree(&child_c2c_he->c2c_he.hists);
		}

		/* Free related symbols list */
		{
			struct related_symbol *rel_sym, *tmp;
			list_for_each_entry_safe(rel_sym, tmp, &child_c2c_he->related_symbols, list) {
				list_del(&rel_sym->list);
				free(rel_sym);
			}
		}

		zfree(&child_c2c_he->c2c_he.cpuset);
		zfree(&child_c2c_he->c2c_he.nodeset);
		zfree(&child_c2c_he->c2c_he.nodestr);
		zfree(&child_c2c_he->c2c_he.node_stats);

		/* Recursively free grandchildren in child_he->hroot_out */
		free_child_entries(child_he);

		rb_erase_cached(&child_he->rb_node, &parent_he->hroot_out);
		free(child_c2c_he);

		nd = next;
	}
}

/**
 * c2c_width - Calculate width for a C2C column in symbol view
 * @fmt: HPP format
 * @hpp: HPP context
 * @hists: Histogram context
 *
 * Returns: Column width based on dimension configuration
 */
static int c2c_width(struct perf_hpp_fmt *fmt,
	      		struct perf_hpp *hpp __maybe_unused,
	      		struct hists *hists __maybe_unused)
{
	struct c2c_fmt *c2c_fmt;
	struct c2c_dimension *dim;

	c2c_fmt = container_of(fmt, struct c2c_fmt, fmt);
	dim = c2c_fmt->dim;

	return dim->width;
}

/**
 * fmt_free - Free a format wrapper
 * @fmt: Format to free
 */
static void fmt_free(struct perf_hpp_fmt *fmt)
{
	struct c2c_fmt *c2c_fmt;

	c2c_fmt = container_of(fmt, struct c2c_fmt, fmt);
	free(c2c_fmt);
}

/**
 * fmt_equal - Check if two formats are equal
 * @a: First format
 * @b: Second format
 *
 * Returns: true if formats refer to the same dimension
 */
static bool fmt_equal(struct perf_hpp_fmt *a, struct perf_hpp_fmt *b)
{
	struct c2c_fmt *c2c_a = container_of(a, struct c2c_fmt, fmt);
	struct c2c_fmt *c2c_b = container_of(b, struct c2c_fmt, fmt);

	return c2c_a->dim == c2c_b->dim;
}

/**
 * c2c_header - Render column header for C2C dimensions
 * @fmt: Format wrapper
 * @hpp: HPP buffer
 * @hists: Histogram context
 * @line: Header line number
 * @span: Output span value
 *
 * Returns: Number of characters written
 */
static int c2c_header(struct perf_hpp_fmt *fmt, struct perf_hpp *hpp,
		      struct hists *hists, int line, int *span)
{
	struct perf_hpp_list *hpp_list = hists->hpp_list;
	struct c2c_fmt *c2c_fmt;
	struct c2c_dimension *dim;
	const char *text = NULL;
	int width = c2c_width(fmt, hpp, hists);

	c2c_fmt = container_of(fmt, struct c2c_fmt, fmt);
	dim = c2c_fmt->dim;

	if (dim->header.line[line].text)
		text = dim->header.line[line].text;

	if (span) {
		if (dim->header.line[line].span)
			*span = dim->header.line[line].span;
		else
			*span = width;
	}

	if (text == NULL)
		text = "";

	/* Support centered header display */
	if (hpp_list && hpp_list->nr_header_lines > 0 &&
	    line >= hpp_list->nr_header_lines)
		return 0;

	return scnprintf(hpp->buf, hpp->size, "%*s", width, text);
}

/*
 * Symbol view dimensions
 */
struct c2c_dimension dim_cycles_percent = {
	.header		= HEADER_BOTH("Cycles", "Percent"),
	.name		= "cycles_percent",
	.cmp		= cycles_percent_cmp,
	.entry		= cycles_percent_entry,
	.width		= 8,
};

struct c2c_dimension dim_total_stores = {
	.header		= HEADER_BOTH("Total", "Stores"),
	.name		= "total_stores",
	.cmp		= total_stores_cmp,
	.entry		= total_stores_entry,
	.width		= 8,
};

struct c2c_dimension dim_cacheline_symbol = {
	.header		= HEADER_LOW("Cacheline"),
	.name		= "cacheline_symbol",
	.cmp		= empty_cmp,
	.entry		= cacheline_symbol_entry,
	.width		= 16,
};

struct c2c_dimension dim_iaddr_symbol = {
	.header		= HEADER_LOW("Code address"),
	.name		= "iaddr_symbol",
	.cmp		= iaddr_symbol_cmp,
	.entry		= iaddr_symbol_entry,
	.width		= 18,
};

struct c2c_dimension dim_symbol_view = {
	.name		= "symbol_view",
	.entry		= symbol_view_entry,
	.width		= SYMBOL_WIDTH,
};

/*
 * Symbol view dimensions - dimensions used specifically in the symbol view browser
 */
static struct c2c_dimension *symbol_view_dimensions[] = {
	&dim_iaddr_symbol,
	&dim_cycles_percent,
	&dim_total_stores,
	&dim_cacheline_symbol,
	&dim_symbol_view,
	NULL,
};

/**
 * get_symbol_dimension - Find a dimension by name in symbol view dimensions
 * @name: Name of the dimension to find
 *
 * Returns: Pointer to the dimension if found, NULL otherwise
 */
static struct c2c_dimension *get_symbol_dimension(const char *name)
{
	unsigned int i;

	for (i = 0; symbol_view_dimensions[i]; i++) {
		struct c2c_dimension *dim = symbol_view_dimensions[i];

		if (!strcmp(dim->name, name))
			return dim;
	}

	return NULL;
}

/**
 * get_symbol_format - Create a format wrapper for a symbol view dimension
 * @name: Name of the dimension
 *
 * Returns: Pointer to the format if found/created, NULL on error
 */
static struct c2c_fmt *get_symbol_format(const char *name)
{
	struct c2c_dimension *dim = get_symbol_dimension(name);
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

/**
 * c2c_symbol_hists__init_output - Initialize output field for symbol view
 * @hpp_list: HPP list to add field to
 * @name: Name of the field
 * @env: Perf environment (unused)
 *
 * Returns: 0 on success, negative error code on failure
 */
static int c2c_symbol_hists__init_output(struct perf_hpp_list *hpp_list, char *name,
					struct perf_env *env __maybe_unused)
{
	struct c2c_fmt *c2c_fmt = get_symbol_format(name);
	int level = 0;

	if (!c2c_fmt) {
		reset_dimensions();
		return output_field_add(hpp_list, name, &level);
	}

	perf_hpp_list__column_register(hpp_list, &c2c_fmt->fmt);
	return 0;
}

/**
 * c2c_symbol_hists__init_sort - Initialize sort field for symbol view
 * @hpp_list: HPP list to add sort field to
 * @name: Name of the sort field
 * @env: Perf environment
 *
 * Returns: 0 on success, negative error code on failure
 */
static int c2c_symbol_hists__init_sort(struct perf_hpp_list *hpp_list, char *name,
				      struct perf_env *env)
{
	struct c2c_fmt *c2c_fmt = get_symbol_format(name);

	if (!c2c_fmt) {
		reset_dimensions();
		return sort_dimension__add(hpp_list, name, /*evlist=*/NULL, env, /*level=*/0);
	}

	/* Note: symbol view doesn't have dim_dso, so we don't need to check for it */

	perf_hpp_list__register_sort_field(hpp_list, &c2c_fmt->fmt);
	return 0;
}

/**
 * symbol_hpp_list__parse - Parse output and sort strings for symbol view
 * @hpp_list: HPP list to configure
 * @output: Output fields string
 * @sort: Sort fields string
 * @env: Perf environment
 *
 * Returns: 0 on success, negative error code on failure
 */
static int symbol_hpp_list__parse(struct perf_hpp_list *hpp_list,
				  const char *output_,
				  const char *sort_,
				  struct perf_env *env)
{
	char *output = output_ ? strdup(output_) : NULL;
	char *sort   = sort_   ? strdup(sort_) : NULL;
	int ret;

#define PARSE_LIST(_list, _fn)							\
	do {									\
		char *tmp, *tok;						\
		ret = 0;							\
										\
		if (!_list)							\
			break;							\
										\
		tmp = strdup(_list);						\
		if (!tmp) {							\
			ret = -ENOMEM;						\
			break;							\
		}								\
										\
		for (tok = strtok(tmp, ","); tok; tok = strtok(NULL, ",")) {	\
			ret = _fn(hpp_list, tok, env);				\
			if (ret)						\
				break;						\
		}								\
										\
		free(tmp);							\
	} while (0)

	PARSE_LIST(output, c2c_symbol_hists__init_output);
	PARSE_LIST(sort,   c2c_symbol_hists__init_sort);

	/* copy sort keys to output fields */
	perf_hpp__setup_output_field(hpp_list);

	/*
	 * We don't need other sorting keys other than those
	 * we already specified. It also really slows down
	 * the processing a lot with big number of output
	 * fields, so switching this off for c2c.
	 */

#if 0
	/* and then copy output fields to sort keys */
	perf_hpp__append_sort_keys(&hists->list);
#endif

	free(output);
	free(sort);
	return ret;
}

/**
 * c2c_symbol_hists__init - Initialize symbol view histograms
 * @hists: C2C hists to initialize
 * @sort: Sort string
 * @nr_header_lines: Number of header lines
 * @env: Perf environment
 *
 * Returns: 0 on success, negative error code on failure
 */
static int c2c_symbol_hists__init(struct c2c_hists *hists,
				 const char *sort,
				 int nr_header_lines,
				 struct perf_env *env)
{
	__hists__init(&hists->hists, &hists->list);

	/*
	 * Initialize only with sort fields, we need to resort
	 * later anyway, and that's where we add output fields
	 * as well.
	 */
	perf_hpp_list__init(&hists->list);

	/* Overload number of header lines.*/
	hists->list.nr_header_lines = nr_header_lines;

	return symbol_hpp_list__parse(&hists->list, /*output=*/NULL, sort, env);
}

/**
 * c2c_symbol_hists__reinit - Reinitialize symbol view histograms with new output/sort
 * @c2c_hists: C2C hists to reinitialize
 * @output: Output columns string
 * @sort: Sort string
 * @env: Perf environment
 *
 * Returns: 0 on success, negative error code on failure
 */
static int c2c_symbol_hists__reinit(struct c2c_hists *c2c_hists,
				   const char *output,
				   const char *sort,
				   struct perf_env *env)
{
	perf_hpp__reset_output_field(&c2c_hists->list);
	return symbol_hpp_list__parse(&c2c_hists->list, output, sort, env);
}

