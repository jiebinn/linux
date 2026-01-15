// SPDX-License-Identifier: GPL-2.0
/**
 * C2C Symbol Browser - Symbol-level cacheline sharing analysis
 *
 * Displays a 4-level hierarchy showing which symbols share cachelines:
 *   Level 1: Symbols sorted by cycles percentage
 *   Level 2: Other symbols sharing cachelines with level 1 symbols
 *   Level 3: Specific shared cachelines between symbol pairs
 *   Level 4: Cacheline detail view
 *
 * Uses _symbol_accessed_cachelines linked list to avoid data duplication.
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


/** Extended C2C context for symbol view (internal to this file) */
struct perf_c2c_ext {
	struct c2c_hists	symbol_hists;		/* Symbol-grouped histograms */
	uint64_t		symbol_total_cycles;	/* Cached total cycles (0 = uncalculated) */
};

/* Static instance - only accessible within this file */
static struct perf_c2c_ext c2c_ext;

/** Symbol browser for C2C analysis */
struct c2c_symbol_browser {
	struct hist_browser	hb;	/* Base histogram browser */
	struct hists		*hists;	/* Symbol histograms to display */
};

/**
 * symbol_name_equal - Compare two symbols by name
 * @a: First symbol
 * @b: Second symbol
 *
 * Returns: true if both symbols are non-NULL and have the same name
 */
static inline bool symbol_name_equal(struct symbol *a, struct symbol *b)
{
	return a && b && strcmp(a->name, b->name) == 0;
}

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
static void step3_insert_child_into_tree(struct rb_root_cached *tree,
					 struct hist_entry *child_he);

/**
 * c2c_he_ext_zalloc - Allocate histogram entry for symbol view
 * @size: Size needed for hist_entry including dynamic callchain data
 *
 * Returns: Pointer to hist_entry within allocated c2c_hist_entry, or NULL on failure
 */
static void *c2c_he_ext_zalloc(size_t size)
{
	struct c2c_hist_entry *c2c_he;

	/* Allocate structure plus space for hist_entry dynamic data
	 * size contains the space needed for hist_entry's dynamic part (callchain)
	 * sizeof(*c2c_he) already includes the static hist_entry size
	 */
	c2c_he = zalloc(size + sizeof(*c2c_he));
	if (!c2c_he)
		return NULL;

	c2c_he->cpuset = bitmap_zalloc(c2c.cpus_cnt);
	if (!c2c_he->cpuset)
		goto out_free;

	c2c_he->nodeset = bitmap_zalloc(c2c.nodes_cnt);
	if (!c2c_he->nodeset)
		goto out_free;

	c2c_he->node_stats = zalloc(c2c.nodes_cnt * sizeof(*c2c_he->node_stats));
	if (!c2c_he->node_stats)
		goto out_free;

	init_stats(&c2c_he->cstats.lcl_hitm);
	init_stats(&c2c_he->cstats.rmt_hitm);
	init_stats(&c2c_he->cstats.lcl_peer);
	init_stats(&c2c_he->cstats.rmt_peer);
	init_stats(&c2c_he->cstats.load);

	return &c2c_he->he;

out_free:
	zfree(&c2c_he->nodeset);
	zfree(&c2c_he->cpuset);
	free(c2c_he);
	return NULL;
}

/**
 * c2c_he_ext_free - Free histogram entry for symbol view
 * @he: Pointer to hist_entry to free
 */
static void c2c_he_ext_free(void *he)
{
	struct c2c_hist_entry *c2c_he;

	c2c_he = container_of(he, struct c2c_hist_entry, he);

	/* Free base c2c_hist_entry */
	if (c2c_he->hists) {
		hists__delete_entries(&c2c_he->hists->hists);
		zfree(&c2c_he->hists);
	}

	/* Free child entries first */
	free_child_entries((struct hist_entry *)he);

	/* Free all fields */
	zfree(&c2c_he->nodeset);
	zfree(&c2c_he->cpuset);
	zfree(&c2c_he->nodestr);
	zfree(&c2c_he->node_stats);


	/* Free the structure */
	free(c2c_he);
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
	struct c2c_hist_entry *c2c_he = container_of(he, struct c2c_hist_entry, he);
	uint64_t total = (uint64_t)c2c_he->stats.store;
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
 * calculate_symbol_cycles - Calculate total cycles for a symbol
 */
static uint64_t calculate_symbol_cycles(struct c2c_hist_entry *c2c_he)
{
	uint64_t cycles_rmt, cycles_lcl, cycles_load, other_load, total_hitm;

	cycles_rmt = avg_stats(&c2c_he->cstats.rmt_hitm) * c2c_he->stats.rmt_hitm;
	cycles_lcl = avg_stats(&c2c_he->cstats.lcl_hitm) * c2c_he->stats.lcl_hitm;
	total_hitm = (uint64_t)c2c_he->stats.rmt_hitm + c2c_he->stats.lcl_hitm;
	other_load = (c2c_he->stats.load >= total_hitm) ? c2c_he->stats.load - total_hitm : 0;
	cycles_load = avg_stats(&c2c_he->cstats.load) * other_load;

	return cycles_rmt + cycles_lcl + cycles_load;
}

/**
 * cycles_percent_entry - Render cycles percentage column
 */
static int
cycles_percent_entry(struct perf_hpp_fmt *fmt, struct perf_hpp *hpp,
		     struct hist_entry *he)
{
	struct c2c_hist_entry *c2c_he;
	int width = c2c_width(fmt, hpp, he->hists);
	uint64_t symbol_cycles;
	uint64_t total_cycles;
	double pct;

	/* Hide Cycles Percent for child symbols and cachelines */
	if (he->parent_he)
		return scnprintf(hpp->buf, hpp->size, "%*s", width, "");

	c2c_he = container_of(he, struct c2c_hist_entry, he);
	symbol_cycles = calculate_symbol_cycles(c2c_he);

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
	struct c2c_hist_entry *c2c_left = container_of(left, struct c2c_hist_entry, he);
	struct c2c_hist_entry *c2c_right = container_of(right, struct c2c_hist_entry, he);
	uint64_t cycles_left, cycles_right;

	cycles_left = calculate_symbol_cycles(c2c_left);
	cycles_right = calculate_symbol_cycles(c2c_right);

	return cycles_left - cycles_right;
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
	struct c2c_hist_entry *c2c_left = container_of(left, struct c2c_hist_entry, he);
	struct c2c_hist_entry *c2c_right = container_of(right, struct c2c_hist_entry, he);

	return (uint64_t)c2c_left->stats.store -
	       (uint64_t)c2c_right->stats.store;
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
 * step4_check_child_accesses_cacheline - Check if child accesses a cacheline
 *
 * Returns aggregated stats if child accesses the cacheline, NULL otherwise.
 */
static bool step4_aggregate_child_cacheline_stats(struct c2c_hist_entry *cacheline_he,
						   uint64_t child_iaddr,
						   struct symbol *child_sym,
						   struct c2c_stats *out_stats,
						   struct compute_stats *out_cstats)
{
	struct rb_node *nd;
	bool found = false;

	memset(out_stats, 0, sizeof(*out_stats));
	memset(out_cstats, 0, sizeof(*out_cstats));

	if (!cacheline_he->hists || !cacheline_he->hists->hists.entries.rb_root.rb_node)
		return false;

	nd = rb_first_cached(&cacheline_he->hists->hists.entries);
	while (nd) {
		struct hist_entry *he_detail = rb_entry(nd, struct hist_entry, rb_node);
		struct c2c_hist_entry *c2c_detail;
		uint64_t detail_iaddr;

		if (!he_detail->ms.sym || he_detail->filtered) {
			nd = rb_next(nd);
			continue;
		}

		detail_iaddr = he_detail->mem_info ?
			mem_info__iaddr(he_detail->mem_info)->addr :
			he_detail->ms.sym->start;

		if (detail_iaddr == child_iaddr && symbol_name_equal(child_sym, he_detail->ms.sym)) {
			/* Aggregate stats from all matching entries */
			found = true;
			c2c_detail = container_of(he_detail, struct c2c_hist_entry, he);
			c2c_add_stats(out_stats, &c2c_detail->stats);
			c2c_add_cstats(out_cstats, &c2c_detail->cstats);
		}

		nd = rb_next(nd);
	}

	return found;
}

/**
 * step4_create_cacheline_grandchild - Create a grandchild entry for a shared cacheline
 *
 * Creates a grandchild entry representing a specific cacheline that is shared
 * between the parent symbol and the child symbol.
 */
static struct hist_entry *
step4_create_cacheline_grandchild(struct hist_entry *child_he,
				  struct c2c_hist_entry *cacheline_he,
				  struct c2c_stats *stats,
				  struct compute_stats *cstats,
				  struct c2c_hist_entry **out_c2c_he)
{
	struct c2c_hist_entry *grand_c2c;
	struct hist_entry *grand_he;

	grand_c2c = zalloc(sizeof(*grand_c2c));
	if (!grand_c2c)
		return NULL;

	grand_he = &grand_c2c->he;

	/* Copy base info from cacheline entry */
	memcpy(&grand_he->ms, &cacheline_he->he.ms, sizeof(struct map_symbol));

	/* Clone mem_info from cacheline to get the data address */
	if (cacheline_he->he.mem_info) {
		grand_he->mem_info = mem_info__clone(cacheline_he->he.mem_info);
	}

	/* Copy basic attributes from cacheline */
	grand_he->thread = cacheline_he->he.thread;
	grand_he->cpumode = cacheline_he->he.cpumode;
	grand_he->cpu = cacheline_he->he.cpu;
	grand_he->socket = cacheline_he->he.socket;

	/* Set hierarchy info */
	grand_he->parent_he = child_he;
	grand_he->depth = child_he->depth + 1;
	grand_he->leaf = true; /* Cachelines are leaf nodes */
	grand_he->hists = &c2c_ext.symbol_hists.hists;
	grand_he->filtered = false;
	grand_he->unfolded = false;
	grand_he->has_children = false;
	grand_he->has_no_entry = false;
	grand_he->nr_rows = 0;
	grand_he->row_offset = 0;

	/* Set statistics */
	memset(&grand_he->stat, 0, sizeof(grand_he->stat));
	grand_he->stat.nr_events = HITM_COUNT(stats) + stats->rmt_peer + stats->lcl_peer;
	grand_he->stat.period = grand_he->stat.nr_events;
	grand_he->stat.weight1 = HITM_COUNT(stats);

	/* Allocate stat_acc if needed */
	if (symbol_conf.cumulate_callchain) {
		grand_he->stat_acc = calloc(1, sizeof(struct he_stat));
		if (grand_he->stat_acc)
			memcpy(grand_he->stat_acc, &grand_he->stat, sizeof(struct he_stat));
	}

	/* Initialize rb-tree and list structures */
	grand_he->hroot_in = RB_ROOT_CACHED;
	grand_he->hroot_out = RB_ROOT_CACHED;
	INIT_LIST_HEAD(&grand_he->pairs.node);
	grand_he->hpp_list = &c2c_ext.symbol_hists.list;

	/* Copy C2C stats and compute stats */
	memcpy(&grand_c2c->stats, stats, sizeof(grand_c2c->stats));
	memcpy(&grand_c2c->cstats, cstats, sizeof(grand_c2c->cstats));

	*out_c2c_he = grand_c2c;
	return grand_he;
}

/**
 * step4_insert_grandchild_sorted - Insert grandchild into child's tree sorted by stores
 */
static void step4_insert_grandchild_sorted(struct rb_root_cached *tree,
					   struct hist_entry *grand_he)
{
	struct rb_node **p = &tree->rb_root.rb_node;
	struct rb_node *parent = NULL;
	struct c2c_hist_entry *grand_c2c = container_of(grand_he, struct c2c_hist_entry, he);
	bool leftmost = true;

	while (*p != NULL) {
		struct hist_entry *entry = rb_entry(*p, struct hist_entry, rb_node);
		struct c2c_hist_entry *entry_c2c = container_of(entry, struct c2c_hist_entry, he);

		parent = *p;
		if (grand_c2c->stats.store > entry_c2c->stats.store) {
			p = &parent->rb_left;
		} else {
			p = &parent->rb_right;
			leftmost = false;
		}
	}

	rb_link_node(&grand_he->rb_node, parent, p);
	rb_insert_color_cached(&grand_he->rb_node, tree, leftmost);
}

/**
 * step3_create_child_entry_from_detail - Create a child entry directly from cacheline detail
 *
 * Creates a child entry for a symbol found in cacheline detail entries,
 * even if that symbol is not in the top-level symbol list.
 */
static struct hist_entry *
step3_create_child_entry_from_detail(struct hist_entry *parent_he,
				     struct hist_entry *detail_he,
				     struct c2c_stats *stats,
				     struct compute_stats *cstats,
				     struct c2c_hist_entry **out_c2c_he)
{
	struct c2c_hist_entry *child_c2c_he;
	struct hist_entry *child_he;
	uint64_t child_iaddr;

	child_iaddr = detail_he->mem_info ?
		mem_info__iaddr(detail_he->mem_info)->addr :
		(detail_he->ms.sym ? detail_he->ms.sym->start : 0);

	child_c2c_he = zalloc(sizeof(*child_c2c_he));
	if (!child_c2c_he)
		return NULL;

	child_he = &child_c2c_he->he;

	/* Copy base info from detail entry */
	memcpy(&child_he->ms, &detail_he->ms, sizeof(struct map_symbol));

	/* Clone mem_info with child's instruction address */
	if (detail_he->mem_info) {
		child_he->mem_info = mem_info__clone(detail_he->mem_info);
		if (child_he->mem_info)
			mem_info__iaddr(child_he->mem_info)->addr = child_iaddr;
	}

	/* Copy basic attributes */
	child_he->thread = detail_he->thread;
	child_he->cpumode = detail_he->cpumode;
	child_he->cpu = detail_he->cpu;
	child_he->socket = detail_he->socket;

	/* Set hierarchy info */
	child_he->parent_he = parent_he;
	child_he->depth = parent_he->depth + 1;
	child_he->leaf = false; /* May have grandchildren (cachelines) */
	child_he->hists = &c2c_ext.symbol_hists.hists;
	child_he->filtered = false;
	child_he->unfolded = false;
	child_he->has_children = false; /* Will be set when grandchildren added */
	child_he->has_no_entry = false;
	child_he->nr_rows = 0;
	child_he->row_offset = 0;

	/* Set statistics from aggregated stats */
	memset(&child_he->stat, 0, sizeof(child_he->stat));
	child_he->stat.nr_events = HITM_COUNT(stats) + stats->rmt_peer + stats->lcl_peer;
	child_he->stat.period = child_he->stat.nr_events;
	child_he->stat.weight1 = HITM_COUNT(stats);

	/* Allocate stat_acc if needed */
	if (symbol_conf.cumulate_callchain) {
		child_he->stat_acc = calloc(1, sizeof(struct he_stat));
		if (child_he->stat_acc)
			memcpy(child_he->stat_acc, &child_he->stat, sizeof(struct he_stat));
	}

	/* Initialize rb-tree and list structures */
	child_he->hroot_in = RB_ROOT_CACHED;
	child_he->hroot_out = RB_ROOT_CACHED;
	INIT_LIST_HEAD(&child_he->pairs.node);
	child_he->hpp_list = &c2c_ext.symbol_hists.list;

	/* Copy C2C stats */
	memcpy(&child_c2c_he->stats, stats, sizeof(child_c2c_he->stats));
	memcpy(&child_c2c_he->cstats, cstats, sizeof(child_c2c_he->cstats));

	*out_c2c_he = child_c2c_he;
	return child_he;
}

/**
 * struct child_cacheline_ref - Tracks which cacheline a child accesses
 *
 * Used during step3 to remember which cachelines each child shares with parent,
 * so we can create grandchildren for each cacheline later.
 */
struct child_cacheline_ref {
	struct list_head list;
	struct c2c_hist_entry *cacheline;
	struct c2c_stats stats;
	struct compute_stats cstats;
};

/**
 * step3_build_children_from_cachelines - Build children directly from cacheline details
 *
 * For a parent symbol, find all other symbols that share its cachelines by
 * directly scanning the cacheline detail entries. This catches symbols that
 * may not be in the top-level symbol list.
 *
 * Also creates grandchildren for each cacheline that child shares with parent.
 */
static void step3_build_children_from_cachelines(struct hist_entry *parent_he)
{
	struct c2c_hist_entry *parent_c2c = container_of(parent_he, struct c2c_hist_entry, he);
	struct symbol_cacheline_ref *parent_ref;
	struct rb_root child_tree = RB_ROOT; /* Temp tree for deduplication */
	uint64_t parent_iaddr;
	int child_count = 0;

	parent_iaddr = parent_he->mem_info ?
		mem_info__iaddr(parent_he->mem_info)->addr :
		(parent_he->ms.sym ? parent_he->ms.sym->start : 0);

	/* For each cacheline the parent accesses */
	list_for_each_entry(parent_ref, &parent_c2c->_symbol_accessed_cachelines, list) {
		struct c2c_hist_entry *cacheline_he = parent_ref->cacheline;
		struct c2c_stats parent_cl_stats;
		struct compute_stats parent_cl_cstats;
		struct rb_node *nd;

		/* Check if parent has HITM on this cacheline */
		if (!step4_aggregate_child_cacheline_stats(cacheline_he, parent_iaddr,
							    parent_he->ms.sym, &parent_cl_stats,
							    &parent_cl_cstats))
			continue;

		if (HITM_COUNT(&parent_cl_stats) == 0)
			continue;

		/* Scan all symbols in this cacheline's detail entries */
		nd = rb_first_cached(&cacheline_he->hists->hists.entries);
		while (nd) {
			struct hist_entry *he_detail = rb_entry(nd, struct hist_entry, rb_node);
			struct c2c_hist_entry *c2c_detail;
			uint64_t detail_iaddr;
			struct rb_node **p, *parent_node;
			bool found_dup = false;

			if (!he_detail->ms.sym || he_detail->filtered) {
				nd = rb_next(nd);
				continue;
			}

			c2c_detail = container_of(he_detail, struct c2c_hist_entry, he);
			detail_iaddr = he_detail->mem_info ?
				mem_info__iaddr(he_detail->mem_info)->addr :
				he_detail->ms.sym->start;

			/* Skip self (same iaddr and symbol as parent) */
			if (detail_iaddr == parent_iaddr &&
			    symbol_name_equal(parent_he->ms.sym, he_detail->ms.sym)) {
				nd = rb_next(nd);
				continue;
			}

			/* Check for duplicate in our temp tree */
			p = &child_tree.rb_node;
			parent_node = NULL;
			while (*p) {
				struct hist_entry *entry = rb_entry(*p, struct hist_entry, rb_node);
				struct c2c_hist_entry *entry_c2c = container_of(entry, struct c2c_hist_entry, he);
				uint64_t entry_iaddr = entry->mem_info ?
					mem_info__iaddr(entry->mem_info)->addr :
					(entry->ms.sym ? entry->ms.sym->start : 0);

				parent_node = *p;
				if (detail_iaddr < entry_iaddr)
					p = &parent_node->rb_left;
				else if (detail_iaddr > entry_iaddr)
					p = &parent_node->rb_right;
				else if (he_detail->ms.sym < entry->ms.sym)
					p = &parent_node->rb_left;
				else if (he_detail->ms.sym > entry->ms.sym)
					p = &parent_node->rb_right;
				else {
					/* Already have this child, aggregate stats */
					struct child_cacheline_ref *cl_ref;
					bool cl_found = false;

					c2c_add_stats(&entry_c2c->stats, &c2c_detail->stats);
					c2c_add_cstats(&entry_c2c->cstats, &c2c_detail->cstats);
					entry->stat.nr_events += HITM_COUNT(&c2c_detail->stats) +
						c2c_detail->stats.rmt_peer + c2c_detail->stats.lcl_peer;

					/* Check if this cacheline is already in the list */
					list_for_each_entry(cl_ref, &entry_c2c->_symbol_accessed_cachelines, list) {
						if (cl_ref->cacheline == cacheline_he) {
							c2c_add_stats(&cl_ref->stats, &c2c_detail->stats);
							c2c_add_cstats(&cl_ref->cstats, &c2c_detail->cstats);
							cl_found = true;
							break;
						}
					}

					if (!cl_found) {
						/* Add new cacheline reference */
						cl_ref = zalloc(sizeof(*cl_ref));
						if (cl_ref) {
							cl_ref->cacheline = cacheline_he;
							memcpy(&cl_ref->stats, &c2c_detail->stats, sizeof(cl_ref->stats));
							memcpy(&cl_ref->cstats, &c2c_detail->cstats, sizeof(cl_ref->cstats));
							list_add_tail(&cl_ref->list, &entry_c2c->_symbol_accessed_cachelines);
						}
					}

					found_dup = true;
					break;
				}
			}

			if (!found_dup) {
				/* Create new child entry */
				struct c2c_hist_entry *child_c2c;
				struct hist_entry *child_he;
				struct child_cacheline_ref *cl_ref;

				child_he = step3_create_child_entry_from_detail(parent_he, he_detail,
										&c2c_detail->stats,
										&c2c_detail->cstats,
										&child_c2c);
				if (child_he) {
					/* Initialize cacheline list and add first ref */
					INIT_LIST_HEAD(&child_c2c->_symbol_accessed_cachelines);

					cl_ref = zalloc(sizeof(*cl_ref));
					if (cl_ref) {
						cl_ref->cacheline = cacheline_he;
						memcpy(&cl_ref->stats, &c2c_detail->stats, sizeof(cl_ref->stats));
						memcpy(&cl_ref->cstats, &c2c_detail->cstats, sizeof(cl_ref->cstats));
						list_add_tail(&cl_ref->list, &child_c2c->_symbol_accessed_cachelines);
					}

					rb_link_node(&child_he->rb_node, parent_node, p);
					rb_insert_color(&child_he->rb_node, &child_tree);
					child_count++;
				}
			}

			nd = rb_next(nd);
		}
	}

	/* Transfer children from temp tree to parent's hroot_out, sorted by stores
	 * Also create grandchildren for each cacheline the child shares with parent
	 */
	while (!RB_EMPTY_ROOT(&child_tree)) {
		struct rb_node *nd_child = rb_first(&child_tree);
		struct hist_entry *child_he = rb_entry(nd_child, struct hist_entry, rb_node);
		struct c2c_hist_entry *child_c2c = container_of(child_he, struct c2c_hist_entry, he);
		struct child_cacheline_ref *cl_ref, *cl_tmp;
		int grandchild_count = 0;

		rb_erase(nd_child, &child_tree);

		/* Create grandchildren for each cacheline */
		list_for_each_entry_safe(cl_ref, cl_tmp, &child_c2c->_symbol_accessed_cachelines, list) {
			struct c2c_hist_entry *grand_c2c;
			struct hist_entry *grand_he;

			grand_he = step4_create_cacheline_grandchild(child_he, cl_ref->cacheline,
								     &cl_ref->stats, &cl_ref->cstats,
								     &grand_c2c);
			if (grand_he) {
				step4_insert_grandchild_sorted(&child_he->hroot_out, grand_he);
				grandchild_count++;
			}

			/* Free the cacheline ref after use */
			list_del(&cl_ref->list);
			free(cl_ref);
		}

		if (grandchild_count > 0) {
			child_he->has_children = true;
			child_he->leaf = false;
			child_he->nr_rows = grandchild_count;
		}

		step3_insert_child_into_tree(&parent_he->hroot_out, child_he);
	}

	if (child_count > 0) {
		parent_he->has_children = true;
		parent_he->unfolded = false;
		parent_he->leaf = false;
		parent_he->nr_rows = child_count;
	}
}

/**
 * step3_insert_child_into_tree - Insert child into parent's rb-tree sorted by stores
 */
static void step3_insert_child_into_tree(struct rb_root_cached *tree,
					 struct hist_entry *child_he)
{
	struct rb_node **p = &tree->rb_root.rb_node;
	struct rb_node *parent = NULL;
	struct c2c_hist_entry *child_c2c = container_of(child_he, struct c2c_hist_entry, he);
	bool leftmost = true;

	/* Find insertion point maintaining descending sort order by stores */
	while (*p != NULL) {
		struct hist_entry *entry = rb_entry(*p, struct hist_entry, rb_node);
		struct c2c_hist_entry *entry_c2c = container_of(entry, struct c2c_hist_entry, he);

		parent = *p;
		if (child_c2c->stats.store > entry_c2c->stats.store) {
			p = &parent->rb_left;
		} else {
			p = &parent->rb_right;
			leftmost = false;
		}
	}

	rb_link_node(&child_he->rb_node, parent, p);
	rb_insert_color_cached(&child_he->rb_node, tree, leftmost);
}


/**
 * step3_build_parent_child_relationships - Build parent-child relationships
 *
 * For each parent symbol, find all other symbols that share cachelines with it
 * by directly scanning cacheline detail entries. This catches symbols that
 * may not be in the top-level symbol list.
 */
static void step3_build_parent_child_relationships(void)
{
	struct rb_node *nd_parent;

	/* For each parent symbol, find and create children directly from cacheline details */
	nd_parent = rb_first_cached(&c2c_ext.symbol_hists.hists.entries);
	while (nd_parent) {
		struct hist_entry *parent_he = rb_entry(nd_parent, struct hist_entry, rb_node);

		/* Skip if already populated */
		if (!RB_EMPTY_ROOT(&parent_he->hroot_out.rb_root)) {
			nd_parent = rb_next(nd_parent);
			continue;
		}

		/* Build children directly from cacheline details */
		step3_build_children_from_cachelines(parent_he);

		nd_parent = rb_next(nd_parent);
	}
}


/**
 * Temporary structure for symbol-level aggregation during hierarchy building
 * Used to deduplicate and aggregate stats by (iaddr, symbol) before creating hist entries
 */
struct symbol_agg_entry {
	struct rb_node rb_node;			/* Red-black tree node for fast lookup */
	uint64_t iaddr;				/* Instruction address */
	struct symbol *sym;			/* Symbol pointer */
	struct c2c_stats stats;			/* Aggregated C2C statistics */
	struct compute_stats cstats;		/* Aggregated compute statistics */
	struct list_head cacheline_refs;	/* List of cacheline references */
	struct maps *maps;			/* Maps reference (for creating hist entry) */
	struct map *map;			/* Map reference */
};

/**
 * find_or_create_symbol_agg - Find or create symbol aggregation entry
 *
 * Uses binary search in red-black tree for O(log N) lookup.
 * Returns: Pointer to symbol_agg_entry (existing or newly created)
 */
static struct symbol_agg_entry *
find_or_create_symbol_agg(struct rb_root *root, uint64_t iaddr,
				  struct symbol *sym, struct maps *maps,
				  struct map *map)
{
	struct rb_node **p = &root->rb_node;
	struct rb_node *parent = NULL;
	struct symbol_agg_entry *entry;

	/* Binary search */
	while (*p) {
		parent = *p;
		entry = rb_entry(parent, struct symbol_agg_entry, rb_node);

		if (iaddr < entry->iaddr)
			p = &parent->rb_left;
		else if (iaddr > entry->iaddr)
			p = &parent->rb_right;
		else if (sym < entry->sym)
			p = &parent->rb_left;
		else if (sym > entry->sym)
			p = &parent->rb_right;
		else
			return entry;  /* Found existing */
	}

	/* Create new entry */
	entry = zalloc(sizeof(*entry));
	if (!entry)
		return NULL;

	entry->iaddr = iaddr;
	entry->sym = sym;
	entry->maps = maps__get(maps);
	entry->map = map__get(map);
	INIT_LIST_HEAD(&entry->cacheline_refs);
	memset(&entry->stats, 0, sizeof(entry->stats));
	memset(&entry->cstats, 0, sizeof(entry->cstats));

	/* Insert into tree */
	rb_link_node(&entry->rb_node, parent, p);
	rb_insert_color(&entry->rb_node, root);

	return entry;
}

/**
 * free_symbol_agg_tree - Free all entries in symbol aggregation tree
 */
static void free_symbol_agg_tree(struct rb_root *root)
{
	struct rb_node *nd;
	struct symbol_agg_entry *entry;
	struct symbol_cacheline_ref *ref, *tmp;

	while ((nd = rb_first(root)) != NULL) {
		entry = rb_entry(nd, struct symbol_agg_entry, rb_node);
		rb_erase(nd, root);

		/* Free cacheline reference list */
		list_for_each_entry_safe(ref, tmp, &entry->cacheline_refs, list) {
			list_del(&ref->list);
			free(ref);
		}

		maps__put(entry->maps);
		map__put(entry->map);
		free(entry);
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
	if (c2c_ext.symbol_total_cycles > 0)
		return c2c_ext.symbol_total_cycles;

	nd = rb_first_cached(&c2c_ext.symbol_hists.hists.entries);
	while (nd) {
		struct hist_entry *he = rb_entry(nd, struct hist_entry, rb_node);
		struct c2c_hist_entry *c2c_he = container_of(he, struct c2c_hist_entry, he);
		uint64_t cycles_rmt, cycles_lcl, cycles_load, other_load, total_hitm, symbol_cycles;

		cycles_rmt = avg_stats(&c2c_he->cstats.rmt_hitm) * c2c_he->stats.rmt_hitm;
		cycles_lcl = avg_stats(&c2c_he->cstats.lcl_hitm) * c2c_he->stats.lcl_hitm;
		/* Prevent unsigned underflow by checking before subtraction */
		total_hitm = (uint64_t)c2c_he->stats.rmt_hitm + c2c_he->stats.lcl_hitm;
		other_load = (c2c_he->stats.load >= total_hitm) ? c2c_he->stats.load - total_hitm : 0;
		cycles_load = avg_stats(&c2c_he->cstats.load) * other_load;

		symbol_cycles = cycles_rmt + cycles_lcl + cycles_load;
		total_cycles += symbol_cycles;
		nd = rb_next(nd);
	}

	c2c_ext.symbol_total_cycles = total_cycles;
	return total_cycles;
}

/**
 * create_symbol_entry - Create new symbol histogram entry
 * @iaddr: Instruction address
 * @sym: Symbol pointer
 * @maps: Maps reference
 * @map: Map reference
 * @thread: Thread reference
 *
 * Creates and initializes a new histogram entry. Should only be called
 * after confirming the entry doesn't exist.
 * Returns: Pointer to c2c_hist_entry if successful, NULL on error
 */
static struct c2c_hist_entry *
create_symbol_entry(uint64_t iaddr, struct symbol *sym,
		    struct maps *maps, struct map *map,
		    struct thread *thread)
{
	struct addr_location al;
	struct perf_sample sample = {};
	struct mem_info *mi_display;
	struct hist_entry *he;
	struct c2c_hist_entry *c2c_he;

	/* Create mem_info for display */
	mi_display = mem_info__new();
	if (mi_display) {
		mem_info__iaddr(mi_display)->addr = iaddr;
		mem_info__iaddr(mi_display)->ms.maps = maps;
		mem_info__iaddr(mi_display)->ms.map = map;
		mem_info__iaddr(mi_display)->ms.sym = sym;
		mem_info__daddr(mi_display)->addr = 0;
	}

	/* Create address location */
	addr_location__init(&al);
	al.thread = thread__get(thread);
	al.maps = maps__get(maps);
	al.map = map__get(map);
	al.sym = sym;
	al.addr = iaddr;
	al.level = PERF_RECORD_MISC_KERNEL;
	al.cpumode = PERF_RECORD_MISC_KERNEL;
	al.cpu = 0;
	al.socket = 0;
	al.filtered = 0;

	/* Create sample */
	sample.period = 1;
	sample.weight = 1;
	sample.ip = iaddr;
	sample.pid = thread__pid(thread);
	sample.tid = thread__tid(thread);
	sample.cpu = 0;

	/* Add entry to histogram */
	he = hists__add_entry_ops(&c2c_ext.symbol_hists.hists,
				  &c2c_symbol_entry_ops,
				  &al, NULL, NULL, mi_display,
				  NULL, &sample, true);

	addr_location__exit(&al);
	if (mi_display)
		mem_info__put(mi_display);

	if (!he)
		return NULL;

	c2c_he = container_of(he, struct c2c_hist_entry, he);

	/* Initialize structures */
	INIT_LIST_HEAD(&c2c_he->_symbol_accessed_cachelines);
	memset(&c2c_he->stats, 0, sizeof(c2c_he->stats));
	memset(&c2c_he->cstats, 0, sizeof(c2c_he->cstats));

	hists__inc_nr_samples(&c2c_ext.symbol_hists.hists, he->filtered);
	he->hpp_list = &c2c_ext.symbol_hists.list;

	return c2c_he;
}

/**
 * add_cacheline_to_symbol_agg - Add cacheline reference to symbol aggregation entry
 */
static void add_cacheline_to_symbol_agg(struct symbol_agg_entry *agg_entry,
					struct c2c_hist_entry *cacheline_he)
{
	struct symbol_cacheline_ref *ref, *existing;

	/* Check if already in list */
	list_for_each_entry(existing, &agg_entry->cacheline_refs, list) {
		if (existing->cacheline == cacheline_he)
			return;
	}

	/* Add new reference */
	ref = zalloc(sizeof(*ref));
	if (ref) {
		ref->cacheline = cacheline_he;
		list_add_tail(&ref->list, &agg_entry->cacheline_refs);
	}
}

/**
 * build_symbol_hists_and_refs - Build symbol histograms and cacheline references
 *
 * Optimized single-pass algorithm with temporary aggregation tree:
 *   1. Single traversal of cacheline hierarchy
 *   2. Aggregates by (iaddr, symbol) using temporary rb-tree for O(log N) dedup
 *   3. Builds cacheline reference lists during aggregation
 *   4. Creates histogram entries only once per unique symbol
 *
 * Returns: 0 on success, negative error code on failure
 */
static int build_symbol_hists_and_refs(void)
{
	struct rb_root symbol_agg_root = RB_ROOT;
	struct rb_node *nd_cl, *nd_agg;
	struct thread *synthetic_thread = NULL;
	int ret;

	/* Invalidate cached total cycles */
	c2c_ext.symbol_total_cycles = 0;

	/* Clean up previous symbol hists entries */
	hists__delete_entries(&c2c_ext.symbol_hists.hists);

	/* Initialize symbol hists with sort by iaddr and symbol_view */
	ret = c2c_symbol_hists__init(&c2c_ext.symbol_hists, "iaddr_symbol,symbol_view", 2, NULL);
	if (ret)
		return ret;

	/* Setup output fields for symbol view - sorted by cycles percentage */
	ret = c2c_symbol_hists__reinit(&c2c_ext.symbol_hists,
		"cycles_percent,total_stores,iaddr_symbol,symbol_view,cacheline_symbol",
		"cycles_percent", NULL);
	if (ret)
		return ret;

	/* Get first thread for consistent aggregation */
	nd_cl = rb_first_cached(&c2c.hists.hists.entries);
	if (nd_cl) {
		struct hist_entry *first_he = rb_entry(nd_cl, struct hist_entry, rb_node);
		synthetic_thread = first_he->thread;
	}

	if (!synthetic_thread)
		return -EINVAL;

	/* Phase 1: Single-pass aggregation with cacheline reference building */
	nd_cl = rb_first_cached(&c2c.hists.hists.entries);
	while (nd_cl) {
		struct hist_entry *he_cl = rb_entry(nd_cl, struct hist_entry, rb_node);
		struct c2c_hist_entry *cacheline_he = container_of(he_cl, struct c2c_hist_entry, he);
		struct rb_node *nd_sym;

		/* Skip cachelines without HITM events */
		if (HITM_COUNT(&cacheline_he->stats) == 0 ||
		    !cacheline_he->hists ||
		    !cacheline_he->hists->hists.entries.rb_root.rb_node) {
			nd_cl = rb_next(nd_cl);
			continue;
		}

		/* Process each symbol accessing this cacheline */
		nd_sym = rb_first_cached(&cacheline_he->hists->hists.entries);
		while (nd_sym) {
			struct hist_entry *he_detail = rb_entry(nd_sym, struct hist_entry, rb_node);
			struct c2c_hist_entry *c2c_detail = container_of(he_detail,
									 struct c2c_hist_entry, he);
			struct symbol_agg_entry *agg_entry;
			uint64_t iaddr;

			if (!he_detail->ms.sym || he_detail->filtered) {
				nd_sym = rb_next(nd_sym);
				continue;
			}

			/* Get instruction address */
			iaddr = he_detail->mem_info ?
				mem_info__iaddr(he_detail->mem_info)->addr :
				he_detail->ms.sym->start;

			/* Find or create symbol aggregation entry */
			agg_entry = find_or_create_symbol_agg(&symbol_agg_root, iaddr,
							      he_detail->ms.sym,
							      he_detail->ms.maps,
							      he_detail->ms.map);
			if (!agg_entry) {
				nd_sym = rb_next(nd_sym);
				continue;
			}

			/* Aggregate stats */
			c2c_add_stats(&agg_entry->stats, &c2c_detail->stats);
			c2c_add_cstats(&agg_entry->cstats, &c2c_detail->cstats);

			/* Build cacheline reference list */
			add_cacheline_to_symbol_agg(agg_entry, cacheline_he);

			/* Accumulate to global stats */
			c2c_add_stats(&c2c_ext.symbol_hists.stats, &c2c_detail->stats);

			nd_sym = rb_next(nd_sym);
		}

		nd_cl = rb_next(nd_cl);
	}

	/*
	 * Phase 2: Create histogram entries from aggregated data.
	 * Also calculate total cycles for all symbols to avoid a second traversal.
	 */
	nd_agg = rb_first(&symbol_agg_root);
	while (nd_agg) {
		struct symbol_agg_entry *agg_entry = rb_entry(nd_agg, struct symbol_agg_entry, rb_node);
		struct c2c_hist_entry *symbol_he;
		struct symbol_cacheline_ref *ref, *tmp;

		/* Create histogram entry */
		symbol_he = create_symbol_entry(agg_entry->iaddr, agg_entry->sym,
						agg_entry->maps, agg_entry->map,
						synthetic_thread);
		if (symbol_he) {
			uint64_t cycles_rmt, cycles_lcl, cycles_load;
			uint64_t other_load, total_hitm;

			/* Copy aggregated stats */
			memcpy(&symbol_he->stats, &agg_entry->stats, sizeof(symbol_he->stats));
			memcpy(&symbol_he->cstats, &agg_entry->cstats, sizeof(symbol_he->cstats));

			/* Transfer cacheline reference list */
			list_for_each_entry_safe(ref, tmp, &agg_entry->cacheline_refs, list) {
				list_del(&ref->list);
				list_add_tail(&ref->list, &symbol_he->_symbol_accessed_cachelines);
			}

			/* Accumulate total cycles in this pass to avoid re-traversal */
			cycles_rmt = avg_stats(&symbol_he->cstats.rmt_hitm) * symbol_he->stats.rmt_hitm;
			cycles_lcl = avg_stats(&symbol_he->cstats.lcl_hitm) * symbol_he->stats.lcl_hitm;
			total_hitm = (uint64_t)symbol_he->stats.rmt_hitm + symbol_he->stats.lcl_hitm;
			other_load = (symbol_he->stats.load >= total_hitm) ?
				     symbol_he->stats.load - total_hitm : 0;
			cycles_load = avg_stats(&symbol_he->cstats.load) * other_load;

			c2c_ext.symbol_total_cycles += cycles_rmt + cycles_lcl + cycles_load;
		}

		nd_agg = rb_next(nd_agg);
	}

	/* Cleanup aggregation tree */
	free_symbol_agg_tree(&symbol_agg_root);

	/* Sort and layout symbol histogram by cycles percentage */
	hists__collapse_resort(&c2c_ext.symbol_hists.hists, NULL);
	hists__output_resort(&c2c_ext.symbol_hists.hists, NULL);

	/* Enable hierarchy support for symbol view to allow multi-level display */
	c2c_ext.symbol_hists.hists.symbol_filter_str = NULL;
	c2c_ext.symbol_hists.hists.socket_filter = -1;
	c2c_ext.symbol_hists.hists.nr_hpp_node = 0;

	return 0;
}

/* ============================================================================
 * Main Entry Point: Build Complete Symbol View Hierarchy
 * ============================================================================ */

/**
 * build_symbol_view_hierarchy - Build complete 4-level symbol view hierarchy
 *
 * Optimized 2-phase algorithm:
 *   Phase 1: Single traversal with temporary tree for symbol aggregation + cacheline refs
 *   Phase 2: Build parent-child-grandchild relationships using the reference lists
 *
 * This approach ensures proper deduplication while minimizing traversal count.
 *
 * Returns: 0 on success, negative error code on failure
 */
static int build_symbol_view_hierarchy(void)
{
	int ret;

	/* Phase 1: Build parent nodes with stats aggregation and cacheline references.
	 * Also pre-computes total cycles during this pass.
	 */
	ret = build_symbol_hists_and_refs();
	if (ret)
		return ret;

	/* Phase 2: Build parent-child-grandchild relationships using the reference lists */
	step3_build_parent_child_relationships();

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

	/* Child entries should already be populated during build_symbol_associations */
	/* If they're not, it means there are no children */

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

	/* Build complete symbol view hierarchy (4 steps) */
	ret = build_symbol_view_hierarchy();
	if (ret) {
		ui__error("Failed to build symbol view hierarchy (ret=%d)\n", ret);
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
	struct c2c_hist_entry *child_c2c_he;

	if (RB_EMPTY_ROOT(&parent_he->hroot_out.rb_root))
		return;

	nd = rb_first_cached(&parent_he->hroot_out);
	while (nd) {
		struct rb_node *next = rb_next(nd);

		child_he = rb_entry(nd, struct hist_entry, rb_node);
		child_c2c_he = container_of(child_he, struct c2c_hist_entry, he);

		if (child_he->stat_acc)
			zfree(&child_he->stat_acc);

		if (child_he->mem_info)
			mem_info__put(child_he->mem_info);

		/* Free child's hists */
		if (child_c2c_he->hists) {
			hists__delete_entries(&child_c2c_he->hists->hists);
			zfree(&child_c2c_he->hists);
		}

		zfree(&child_c2c_he->cpuset);
		zfree(&child_c2c_he->nodeset);
		zfree(&child_c2c_he->nodestr);
		zfree(&child_c2c_he->node_stats);

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
	.cmp		= empty_cmp,
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
	int ret = 0;

#define PARSE_LIST(_list, _fn)							\
	do {									\
		char *tmp, *tok;						\
										\
		if (ret)							\
			break;							\
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

