// SPDX-License-Identifier: GPL-2.0
/**
 * C2C Symbol Browser - Symbol-level cacheline sharing analysis
 *
 * Displays a 3-level hierarchy showing which symbols share cachelines:
 *   Level 1: Primary symbols sorted by cycles percentage
 *   Level 2: Other symbols sharing cachelines with level 1 symbols
 *   Level 3: Specific shared cachelines between symbol pairs
 *
 * Uses c2c_hist_entry->hists to build hierarchy (no extra data structures).
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

/**
 * get_hist_entry_iaddr - Get instruction address from histogram entry
 * @he: Histogram entry
 *
 * Returns: Instruction address from mem_info if available, otherwise symbol start
 */
static inline uint64_t get_hist_entry_iaddr(struct hist_entry *he)
{
	if (he->mem_info)
		return mem_info__iaddr(he->mem_info)->addr;
	return he->ms.sym ? he->ms.sym->start : 0;
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
static void free_hierarchy_entries(struct hist_entry *he);

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

	/* Free sub-hists (used for hierarchy) */
	if (c2c_he->hists) {
		hists__delete_entries(&c2c_he->hists->hists);
		zfree(&c2c_he->hists);
	}

	/* Free child entries in hroot_out */
	free_hierarchy_entries((struct hist_entry *)he);

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

static bool hist_entry__add_c2c_stats(struct hist_entry *he, struct c2c_stats *stats)
{
	u64 nr_events = HITM_COUNT(stats) + stats->rmt_peer + stats->lcl_peer;
	u64 weight1 = HITM_COUNT(stats);

	he->stat.nr_events += nr_events;
	he->stat.period += nr_events;
	he->stat.weight1 += weight1;

	if (!symbol_conf.cumulate_callchain)
		return true;

	if (!he->stat_acc) {
		he->stat_acc = calloc(1, sizeof(struct he_stat));
		if (!he->stat_acc)
			return false;
	}

	he->stat_acc->nr_events += nr_events;
	he->stat_acc->period += nr_events;
	he->stat_acc->weight1 += weight1;

	return true;
}

/**
 * find_or_create_level1_entry - Find or create a level 1 (primary symbol) entry
 * @sym: Symbol for the entry
 * @iaddr: Instruction address
 * @detail_he: Source detail entry for attributes
 * @synthetic_thread: Thread to use for new entries
 *
 * Returns: Pointer to the level 1 hist_entry, or NULL on failure
 */
static struct hist_entry *
find_or_create_level1_entry(struct symbol *sym, uint64_t iaddr,
			    struct hist_entry *detail_he,
			    struct thread *synthetic_thread)
{
	struct addr_location al;
	struct perf_sample sample = {};
	struct mem_info *mi;
	struct hist_entry *he;

	/* Create mem_info */
	mi = mem_info__new();
	if (mi) {
		mem_info__iaddr(mi)->addr = iaddr;
		mem_info__iaddr(mi)->ms.maps = detail_he->ms.maps;
		mem_info__iaddr(mi)->ms.map = detail_he->ms.map;
		mem_info__iaddr(mi)->ms.sym = sym;
		mem_info__daddr(mi)->addr = 0;
	}

	/* Create address location */
	addr_location__init(&al);
	al.thread = thread__get(synthetic_thread);
	al.maps = maps__get(detail_he->ms.maps);
	al.map = map__get(detail_he->ms.map);
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
	sample.pid = thread__pid(synthetic_thread);
	sample.tid = thread__tid(synthetic_thread);
	sample.cpu = 0;

	/* Add entry - histogram handles dedup */
	he = hists__add_entry_ops(&c2c_ext.symbol_hists.hists,
				  &c2c_symbol_entry_ops,
				  &al, NULL, NULL, mi,
				  NULL, &sample, true);

	addr_location__exit(&al);
	if (mi)
		mem_info__put(mi);

	if (he)
		he->hpp_list = &c2c_ext.symbol_hists.list;

	return he;
}

/**
 * find_or_create_level2_entry - Find or create a level 2 (sharing symbol) entry
 * @level1_c2c: Parent level 1 c2c_hist_entry
 * @sym: Symbol for the level 2 entry
 * @iaddr: Instruction address
 * @detail_he: Source detail entry for attributes
 *
 * Returns: Pointer to the level 2 c2c_hist_entry, or NULL on failure
 */
static struct c2c_hist_entry *
find_or_create_level2_entry(struct c2c_hist_entry *level1_c2c,
			    struct symbol *sym, uint64_t iaddr,
			    struct hist_entry *detail_he)
{
	struct hist_entry *level1_he = &level1_c2c->he;
	struct rb_node **p = &level1_he->hroot_out.rb_root.rb_node;
	struct rb_node *parent = NULL;
	struct c2c_hist_entry *level2_c2c;
	struct hist_entry *level2_he;
	bool leftmost = true;

	/* Search for existing entry */
	while (*p) {
		struct hist_entry *iter = rb_entry(*p, struct hist_entry, rb_node);
		uint64_t iter_iaddr = get_hist_entry_iaddr(iter);

		parent = *p;
		if (iaddr < iter_iaddr) {
			p = &parent->rb_left;
		} else if (iaddr > iter_iaddr) {
			p = &parent->rb_right;
			leftmost = false;
		} else if (sym < iter->ms.sym) {
			p = &parent->rb_left;
		} else if (sym > iter->ms.sym) {
			p = &parent->rb_right;
			leftmost = false;
		} else {
			/* Found existing entry */
			return container_of(iter, struct c2c_hist_entry, he);
		}
	}

	/* Create new level 2 entry */
	level2_c2c = zalloc(sizeof(*level2_c2c));
	if (!level2_c2c)
		return NULL;

	level2_he = &level2_c2c->he;

	/* Copy base info */
	memcpy(&level2_he->ms, &detail_he->ms, sizeof(struct map_symbol));

	/* Clone mem_info */
	if (detail_he->mem_info) {
		level2_he->mem_info = mem_info__clone(detail_he->mem_info);
		if (level2_he->mem_info)
			mem_info__iaddr(level2_he->mem_info)->addr = iaddr;
	}

	/* Copy attributes */
	level2_he->thread = detail_he->thread;
	level2_he->cpumode = detail_he->cpumode;
	level2_he->cpu = detail_he->cpu;
	level2_he->socket = detail_he->socket;

	/* Set hierarchy info */
	level2_he->parent_he = level1_he;
	level2_he->depth = 1;
	level2_he->leaf = false;
	level2_he->hists = &c2c_ext.symbol_hists.hists;
	level2_he->filtered = false;
	level2_he->unfolded = false;
	level2_he->has_children = false;
	level2_he->has_no_entry = false;
	level2_he->nr_rows = 0;
	level2_he->row_offset = 0;

	/* Initialize stats */
	memset(&level2_he->stat, 0, sizeof(level2_he->stat));
	level2_he->hroot_in = RB_ROOT_CACHED;
	level2_he->hroot_out = RB_ROOT_CACHED;
	INIT_LIST_HEAD(&level2_he->pairs.node);
	level2_he->hpp_list = &c2c_ext.symbol_hists.list;
	if (symbol_conf.cumulate_callchain) {
		level2_he->stat_acc = calloc(1, sizeof(struct he_stat));
		if (!level2_he->stat_acc) {
			if (level2_he->mem_info)
				mem_info__put(level2_he->mem_info);
			free(level2_c2c);
			return NULL;
		}
	}

	/* Initialize cstats */
	init_stats(&level2_c2c->cstats.lcl_hitm);
	init_stats(&level2_c2c->cstats.rmt_hitm);
	init_stats(&level2_c2c->cstats.lcl_peer);
	init_stats(&level2_c2c->cstats.rmt_peer);
	init_stats(&level2_c2c->cstats.load);

	/* Insert into tree */
	rb_link_node(&level2_he->rb_node, parent, p);
	rb_insert_color_cached(&level2_he->rb_node, &level1_he->hroot_out, leftmost);

	/* Mark parent as having children */
	level1_he->has_children = true;
	level1_he->leaf = false;
	level1_he->nr_rows++;

	return level2_c2c;
}

/**
 * find_or_create_level3_entry - Find or create a level 3 (cacheline) entry
 * @level2_c2c: Parent level 2 c2c_hist_entry
 * @cl_addr: Cacheline address
 * @cacheline_src_he: Source cacheline entry for attributes
 *
 * Returns: Pointer to the level 3 c2c_hist_entry, or NULL on failure
 */
static struct c2c_hist_entry *
find_or_create_level3_entry(struct c2c_hist_entry *level2_c2c,
			    uint64_t cl_addr,
			    struct c2c_hist_entry *cacheline_src_he)
{
	struct hist_entry *level2_he = &level2_c2c->he;
	struct rb_node **p = &level2_he->hroot_out.rb_root.rb_node;
	struct rb_node *parent = NULL;
	struct c2c_hist_entry *level3_c2c;
	struct hist_entry *level3_he;
	bool leftmost = true;

	/* Search for existing entry */
	while (*p) {
		struct hist_entry *iter = rb_entry(*p, struct hist_entry, rb_node);
		uint64_t iter_addr = 0;

		if (iter->mem_info)
			iter_addr = cl_address(mem_info__daddr(iter->mem_info)->addr, chk_double_cl);

		parent = *p;
		if (cl_addr < iter_addr) {
			p = &parent->rb_left;
		} else if (cl_addr > iter_addr) {
			p = &parent->rb_right;
			leftmost = false;
		} else {
			/* Found existing entry */
			return container_of(iter, struct c2c_hist_entry, he);
		}
	}

	/* Create new level 3 entry */
	level3_c2c = zalloc(sizeof(*level3_c2c));
	if (!level3_c2c)
		return NULL;

	level3_he = &level3_c2c->he;

	/* Copy base info */
	memcpy(&level3_he->ms, &cacheline_src_he->he.ms, sizeof(struct map_symbol));

	/* Clone mem_info from cacheline source */
	if (cacheline_src_he->he.mem_info)
		level3_he->mem_info = mem_info__clone(cacheline_src_he->he.mem_info);

	/* Copy attributes */
	level3_he->thread = cacheline_src_he->he.thread;
	level3_he->cpumode = cacheline_src_he->he.cpumode;
	level3_he->cpu = cacheline_src_he->he.cpu;
	level3_he->socket = cacheline_src_he->he.socket;

	/* Set hierarchy info */
	level3_he->parent_he = level2_he;
	level3_he->depth = 2;
	level3_he->leaf = true;
	level3_he->hists = &c2c_ext.symbol_hists.hists;
	level3_he->filtered = false;
	level3_he->unfolded = false;
	level3_he->has_children = false;
	level3_he->has_no_entry = false;
	level3_he->nr_rows = 0;
	level3_he->row_offset = 0;

	/* Initialize stats */
	memset(&level3_he->stat, 0, sizeof(level3_he->stat));
	level3_he->hroot_in = RB_ROOT_CACHED;
	level3_he->hroot_out = RB_ROOT_CACHED;
	INIT_LIST_HEAD(&level3_he->pairs.node);
	level3_he->hpp_list = &c2c_ext.symbol_hists.list;
	if (symbol_conf.cumulate_callchain) {
		level3_he->stat_acc = calloc(1, sizeof(struct he_stat));
		if (!level3_he->stat_acc) {
			if (level3_he->mem_info)
				mem_info__put(level3_he->mem_info);
			free(level3_c2c);
			return NULL;
		}
	}

	/* Initialize cstats */
	init_stats(&level3_c2c->cstats.lcl_hitm);
	init_stats(&level3_c2c->cstats.rmt_hitm);
	init_stats(&level3_c2c->cstats.lcl_peer);
	init_stats(&level3_c2c->cstats.rmt_peer);
	init_stats(&level3_c2c->cstats.load);

	/* Insert into tree */
	rb_link_node(&level3_he->rb_node, parent, p);
	rb_insert_color_cached(&level3_he->rb_node, &level2_he->hroot_out, leftmost);

	/* Mark parent as having children */
	level2_he->has_children = true;
	level2_he->leaf = false;
	level2_he->nr_rows++;

	return level3_c2c;
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

		total_cycles += calculate_symbol_cycles(c2c_he);
		nd = rb_next(nd);
	}

	c2c_ext.symbol_total_cycles = total_cycles;
	return total_cycles;
}

struct processed_symbol {
	struct symbol *sym;
	uint64_t iaddr;
	struct processed_symbol *next;
};

/**
 * build_symbol_view_hierarchy - Build complete 3-level symbol view hierarchy
 *
 * Single-pass algorithm that builds all three levels in one traversal:
 *   Level 1: Primary symbols (aggregated from all cachelines)
 *   Level 2: Sharing symbols (other symbols accessing same cachelines)
 *   Level 3: Shared cachelines between symbol pairs
 *
 * For each cacheline, for each pair of symbols (A, B) accessing it:
 *   - Find or create Level 1 entry for A
 *   - Find or create Level 2 entry for B under A
 *   - Find or create Level 3 entry for the cacheline under B
 *   - Aggregate stats at all levels
 *
 * Returns: 0 on success, negative error code on failure
 */
static int build_symbol_view_hierarchy(void)
{
	struct rb_node *nd_cl;
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

	/* Get first thread for consistent aggregation */
	nd_cl = rb_first_cached(&c2c.hists.hists.entries);
	if (nd_cl) {
		struct hist_entry *first_he = rb_entry(nd_cl, struct hist_entry, rb_node);
		synthetic_thread = first_he->thread;
	}

	if (!synthetic_thread)
		return -EINVAL;

	/* Single-pass: traverse all cachelines */
	nd_cl = rb_first_cached(&c2c.hists.hists.entries);
	while (nd_cl) {
		struct hist_entry *he_cl = rb_entry(nd_cl, struct hist_entry, rb_node);
		struct c2c_hist_entry *cacheline_he = container_of(he_cl, struct c2c_hist_entry, he);
		struct rb_node *nd_a, *nd_b;
		uint64_t cl_addr;
		struct processed_symbol *processed_list = NULL;

		/* Skip cachelines without HITM events */
		if (HITM_COUNT(&cacheline_he->stats) == 0 ||
		    !cacheline_he->hists ||
		    !cacheline_he->hists->hists.entries.rb_root.rb_node) {
			nd_cl = rb_next(nd_cl);
			continue;
		}

		if (!he_cl->mem_info || !mem_info__daddr(he_cl->mem_info)) {
			nd_cl = rb_next(nd_cl);
			continue;
		}

		cl_addr = cl_address(mem_info__daddr(he_cl->mem_info)->addr, chk_double_cl);

		/* For each symbol A accessing this cacheline */
		nd_a = rb_first_cached(&cacheline_he->hists->hists.entries);
		while (nd_a) {
			struct hist_entry *he_a = rb_entry(nd_a, struct hist_entry, rb_node);
			struct c2c_hist_entry *c2c_a = container_of(he_a, struct c2c_hist_entry, he);
			struct hist_entry *level1_he;
			struct c2c_hist_entry *level1_c2c;
			uint64_t iaddr_a;
			struct processed_symbol *p;
			bool already_processed = false;

			if (!he_a->ms.sym || he_a->filtered) {
				nd_a = rb_next(nd_a);
				continue;
			}

			iaddr_a = get_hist_entry_iaddr(he_a);

			/* Find or create Level 1 entry for symbol A */
			level1_he = find_or_create_level1_entry(he_a->ms.sym, iaddr_a,
								he_a, synthetic_thread);
			if (!level1_he) {
				nd_a = rb_next(nd_a);
				continue;
			}

			level1_c2c = container_of(level1_he, struct c2c_hist_entry, he);

			/* Aggregate stats for Level 1 */
			c2c_add_stats(&level1_c2c->stats, &c2c_a->stats);
			c2c_add_cstats(&level1_c2c->cstats, &c2c_a->cstats);

			/* Accumulate to global stats */
			c2c_add_stats(&c2c_ext.symbol_hists.stats, &c2c_a->stats);

			/* Check if we've processed this (symbol, iaddr) pair as a parent for this CL already */
			p = processed_list;
			while (p) {
				if (p->sym == he_a->ms.sym && p->iaddr == iaddr_a) {
					already_processed = true;
					break;
				}
				p = p->next;
			}

			if (already_processed) {
				nd_a = rb_next(nd_a);
				continue;
			}

			/* Add to processed list */
			p = zalloc(sizeof(*p));
			if (p) {
				p->sym = he_a->ms.sym;
				p->iaddr = iaddr_a;
				p->next = processed_list;
				processed_list = p;
			}

			/* For each other symbol B on the same cacheline */
			nd_b = rb_first_cached(&cacheline_he->hists->hists.entries);
			while (nd_b) {
				struct hist_entry *he_b = rb_entry(nd_b, struct hist_entry, rb_node);
				struct c2c_hist_entry *c2c_b = container_of(he_b, struct c2c_hist_entry, he);
				struct c2c_hist_entry *level2_c2c, *level3_c2c;
				uint64_t iaddr_b;

				if (!he_b->ms.sym || he_b->filtered) {
					nd_b = rb_next(nd_b);
					continue;
				}

				iaddr_b = get_hist_entry_iaddr(he_b);

				/* Skip self */
				if (iaddr_a == iaddr_b &&
				    symbol_name_equal(he_a->ms.sym, he_b->ms.sym)) {
					nd_b = rb_next(nd_b);
					continue;
				}

				/* Find or create Level 2 entry for symbol B under A */
				level2_c2c = find_or_create_level2_entry(level1_c2c,
									 he_b->ms.sym, iaddr_b, he_b);
				if (!level2_c2c) {
					nd_b = rb_next(nd_b);
					continue;
				}

				/* Aggregate stats for Level 2 */
				c2c_add_stats(&level2_c2c->stats, &c2c_b->stats);
				c2c_add_cstats(&level2_c2c->cstats, &c2c_b->cstats);
				if (!hist_entry__add_c2c_stats(&level2_c2c->he, &c2c_b->stats)) {
					nd_b = rb_next(nd_b);
					continue;
				}

				/* Find or create Level 3 entry for cacheline under B */
				level3_c2c = find_or_create_level3_entry(level2_c2c, cl_addr,
									 cacheline_he);
				if (!level3_c2c) {
					nd_b = rb_next(nd_b);
					continue;
				}

				/* Aggregate stats for Level 3 */
				c2c_add_stats(&level3_c2c->stats, &c2c_b->stats);
				c2c_add_cstats(&level3_c2c->cstats, &c2c_b->cstats);
				if (!hist_entry__add_c2c_stats(&level3_c2c->he, &c2c_b->stats)) {
					nd_b = rb_next(nd_b);
					continue;
				}

				nd_b = rb_next(nd_b);
			}

			nd_a = rb_next(nd_a);
		}

		/* Free processed list */
		while (processed_list) {
			struct processed_symbol *n = processed_list->next;
			free(processed_list);
			processed_list = n;
		}

		nd_cl = rb_next(nd_cl);
	}

	/* Setup output fields for symbol view - sorted by cycles percentage */
	ret = c2c_symbol_hists__reinit(&c2c_ext.symbol_hists,
		"cycles_percent,total_stores,iaddr_symbol,symbol_view,cacheline_symbol",
		"cycles_percent", NULL);
	if (ret)
		return ret;

	/* Sort and layout symbol histogram by cycles percentage */
	hists__collapse_resort(&c2c_ext.symbol_hists.hists, NULL);
	hists__output_resort(&c2c_ext.symbol_hists.hists, NULL);

	/* Calculate and cache total cycles after resort */
	c2c_ext.symbol_total_cycles = 0;
	(void)get_total_cycles_all_symbols();

	/* Enable hierarchy support for symbol view */
	c2c_ext.symbol_hists.hists.symbol_filter_str = NULL;
	c2c_ext.symbol_hists.hists.socket_filter = -1;
	c2c_ext.symbol_hists.hists.nr_hpp_node = 0;

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

	/* Build complete symbol view hierarchy (single pass) */
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
 * free_hierarchy_entries - Free all child entries of a histogram entry recursively
 * @he: Histogram entry whose children to free
 *
 * Recursively frees all child entries (sharing symbols and cacheline details)
 * and their associated resources including histograms and memory info.
 */
static void free_hierarchy_entries(struct hist_entry *he)
{
	struct rb_node *nd;
	struct hist_entry *child_he;
	struct c2c_hist_entry *child_c2c;

	if (RB_EMPTY_ROOT(&he->hroot_out.rb_root))
		return;

	nd = rb_first_cached(&he->hroot_out);
	while (nd) {
		struct rb_node *next = rb_next(nd);

		child_he = rb_entry(nd, struct hist_entry, rb_node);
		child_c2c = container_of(child_he, struct c2c_hist_entry, he);

		if (child_he->stat_acc)
			zfree(&child_he->stat_acc);

		if (child_he->mem_info)
			mem_info__put(child_he->mem_info);

		/* Free child's hists */
		if (child_c2c->hists) {
			hists__delete_entries(&child_c2c->hists->hists);
			zfree(&child_c2c->hists);
		}

		zfree(&child_c2c->cpuset);
		zfree(&child_c2c->nodeset);
		zfree(&child_c2c->nodestr);
		zfree(&child_c2c->node_stats);

		/* Recursively free children in child_he->hroot_out */
		free_hierarchy_entries(child_he);

		rb_erase_cached(&child_he->rb_node, &he->hroot_out);
		free(child_c2c);

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
	INIT_LIST_HEAD(&c2c_hists->list.sorts);
	return symbol_hpp_list__parse(&c2c_hists->list, output, sort, env);
}

