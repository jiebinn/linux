// SPDX-License-Identifier: GPL-2.0
/*
 * This is rewrite of original c2c tool introduced in here:
 *   http://lwn.net/Articles/588866/
 *
 * The original tool was changed to fit in current perf state.
 *
 * Original authors:
 *   Don Zickus <dzickus@redhat.com>
 *   Dick Fowles <fowles@inreach.com>
 *   Joe Mario <jmario@redhat.com>
 */
#include <errno.h>
#include <inttypes.h>
#include <stdlib.h>
#include <linux/compiler.h>
#include <linux/hash.h>
#include <linux/err.h>
#include <linux/kernel.h>
#include <linux/stringify.h>
#include <linux/zalloc.h>
#include <linux/list.h>
#include <linux/bitmap.h>
#include <asm/bug.h>
#include <sys/param.h>
#include "debug.h"
#include "builtin.h"
#include <perf/cpumap.h>
#include <subcmd/pager.h>
#include <subcmd/parse-options.h>
#include "addr_location.h"
#include "map_symbol.h"
#include "mem-events.h"
#include "session.h"
#include "hist.h"
#include "sort.h"
#include "tool.h"
#include "cacheline.h"
#include "data.h"
#include "event.h"
#include "evlist.h"
#include "evsel.h"
#include "ui/browsers/hists.h"
#include "thread.h"
#include "mem2node.h"
#include "mem-info.h"
#include "symbol.h"
#include "map.h"
#include "ui/ui.h"
#include "ui/progress.h"
#include "pmus.h"
#include "string2.h"
#include "util/util.h"

static inline bool symbol_name_equal(struct symbol *a, struct symbol *b)
{
	return a && b && strcmp(a->name, b->name) == 0;
}

struct c2c_hists {
	struct hists		hists;
	struct perf_hpp_list	list;
	struct c2c_stats	stats;
};

struct compute_stats {
	struct stats		 lcl_hitm;
	struct stats		 rmt_hitm;
	struct stats		 lcl_peer;
	struct stats		 rmt_peer;
	struct stats		 load;
};

struct c2c_hist_entry {
	struct c2c_hists	*hists;
	struct c2c_stats	 stats;
	unsigned long		*cpuset;
	unsigned long		*nodeset;
	struct c2c_stats	*node_stats;
	unsigned int		 cacheline_idx;

	struct compute_stats	 cstats;

	unsigned long		 paddr;
	unsigned long		 paddr_cnt;
	bool			 paddr_zero;
	char			*nodestr;

	/* Symbol association support */
	struct list_head	related_symbols;	/* Related symbols list */

	/* Cached total cycles for this entry to avoid repeated calculations */
	uint64_t		 total_cycles;
	bool			 total_cycles_valid;

	/*
	 * must be at the end,
	 * because of its callchain dynamic entry
	 */
	struct hist_entry	he;
};

static char const *coalesce_default = "iaddr";

/* Structure to represent related symbols */
struct related_symbol {
	struct list_head	 list;
	struct symbol		*sym;
	uint64_t		iaddr;			/* Code address */
	struct c2c_stats	stats;			/* Aggregated stats */
	struct compute_stats	cstats;			/* Compute stats */
	int			association_count;	/* Shared cachelines count */
};

struct perf_c2c {
	struct perf_tool	tool;
	struct c2c_hists	hists;
	struct c2c_hists	symbol_hists;  /* Symbol grouped hists */
	struct mem2node		mem2node;

	unsigned long		**nodes;
	int			 nodes_cnt;
	int			 cpus_cnt;
	int			*cpu2node;
	int			 node_info;

	bool			 show_src;
	bool			 show_all;
	bool			 use_stdio;
	bool			 stats_only;
	bool			 symbol_full;
	bool			 stitch_lbr;

	/* Shared cache line stats */
	struct c2c_stats	shared_clines_stats;
	int			shared_clines;

	int			 display;

	/* Cached total cycles across all symbols for percent column */
	uint64_t		symbol_total_cycles;
	bool			symbol_total_cycles_valid;

	const char		*coalesce;
	char			*cl_sort;
	char			*cl_resort;
	char			*cl_output;
};

enum {
	DISPLAY_LCL_HITM,
	DISPLAY_RMT_HITM,
	DISPLAY_TOT_HITM,
	DISPLAY_SNP_PEER,
	DISPLAY_MAX,
};

static const char *display_str[DISPLAY_MAX] = {
	[DISPLAY_LCL_HITM] = "Local HITMs",
	[DISPLAY_RMT_HITM] = "Remote HITMs",
	[DISPLAY_TOT_HITM] = "Total HITMs",
	[DISPLAY_SNP_PEER] = "Peer Snoop",
};

static const struct option c2c_options[] = {
	OPT_INCR('v', "verbose", &verbose, "be more verbose (show counter open errors, etc)"),
	OPT_END()
};

static struct perf_c2c c2c;

static int build_symbol_hists(struct perf_env *env);

/* Helper function to initialize c2c_hist_entry related_symbols */
static void init_c2c_he_related_symbols(struct c2c_hist_entry *c2c_he)
{
	INIT_LIST_HEAD(&c2c_he->related_symbols);
}

/* Helper function to invalidate cached total cycles */
static void c2c_he_invalidate_total_cycles_cache(struct c2c_hist_entry *c2c_he)
{
	c2c_he->total_cycles_valid = false;
}

static void *c2c_he_zalloc(size_t size)
{
	struct c2c_hist_entry *c2c_he;

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

	/* Initialize symbol association fields */
	init_c2c_he_related_symbols(c2c_he);

	/* Initialize cached total cycles */
	c2c_he->total_cycles = 0;
	c2c_he->total_cycles_valid = false;

	return &c2c_he->he;

out_free:
	zfree(&c2c_he->nodeset);
	zfree(&c2c_he->cpuset);
	free(c2c_he);
	return NULL;
}

/* Helper function to free child entries properly */
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

		if (child_he->stat_acc) {
			zfree(&child_he->stat_acc);
		}

		if (child_he->mem_info) {
			zfree(&child_he->mem_info);
		}

		rb_erase_cached(&child_he->rb_node, &parent_he->hroot_out);
		free(child_c2c_he);

		nd = next;
	}
}

static void c2c_he_free(void *he)
{
	struct c2c_hist_entry *c2c_he;
	struct related_symbol *rel_sym, *tmp;
	struct hist_entry *hist_entry = (struct hist_entry *)he;

	c2c_he = container_of(he, struct c2c_hist_entry, he);

	/* Free child entries first */
	free_child_entries(hist_entry);

	if (c2c_he->hists) {
		hists__delete_entries(&c2c_he->hists->hists);
		zfree(&c2c_he->hists);
	}

	/* Free related symbols list */
	list_for_each_entry_safe(rel_sym, tmp, &c2c_he->related_symbols, list) {
		list_del(&rel_sym->list);
		free(rel_sym);
	}

	if (hist_entry->parent_he && symbol_conf.cumulate_callchain && hist_entry->stat_acc) {
		zfree(&hist_entry->stat_acc);
	}

	zfree(&c2c_he->cpuset);
	zfree(&c2c_he->nodeset);
	zfree(&c2c_he->nodestr);
	zfree(&c2c_he->node_stats);
	free(c2c_he);
}

static struct hist_entry_ops c2c_entry_ops = {
	.new	= c2c_he_zalloc,
	.free	= c2c_he_free,
};

static int c2c_hists__init(struct c2c_hists *hists,
			   const char *sort,
			   int nr_header_lines,
			   struct perf_env *env);

static struct c2c_hists*
he__get_c2c_hists(struct hist_entry *he,
		  const char *sort,
		  int nr_header_lines,
		  struct perf_env *env)
{
	struct c2c_hist_entry *c2c_he;
	struct c2c_hists *hists;
	int ret;

	c2c_he = container_of(he, struct c2c_hist_entry, he);
	if (c2c_he->hists)
		return c2c_he->hists;

	hists = c2c_he->hists = zalloc(sizeof(*hists));
	if (!hists)
		return NULL;

	ret = c2c_hists__init(hists, sort, nr_header_lines, env);
	if (ret) {
		free(hists);
		return NULL;
	}

	return hists;
}

static void c2c_he__set_cpu(struct c2c_hist_entry *c2c_he,
			    struct perf_sample *sample)
{
	if (WARN_ONCE(sample->cpu == (unsigned int) -1,
		      "WARNING: no sample cpu value"))
		return;

	__set_bit(sample->cpu, c2c_he->cpuset);
}

static void c2c_he__set_node(struct c2c_hist_entry *c2c_he,
			     struct perf_sample *sample)
{
	int node;

	if (!sample->phys_addr) {
		c2c_he->paddr_zero = true;
		return;
	}

	node = mem2node__node(&c2c.mem2node, sample->phys_addr);
	if (WARN_ONCE(node < 0, "WARNING: failed to find node\n"))
		return;

	__set_bit(node, c2c_he->nodeset);

	if (c2c_he->paddr != sample->phys_addr) {
		c2c_he->paddr_cnt++;
		c2c_he->paddr = sample->phys_addr;
	}
}

static void compute_stats(struct c2c_hist_entry *c2c_he,
			  struct c2c_stats *stats,
			  u64 weight)
{
	struct compute_stats *cstats = &c2c_he->cstats;

	if (stats->rmt_hitm)
		update_stats(&cstats->rmt_hitm, weight);
	else if (stats->lcl_hitm)
		update_stats(&cstats->lcl_hitm, weight);
	else if (stats->rmt_peer)
		update_stats(&cstats->rmt_peer, weight);
	else if (stats->lcl_peer)
		update_stats(&cstats->lcl_peer, weight);
	else if (stats->load)
		update_stats(&cstats->load, weight);
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
	if (src->min < dest->min || dest->min == 0)
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

static int process_sample_event(const struct perf_tool *tool __maybe_unused,
				union perf_event *event,
				struct perf_sample *sample,
				struct evsel *evsel,
				struct machine *machine)
{
	struct c2c_hists *c2c_hists = &c2c.hists;
	struct c2c_hist_entry *c2c_he;
	struct c2c_stats stats = { .nr_entries = 0, };
	struct hist_entry *he;
	struct addr_location al;
	struct mem_info *mi, *mi_dup;
	struct callchain_cursor *cursor;
	int ret;

	addr_location__init(&al);
	if (machine__resolve(machine, &al, sample) < 0) {
		pr_debug("problem processing %d event, skipping it.\n",
			 event->header.type);
		ret = -1;
		goto out;
	}

	if (c2c.stitch_lbr)
		thread__set_lbr_stitch_enable(al.thread, true);

	cursor = get_tls_callchain_cursor();
	ret = sample__resolve_callchain(sample, cursor, NULL,
					evsel, &al, sysctl_perf_event_max_stack);
	if (ret)
		goto out;

	mi = sample__resolve_mem(sample, &al);
	if (mi == NULL) {
		ret = -ENOMEM;
		goto out;
	}

	/*
	 * The mi object is released in hists__add_entry_ops,
	 * if it gets sorted out into existing data, so we need
	 * to take the copy now.
	 */
	mi_dup = mem_info__get(mi);

	c2c_decode_stats(&stats, mi);

	he = hists__add_entry_ops(&c2c_hists->hists, &c2c_entry_ops,
				  &al, NULL, NULL, mi, NULL,
				  sample, true);
	if (he == NULL)
		goto free_mi;

	c2c_he = container_of(he, struct c2c_hist_entry, he);
	c2c_add_stats(&c2c_he->stats, &stats);
	c2c_he_invalidate_total_cycles_cache(c2c_he);
	c2c_add_stats(&c2c_hists->stats, &stats);

	c2c_he__set_cpu(c2c_he, sample);
	c2c_he__set_node(c2c_he, sample);

	hists__inc_nr_samples(&c2c_hists->hists, he->filtered);
	ret = hist_entry__append_callchain(he, sample);

	if (!ret) {
		/*
		 * There's already been warning about missing
		 * sample's cpu value. Let's account all to
		 * node 0 in this case, without any further
		 * warning.
		 *
		 * Doing node stats only for single callchain data.
		 */
		int cpu = sample->cpu == (unsigned int) -1 ? 0 : sample->cpu;
		int node = c2c.cpu2node[cpu];

		mi = mi_dup;

		c2c_hists = he__get_c2c_hists(he, c2c.cl_sort, 2, machine->env);
		if (!c2c_hists)
			goto free_mi;

		he = hists__add_entry_ops(&c2c_hists->hists, &c2c_entry_ops,
					  &al, NULL, NULL, mi, NULL,
					  sample, true);
		if (he == NULL)
			goto free_mi;

		c2c_he = container_of(he, struct c2c_hist_entry, he);
		c2c_add_stats(&c2c_he->stats, &stats);
		c2c_he_invalidate_total_cycles_cache(c2c_he);
		c2c_add_stats(&c2c_hists->stats, &stats);
		c2c_add_stats(&c2c_he->node_stats[node], &stats);

		compute_stats(c2c_he, &stats, sample->weight);

		c2c_he__set_cpu(c2c_he, sample);
		c2c_he__set_node(c2c_he, sample);

		hists__inc_nr_samples(&c2c_hists->hists, he->filtered);
		ret = hist_entry__append_callchain(he, sample);
	}

out:
	addr_location__exit(&al);
	return ret;

free_mi:
	mem_info__put(mi_dup);
	mem_info__put(mi);
	ret = -ENOMEM;
	goto out;
}

static const char * const c2c_usage[] = {
	"perf c2c {record|report}",
	NULL
};

static const char * const __usage_report[] = {
	"perf c2c report",
	NULL
};

static const char * const *report_c2c_usage = __usage_report;

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

#define SYMBOL_WIDTH 30

static struct c2c_dimension dim_symbol;
static struct c2c_dimension dim_srcline;

static int symbol_width(struct hists *hists, struct sort_entry *se)
{
	int width = hists__col_len(hists, se->se_width_idx);

	if (!c2c.symbol_full)
		width = MIN(width, SYMBOL_WIDTH);

	return width;
}

static int c2c_width(struct perf_hpp_fmt *fmt,
		     struct perf_hpp *hpp __maybe_unused,
		     struct hists *hists)
{
	struct c2c_fmt *c2c_fmt;
	struct c2c_dimension *dim;

	c2c_fmt = container_of(fmt, struct c2c_fmt, fmt);
	dim = c2c_fmt->dim;

	if (dim == &dim_symbol || dim == &dim_srcline)
		return symbol_width(hists, dim->se);

	return dim->se ? hists__col_len(hists, dim->se->se_width_idx) :
			 c2c_fmt->dim->width;
}

static int c2c_header(struct perf_hpp_fmt *fmt, struct perf_hpp *hpp,
		      struct hists *hists, int line, int *span)
{
	struct perf_hpp_list *hpp_list = hists->hpp_list;
	struct c2c_fmt *c2c_fmt;
	struct c2c_dimension *dim;
	const char *text = NULL;
	int width = c2c_width(fmt, hpp, hists);
	/* Center align the header text */
	int text_len;
	int padding;
	int left_pad;
	char centered_text[256];

	c2c_fmt = container_of(fmt, struct c2c_fmt, fmt);
	dim = c2c_fmt->dim;

	if (dim->se) {
		text = dim->header.line[line].text;
		/* Use the last line from sort_entry if not defined. */
		if (!text && (line == hpp_list->nr_header_lines - 1))
			text = dim->se->se_header;
	} else {
		text = dim->header.line[line].text;

		if (*span) {
			(*span)--;
			return 0;
		} else {
			*span = dim->header.line[line].span;
		}
	}

	if (text == NULL)
		text = "";

	text_len = strlen(text);
	if (text_len >= width) {
		return scnprintf(hpp->buf, hpp->size, "%-*.*s", width, width, text);
	} else {
		padding = width - text_len;
		left_pad = padding / 2;
		
		/* Create centered text with proper spacing */
		snprintf(centered_text, sizeof(centered_text), "%*s%s%*s", 
			left_pad, "", text, padding - left_pad, "");
		
		return scnprintf(hpp->buf, hpp->size, "%-*s", width, centered_text);
	}
}

#define HEX_STR(__s, __v)				\
({							\
	scnprintf(__s, sizeof(__s), "0x%" PRIx64, __v);	\
	__s;						\
})

static int64_t
dcacheline_cmp(struct perf_hpp_fmt *fmt __maybe_unused,
	       struct hist_entry *left, struct hist_entry *right)
{
	return sort__dcacheline_cmp(left, right);
}

static int dcacheline_entry(struct perf_hpp_fmt *fmt, struct perf_hpp *hpp,
			    struct hist_entry *he)
{
	uint64_t addr = 0;
	int width = c2c_width(fmt, hpp, he->hists);
	char buf[20];

	if (he->mem_info)
		addr = cl_address(mem_info__daddr(he->mem_info)->addr, chk_double_cl);

	return scnprintf(hpp->buf, hpp->size, "%*s", width, HEX_STR(buf, addr));
}

static int
dcacheline_node_entry(struct perf_hpp_fmt *fmt, struct perf_hpp *hpp,
		      struct hist_entry *he)
{
	struct c2c_hist_entry *c2c_he;
	int width = c2c_width(fmt, hpp, he->hists);

	c2c_he = container_of(he, struct c2c_hist_entry, he);
	if (WARN_ON_ONCE(!c2c_he->nodestr))
		return 0;

	return scnprintf(hpp->buf, hpp->size, "%*s", width, c2c_he->nodestr);
}

static int
dcacheline_node_count(struct perf_hpp_fmt *fmt, struct perf_hpp *hpp,
		      struct hist_entry *he)
{
	struct c2c_hist_entry *c2c_he;
	int width = c2c_width(fmt, hpp, he->hists);

	c2c_he = container_of(he, struct c2c_hist_entry, he);
	return scnprintf(hpp->buf, hpp->size, "%*lu", width, c2c_he->paddr_cnt);
}

static int offset_entry(struct perf_hpp_fmt *fmt, struct perf_hpp *hpp,
			struct hist_entry *he)
{
	uint64_t addr = 0;
	int width = c2c_width(fmt, hpp, he->hists);
	char buf[20];

	if (he->mem_info)
		addr = cl_offset(mem_info__daddr(he->mem_info)->al_addr, chk_double_cl);

	return scnprintf(hpp->buf, hpp->size, "%*s", width, HEX_STR(buf, addr));
}

static int64_t
offset_cmp(struct perf_hpp_fmt *fmt __maybe_unused,
	   struct hist_entry *left, struct hist_entry *right)
{
	uint64_t l = 0, r = 0;

	if (left->mem_info)
		l = cl_offset(mem_info__daddr(left->mem_info)->addr, chk_double_cl);

	if (right->mem_info)
		r = cl_offset(mem_info__daddr(right->mem_info)->addr, chk_double_cl);

	return (int64_t)(r - l);
}

static int
iaddr_entry(struct perf_hpp_fmt *fmt, struct perf_hpp *hpp,
	    struct hist_entry *he)
{
	uint64_t addr = 0;
	int width = c2c_width(fmt, hpp, he->hists);
	char buf[20];

	/* Hide Code address for cacheline entries */
	if (he->depth == 2 && he->parent_he && he->parent_he->parent_he) {
		return scnprintf(hpp->buf, hpp->size, "%-*s", width, "");
	}

	if (he->mem_info)
		addr = mem_info__iaddr(he->mem_info)->addr;

    if (he->parent_he) {
        /* Indent child addresses */
        char out[40];
        scnprintf(out, sizeof(out), "    %s", HEX_STR(buf, addr));
        return scnprintf(hpp->buf, hpp->size, "%-*s", width, out);
    }

	return scnprintf(hpp->buf, hpp->size, "%-*s", width, HEX_STR(buf, addr));
}

static int64_t
iaddr_cmp(struct perf_hpp_fmt *fmt __maybe_unused,
	  struct hist_entry *left, struct hist_entry *right)
{
	return sort__iaddr_cmp(left, right);
}

static int
tot_hitm_entry(struct perf_hpp_fmt *fmt, struct perf_hpp *hpp,
	       struct hist_entry *he)
{
	struct c2c_hist_entry *c2c_he;
	int width = c2c_width(fmt, hpp, he->hists);
	unsigned int tot_hitm;

	c2c_he = container_of(he, struct c2c_hist_entry, he);
	tot_hitm = c2c_he->stats.lcl_hitm + c2c_he->stats.rmt_hitm;

	return scnprintf(hpp->buf, hpp->size, "%*u", width, tot_hitm);
}

static int64_t
tot_hitm_cmp(struct perf_hpp_fmt *fmt __maybe_unused,
	     struct hist_entry *left, struct hist_entry *right)
{
	struct c2c_hist_entry *c2c_left;
	struct c2c_hist_entry *c2c_right;
	uint64_t tot_hitm_left;
	uint64_t tot_hitm_right;

	c2c_left  = container_of(left, struct c2c_hist_entry, he);
	c2c_right = container_of(right, struct c2c_hist_entry, he);

	tot_hitm_left  = c2c_left->stats.lcl_hitm + c2c_left->stats.rmt_hitm;
	tot_hitm_right = c2c_right->stats.lcl_hitm + c2c_right->stats.rmt_hitm;

	return tot_hitm_left - tot_hitm_right;
}

#define STAT_FN_ENTRY(__f)					\
static int							\
__f ## _entry(struct perf_hpp_fmt *fmt, struct perf_hpp *hpp,	\
	      struct hist_entry *he)				\
{								\
	struct c2c_hist_entry *c2c_he;				\
	int width = c2c_width(fmt, hpp, he->hists);		\
								\
	c2c_he = container_of(he, struct c2c_hist_entry, he);	\
	return scnprintf(hpp->buf, hpp->size, "%*u", width,	\
			 c2c_he->stats.__f);			\
}

#define STAT_FN_CMP(__f)						\
static int64_t								\
__f ## _cmp(struct perf_hpp_fmt *fmt __maybe_unused,			\
	    struct hist_entry *left, struct hist_entry *right)		\
{									\
	struct c2c_hist_entry *c2c_left, *c2c_right;			\
									\
	c2c_left  = container_of(left, struct c2c_hist_entry, he);	\
	c2c_right = container_of(right, struct c2c_hist_entry, he);	\
	return (uint64_t) c2c_left->stats.__f -				\
	       (uint64_t) c2c_right->stats.__f;				\
}

#define STAT_FN(__f)		\
	STAT_FN_ENTRY(__f)	\
	STAT_FN_CMP(__f)

STAT_FN(rmt_hitm)
STAT_FN(lcl_hitm)
STAT_FN(rmt_peer)
STAT_FN(lcl_peer)
STAT_FN(tot_peer)
STAT_FN(store)
STAT_FN(st_l1hit)
STAT_FN(st_l1miss)
STAT_FN(st_na)
STAT_FN(ld_fbhit)
STAT_FN(ld_l1hit)
STAT_FN(ld_l2hit)
STAT_FN(ld_llchit)
STAT_FN(rmt_hit)

static uint64_t get_load_llc_misses(struct c2c_stats *stats)
{
	return stats->lcl_dram +
	       stats->rmt_dram +
	       stats->rmt_hitm +
	       stats->rmt_hit;
}

static uint64_t get_load_cache_hits(struct c2c_stats *stats)
{
	return stats->ld_fbhit +
	       stats->ld_l1hit +
	       stats->ld_l2hit +
	       stats->ld_llchit +
	       stats->lcl_hitm;
}

static uint64_t get_stores(struct c2c_stats *stats)
{
	return stats->st_l1hit +
	       stats->st_l1miss +
	       stats->st_na;
}

static uint64_t total_records(struct c2c_stats *stats)
{
	return get_load_llc_misses(stats) +
	       get_load_cache_hits(stats) +
	       get_stores(stats);
}

static int
tot_recs_entry(struct perf_hpp_fmt *fmt, struct perf_hpp *hpp,
		struct hist_entry *he)
{
	struct c2c_hist_entry *c2c_he;
	int width = c2c_width(fmt, hpp, he->hists);
	uint64_t tot_recs;

	c2c_he = container_of(he, struct c2c_hist_entry, he);
	tot_recs = total_records(&c2c_he->stats);

	return scnprintf(hpp->buf, hpp->size, "%*" PRIu64, width, tot_recs);
}

static int64_t
tot_recs_cmp(struct perf_hpp_fmt *fmt __maybe_unused,
	     struct hist_entry *left, struct hist_entry *right)
{
	struct c2c_hist_entry *c2c_left;
	struct c2c_hist_entry *c2c_right;
	uint64_t tot_recs_left;
	uint64_t tot_recs_right;

	c2c_left  = container_of(left, struct c2c_hist_entry, he);
	c2c_right = container_of(right, struct c2c_hist_entry, he);

	tot_recs_left  = total_records(&c2c_left->stats);
	tot_recs_right = total_records(&c2c_right->stats);

	return tot_recs_left - tot_recs_right;
}

static uint64_t total_loads(struct c2c_stats *stats)
{
	return get_load_llc_misses(stats) +
	       get_load_cache_hits(stats);
}

static int
tot_loads_entry(struct perf_hpp_fmt *fmt, struct perf_hpp *hpp,
		struct hist_entry *he)
{
	struct c2c_hist_entry *c2c_he;
	int width = c2c_width(fmt, hpp, he->hists);
	uint64_t tot_recs;

	c2c_he = container_of(he, struct c2c_hist_entry, he);
	tot_recs = total_loads(&c2c_he->stats);

	return scnprintf(hpp->buf, hpp->size, "%*" PRIu64, width, tot_recs);
}

static int64_t
tot_loads_cmp(struct perf_hpp_fmt *fmt __maybe_unused,
	      struct hist_entry *left, struct hist_entry *right)
{
	struct c2c_hist_entry *c2c_left;
	struct c2c_hist_entry *c2c_right;
	uint64_t tot_recs_left;
	uint64_t tot_recs_right;

	c2c_left  = container_of(left, struct c2c_hist_entry, he);
	c2c_right = container_of(right, struct c2c_hist_entry, he);

	tot_recs_left  = total_loads(&c2c_left->stats);
	tot_recs_right = total_loads(&c2c_right->stats);

	return tot_recs_left - tot_recs_right;
}

typedef double (get_percent_cb)(struct c2c_hist_entry *);

static int
percent_color(struct perf_hpp_fmt *fmt, struct perf_hpp *hpp,
	      struct hist_entry *he, get_percent_cb get_percent)
{
	struct c2c_hist_entry *c2c_he;
	int width = c2c_width(fmt, hpp, he->hists);
	double per;

	c2c_he = container_of(he, struct c2c_hist_entry, he);
	per = get_percent(c2c_he);

#ifdef HAVE_SLANG_SUPPORT
	if (use_browser)
		return __hpp__slsmg_color_printf(hpp, "%*.2f%%", width - 1, per);
#endif
	return hpp_color_scnprintf(hpp, "%*.2f%%", width - 1, per);
}

static double percent_costly_snoop(struct c2c_hist_entry *c2c_he)
{
	struct c2c_hists *hists;
	struct c2c_stats *stats;
	struct c2c_stats *total;
	int tot = 0, st = 0;
	double p;

	hists = container_of(c2c_he->he.hists, struct c2c_hists, hists);
	stats = &c2c_he->stats;
	total = &hists->stats;

	switch (c2c.display) {
	case DISPLAY_RMT_HITM:
		st  = stats->rmt_hitm;
		tot = total->rmt_hitm;
		break;
	case DISPLAY_LCL_HITM:
		st  = stats->lcl_hitm;
		tot = total->lcl_hitm;
		break;
	case DISPLAY_TOT_HITM:
		st  = stats->tot_hitm;
		tot = total->tot_hitm;
		break;
	case DISPLAY_SNP_PEER:
		st  = stats->tot_peer;
		tot = total->tot_peer;
		break;
	default:
		break;
	}

	p = tot ? (double) st / tot : 0;

	return 100 * p;
}

#define PERC_STR(__s, __v)				\
({							\
	scnprintf(__s, sizeof(__s), "%.2F%%", __v);	\
	__s;						\
})

static int
percent_costly_snoop_entry(struct perf_hpp_fmt *fmt, struct perf_hpp *hpp,
			   struct hist_entry *he)
{
	struct c2c_hist_entry *c2c_he;
	int width = c2c_width(fmt, hpp, he->hists);
	char buf[10];
	double per;

	c2c_he = container_of(he, struct c2c_hist_entry, he);
	per = percent_costly_snoop(c2c_he);
	return scnprintf(hpp->buf, hpp->size, "%*s", width, PERC_STR(buf, per));
}

static int
percent_costly_snoop_color(struct perf_hpp_fmt *fmt, struct perf_hpp *hpp,
			   struct hist_entry *he)
{
	return percent_color(fmt, hpp, he, percent_costly_snoop);
}

static int64_t
percent_costly_snoop_cmp(struct perf_hpp_fmt *fmt __maybe_unused,
			 struct hist_entry *left, struct hist_entry *right)
{
	struct c2c_hist_entry *c2c_left;
	struct c2c_hist_entry *c2c_right;
	double per_left;
	double per_right;

	c2c_left  = container_of(left, struct c2c_hist_entry, he);
	c2c_right = container_of(right, struct c2c_hist_entry, he);

	per_left  = percent_costly_snoop(c2c_left);
	per_right = percent_costly_snoop(c2c_right);

	return per_left - per_right;
}

static struct c2c_stats *he_stats(struct hist_entry *he)
{
	struct c2c_hist_entry *c2c_he;

	c2c_he = container_of(he, struct c2c_hist_entry, he);
	return &c2c_he->stats;
}

static struct c2c_stats *total_stats(struct hist_entry *he)
{
	struct c2c_hists *hists;

	hists = container_of(he->hists, struct c2c_hists, hists);
	return &hists->stats;
}

static double percent(u32 st, u32 tot)
{
	return tot ? 100. * (double) st / (double) tot : 0;
}

#define PERCENT(__h, __f) percent(he_stats(__h)->__f, total_stats(__h)->__f)

#define PERCENT_FN(__f)								\
static double percent_ ## __f(struct c2c_hist_entry *c2c_he)			\
{										\
	struct c2c_hists *hists;						\
										\
	hists = container_of(c2c_he->he.hists, struct c2c_hists, hists);	\
	return percent(c2c_he->stats.__f, hists->stats.__f);			\
}

PERCENT_FN(rmt_hitm)
PERCENT_FN(lcl_hitm)
PERCENT_FN(rmt_peer)
PERCENT_FN(lcl_peer)
PERCENT_FN(st_l1hit)
PERCENT_FN(st_l1miss)
PERCENT_FN(st_na)

/* Simple percentage functions for cacheline offsets view */
static int
percent_cl_stores_l1hit_entry(struct perf_hpp_fmt *fmt, struct perf_hpp *hpp,
			       struct hist_entry *he)
{
	int width = c2c_width(fmt, hpp, he->hists);
	double per = percent(he_stats(he)->st_l1hit, total_stats(he)->st_l1hit);
	char buf[10];
	return scnprintf(hpp->buf, hpp->size, "%*s", width, PERC_STR(buf, per));
}

static int
percent_cl_stores_l1hit_color(struct perf_hpp_fmt *fmt, struct perf_hpp *hpp,
			       struct hist_entry *he)
{
	return percent_color(fmt, hpp, he, percent_st_l1hit);
}

static int
percent_cl_stores_l1miss_entry(struct perf_hpp_fmt *fmt, struct perf_hpp *hpp,
			        struct hist_entry *he)
{
	int width = c2c_width(fmt, hpp, he->hists);
	double per = PERCENT(he, st_l1miss);
	char buf[10];
	return scnprintf(hpp->buf, hpp->size, "%*s", width, PERC_STR(buf, per));
}

static int
percent_cl_stores_na_entry(struct perf_hpp_fmt *fmt, struct perf_hpp *hpp,
			    struct hist_entry *he)
{
	int width = c2c_width(fmt, hpp, he->hists);
	double per = PERCENT(he, st_na);
	char buf[10];
	return scnprintf(hpp->buf, hpp->size, "%*s", width, PERC_STR(buf, per));
}

static int
percent_rmt_hitm_entry(struct perf_hpp_fmt *fmt, struct perf_hpp *hpp,
		       struct hist_entry *he)
{
	int width = c2c_width(fmt, hpp, he->hists);
	double per = PERCENT(he, rmt_hitm);
	char buf[10];

	return scnprintf(hpp->buf, hpp->size, "%*s", width, PERC_STR(buf, per));
}

static int
percent_rmt_hitm_color(struct perf_hpp_fmt *fmt, struct perf_hpp *hpp,
		       struct hist_entry *he)
{
	return percent_color(fmt, hpp, he, percent_rmt_hitm);
}

static int64_t
percent_rmt_hitm_cmp(struct perf_hpp_fmt *fmt __maybe_unused,
		     struct hist_entry *left, struct hist_entry *right)
{
	double per_left;
	double per_right;

	per_left  = PERCENT(left, rmt_hitm);
	per_right = PERCENT(right, rmt_hitm);

	return per_left - per_right;
}

static int
percent_lcl_hitm_entry(struct perf_hpp_fmt *fmt, struct perf_hpp *hpp,
		       struct hist_entry *he)
{
	int width = c2c_width(fmt, hpp, he->hists);
	double per = PERCENT(he, lcl_hitm);
	char buf[10];

	return scnprintf(hpp->buf, hpp->size, "%*s", width, PERC_STR(buf, per));
}

static int
percent_lcl_hitm_color(struct perf_hpp_fmt *fmt, struct perf_hpp *hpp,
		       struct hist_entry *he)
{
	return percent_color(fmt, hpp, he, percent_lcl_hitm);
}

static int64_t
percent_lcl_hitm_cmp(struct perf_hpp_fmt *fmt __maybe_unused,
		     struct hist_entry *left, struct hist_entry *right)
{
	double per_left;
	double per_right;

	per_left  = PERCENT(left, lcl_hitm);
	per_right = PERCENT(right, lcl_hitm);

	return per_left - per_right;
}

static int
percent_lcl_peer_entry(struct perf_hpp_fmt *fmt, struct perf_hpp *hpp,
		       struct hist_entry *he)
{
	int width = c2c_width(fmt, hpp, he->hists);
	double per = PERCENT(he, lcl_peer);
	char buf[10];

	return scnprintf(hpp->buf, hpp->size, "%*s", width, PERC_STR(buf, per));
}

static int
percent_lcl_peer_color(struct perf_hpp_fmt *fmt, struct perf_hpp *hpp,
		       struct hist_entry *he)
{
	return percent_color(fmt, hpp, he, percent_lcl_peer);
}

static int64_t
percent_lcl_peer_cmp(struct perf_hpp_fmt *fmt __maybe_unused,
		     struct hist_entry *left, struct hist_entry *right)
{
	double per_left;
	double per_right;

	per_left  = PERCENT(left, lcl_peer);
	per_right = PERCENT(right, lcl_peer);

	return per_left - per_right;
}

static int
percent_rmt_peer_entry(struct perf_hpp_fmt *fmt, struct perf_hpp *hpp,
		       struct hist_entry *he)
{
	int width = c2c_width(fmt, hpp, he->hists);
	double per = PERCENT(he, rmt_peer);
	char buf[10];

	return scnprintf(hpp->buf, hpp->size, "%*s", width, PERC_STR(buf, per));
}

static int
percent_rmt_peer_color(struct perf_hpp_fmt *fmt, struct perf_hpp *hpp,
		       struct hist_entry *he)
{
	return percent_color(fmt, hpp, he, percent_rmt_peer);
}

static int64_t
percent_rmt_peer_cmp(struct perf_hpp_fmt *fmt __maybe_unused,
		     struct hist_entry *left, struct hist_entry *right)
{
	double per_left;
	double per_right;

	per_left  = PERCENT(left, rmt_peer);
	per_right = PERCENT(right, rmt_peer);

	return per_left - per_right;
}

static int
percent_stores_l1hit_entry(struct perf_hpp_fmt *fmt, struct perf_hpp *hpp,
			   struct hist_entry *he)
{
	int width = c2c_width(fmt, hpp, he->hists);
	double per = PERCENT(he, st_l1hit);
	char buf[10];

	return scnprintf(hpp->buf, hpp->size, "%*s", width, PERC_STR(buf, per));
}

static int
percent_stores_l1hit_color(struct perf_hpp_fmt *fmt, struct perf_hpp *hpp,
			   struct hist_entry *he)
{
	return percent_color(fmt, hpp, he, percent_st_l1hit);
}

static int64_t
percent_stores_l1hit_cmp(struct perf_hpp_fmt *fmt __maybe_unused,
			struct hist_entry *left, struct hist_entry *right)
{
	double per_left;
	double per_right;

	per_left  = PERCENT(left, st_l1hit);
	per_right = PERCENT(right, st_l1hit);

	return per_left - per_right;
}

static int
total_stores_entry(struct perf_hpp_fmt *fmt, struct perf_hpp *hpp,
                   struct hist_entry *he)
{
    struct c2c_hist_entry *c2c_he = container_of(he, struct c2c_hist_entry, he);
    /* Use stats.store as authoritative total stores */
    uint64_t total = (uint64_t)c2c_he->stats.store;
    int width = c2c_width(fmt, hpp, he->hists);

	/* Hide Stores for parent symbols */
	if (!he->parent_he) {
		return scnprintf(hpp->buf, hpp->size, "%-*s", width, "");
	}

    if (he->parent_he) {
        char out[32];
        char num[24];
        scnprintf(num, sizeof(num), "%" PRIu64, total);

        /* Consistent indentation with symbol hierarchy */
        if (he->parent_he->parent_he) {
            scnprintf(out, sizeof(out), "        %s", num);  /* 8 spaces for grandchildren */
        } else {
            scnprintf(out, sizeof(out), "      %s", num);  /* 6 spaces for children */
        }
        return scnprintf(hpp->buf, hpp->size, "%-*s", width, out);
    }

    return scnprintf(hpp->buf, hpp->size, "%-*" PRIu64, width, total);
}

static int
percent_stores_l1miss_entry(struct perf_hpp_fmt *fmt, struct perf_hpp *hpp,
			   struct hist_entry *he)
{
	int width = c2c_width(fmt, hpp, he->hists);
	double per = PERCENT(he, st_l1miss);
	char buf[10];

	return scnprintf(hpp->buf, hpp->size, "%*s", width, PERC_STR(buf, per));
}

static int
percent_stores_l1miss_color(struct perf_hpp_fmt *fmt, struct perf_hpp *hpp,
			    struct hist_entry *he)
{
	return percent_color(fmt, hpp, he, percent_st_l1miss);
}

static int64_t
percent_stores_l1miss_cmp(struct perf_hpp_fmt *fmt __maybe_unused,
			  struct hist_entry *left, struct hist_entry *right)
{
	double per_left;
	double per_right;

	per_left  = PERCENT(left, st_l1miss);
	per_right = PERCENT(right, st_l1miss);

	return per_left - per_right;
}

static int
percent_stores_na_entry(struct perf_hpp_fmt *fmt, struct perf_hpp *hpp,
			struct hist_entry *he)
{
	int width = c2c_width(fmt, hpp, he->hists);
	double per = PERCENT(he, st_na);
	char buf[10];

	return scnprintf(hpp->buf, hpp->size, "%*s", width, PERC_STR(buf, per));
}

static int
percent_stores_na_color(struct perf_hpp_fmt *fmt, struct perf_hpp *hpp,
			struct hist_entry *he)
{
	return percent_color(fmt, hpp, he, percent_st_na);
}

static int64_t
percent_stores_na_cmp(struct perf_hpp_fmt *fmt __maybe_unused,
		      struct hist_entry *left, struct hist_entry *right)
{
	double per_left;
	double per_right;

	per_left  = PERCENT(left, st_na);
	per_right = PERCENT(right, st_na);

	return per_left - per_right;
}

STAT_FN(lcl_dram)
STAT_FN(rmt_dram)

static int
pid_entry(struct perf_hpp_fmt *fmt, struct perf_hpp *hpp,
	  struct hist_entry *he)
{
	int width = c2c_width(fmt, hpp, he->hists);

	return scnprintf(hpp->buf, hpp->size, "%*d", width, thread__pid(he->thread));
}

static int64_t
pid_cmp(struct perf_hpp_fmt *fmt __maybe_unused,
	struct hist_entry *left, struct hist_entry *right)
{
	return thread__pid(left->thread) - thread__pid(right->thread);
}

static int64_t
empty_cmp(struct perf_hpp_fmt *fmt __maybe_unused,
	  struct hist_entry *left __maybe_unused,
	  struct hist_entry *right __maybe_unused)
{
	return 0;
}

static int display_metrics(struct perf_hpp *hpp, u32 val, u32 sum)
{
	int ret;

	if (sum != 0)
		ret = scnprintf(hpp->buf, hpp->size, "%5.1f%% ",
				percent(val, sum));
	else
		ret = scnprintf(hpp->buf, hpp->size, "%6s ", "n/a");

	return ret;
}

static int
node_entry(struct perf_hpp_fmt *fmt __maybe_unused, struct perf_hpp *hpp,
	   struct hist_entry *he)
{
	struct c2c_hist_entry *c2c_he;
	bool first = true;
	int node;
	int ret = 0;
	DECLARE_BITMAP(set, c2c.cpus_cnt);

	c2c_he = container_of(he, struct c2c_hist_entry, he);

	for (node = 0; node < c2c.nodes_cnt; node++) {
		bitmap_zero(set, c2c.cpus_cnt);
		bitmap_and(set, c2c_he->cpuset, c2c.nodes[node], c2c.cpus_cnt);

		if (bitmap_empty(set, c2c.cpus_cnt)) {
			if (c2c.node_info == 1) {
				ret = scnprintf(hpp->buf, hpp->size, "%21s", " ");
				advance_hpp(hpp, ret);
			}
			continue;
		}

		if (!first) {
			ret = scnprintf(hpp->buf, hpp->size, " ");
			advance_hpp(hpp, ret);
		}

		switch (c2c.node_info) {
		case 0:
			ret = scnprintf(hpp->buf, hpp->size, "%2d", node);
			advance_hpp(hpp, ret);
			break;
		case 1:
		{
			int num = bitmap_weight(set, c2c.cpus_cnt);
			struct c2c_stats *stats = &c2c_he->node_stats[node];

			ret = scnprintf(hpp->buf, hpp->size, "%2d{%2d ", node, num);
			advance_hpp(hpp, ret);

			switch (c2c.display) {
			case DISPLAY_RMT_HITM:
				ret = display_metrics(hpp, stats->rmt_hitm,
						      c2c_he->stats.rmt_hitm);
				break;
			case DISPLAY_LCL_HITM:
				ret = display_metrics(hpp, stats->lcl_hitm,
						      c2c_he->stats.lcl_hitm);
				break;
			case DISPLAY_TOT_HITM:
				ret = display_metrics(hpp, stats->tot_hitm,
						      c2c_he->stats.tot_hitm);
				break;
			case DISPLAY_SNP_PEER:
				ret = display_metrics(hpp, stats->tot_peer,
						      c2c_he->stats.tot_peer);
				break;
			default:
				break;
			}

			advance_hpp(hpp, ret);

			if (c2c_he->stats.store > 0) {
				ret = scnprintf(hpp->buf, hpp->size, "%5.1f%%}",
						percent(stats->store, c2c_he->stats.store));
			} else {
				ret = scnprintf(hpp->buf, hpp->size, "%6s}", "n/a");
			}

			advance_hpp(hpp, ret);
			break;
		}
		case 2:
			ret = scnprintf(hpp->buf, hpp->size, "%2d{", node);
			advance_hpp(hpp, ret);

			ret = bitmap_scnprintf(set, c2c.cpus_cnt, hpp->buf, hpp->size);
			advance_hpp(hpp, ret);

			ret = scnprintf(hpp->buf, hpp->size, "}");
			advance_hpp(hpp, ret);
			break;
		default:
			break;
		}

		first = false;
	}

	return 0;
}

static int
mean_entry(struct perf_hpp_fmt *fmt, struct perf_hpp *hpp,
	   struct hist_entry *he, double mean)
{
	int width = c2c_width(fmt, hpp, he->hists);
	char buf[10];

	scnprintf(buf, 10, "%6.0f", mean);
	return scnprintf(hpp->buf, hpp->size, "%*s", width, buf);
}

#define MEAN_ENTRY(__func, __val)						\
static int									\
__func(struct perf_hpp_fmt *fmt, struct perf_hpp *hpp, struct hist_entry *he)	\
{										\
	struct c2c_hist_entry *c2c_he;						\
	c2c_he = container_of(he, struct c2c_hist_entry, he);			\
	return mean_entry(fmt, hpp, he, avg_stats(&c2c_he->cstats.__val));	\
}

MEAN_ENTRY(mean_rmt_entry,  rmt_hitm);
MEAN_ENTRY(mean_lcl_entry,  lcl_hitm);
MEAN_ENTRY(mean_load_entry, load);
MEAN_ENTRY(mean_rmt_peer_entry, rmt_peer);
MEAN_ENTRY(mean_lcl_peer_entry, lcl_peer);

static int
cpucnt_entry(struct perf_hpp_fmt *fmt, struct perf_hpp *hpp,
	     struct hist_entry *he)
{
	struct c2c_hist_entry *c2c_he;
	int width = c2c_width(fmt, hpp, he->hists);
	char buf[10];

	c2c_he = container_of(he, struct c2c_hist_entry, he);

	scnprintf(buf, 10, "%d", bitmap_weight(c2c_he->cpuset, c2c.cpus_cnt));
	return scnprintf(hpp->buf, hpp->size, "%*s", width, buf);
}

static int
cl_idx_entry(struct perf_hpp_fmt *fmt, struct perf_hpp *hpp,
	     struct hist_entry *he)
{
	struct c2c_hist_entry *c2c_he;
	int width = c2c_width(fmt, hpp, he->hists);
	char buf[10];

	c2c_he = container_of(he, struct c2c_hist_entry, he);

	scnprintf(buf, 10, "%u", c2c_he->cacheline_idx);
	return scnprintf(hpp->buf, hpp->size, "%*s", width, buf);
}

static int
cl_idx_empty_entry(struct perf_hpp_fmt *fmt, struct perf_hpp *hpp,
		   struct hist_entry *he)
{
	int width = c2c_width(fmt, hpp, he->hists);

	return scnprintf(hpp->buf, hpp->size, "%*s", width, "");
}

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

#define HEADER_SPAN(__h0, __h1, __s)	\
	{				\
		.line[0] = {		\
			.text = __h0,	\
			.span = __s,	\
		},			\
		.line[1] = {		\
			.text = __h1,	\
		},			\
	}

#define HEADER_SPAN_LOW(__h)		\
	{				\
		.line[1] = {		\
			.text = __h,	\
		},			\
	}

static struct c2c_dimension dim_dcacheline = {
	.header		= HEADER_SPAN("--- Cacheline ----", "Address", 2),
	.name		= "dcacheline",
	.cmp		= dcacheline_cmp,
	.entry		= dcacheline_entry,
	.width		= 18,
};

static struct c2c_dimension dim_dcacheline_node = {
	.header		= HEADER_LOW("Node"),
	.name		= "dcacheline_node",
	.cmp		= empty_cmp,
	.entry		= dcacheline_node_entry,
	.width		= 4,
};

static struct c2c_dimension dim_dcacheline_count = {
	.header		= HEADER_LOW("PA cnt"),
	.name		= "dcacheline_count",
	.cmp		= empty_cmp,
	.entry		= dcacheline_node_count,
	.width		= 6,
};

static struct c2c_header header_offset_tui = HEADER_SPAN("-----", "Off", 2);

static struct c2c_dimension dim_offset = {
	.header		= HEADER_SPAN("--- Data address -", "Offset", 2),
	.name		= "offset",
	.cmp		= offset_cmp,
	.entry		= offset_entry,
	.width		= 18,
};

static struct c2c_dimension dim_offset_node = {
	.header		= HEADER_LOW("Node"),
	.name		= "offset_node",
	.cmp		= empty_cmp,
	.entry		= dcacheline_node_entry,
	.width		= 4,
};

static struct c2c_dimension dim_iaddr = {
	.header		= HEADER_LOW("Code address"),
	.name		= "iaddr",
	.cmp		= iaddr_cmp,
	.entry		= iaddr_entry,
	.width		= 26,
};

static struct c2c_dimension dim_tot_hitm = {
	.header		= HEADER_SPAN("------- Load Hitm -------", "Total", 2),
	.name		= "tot_hitm",
	.cmp		= tot_hitm_cmp,
	.entry		= tot_hitm_entry,
	.width		= 7,
};

static struct c2c_dimension dim_lcl_hitm = {
	.header		= HEADER_SPAN_LOW("LclHitm"),
	.name		= "lcl_hitm",
	.cmp		= lcl_hitm_cmp,
	.entry		= lcl_hitm_entry,
	.width		= 7,
};

static struct c2c_dimension dim_rmt_hitm = {
	.header		= HEADER_SPAN_LOW("RmtHitm"),
	.name		= "rmt_hitm",
	.cmp		= rmt_hitm_cmp,
	.entry		= rmt_hitm_entry,
	.width		= 7,
};

static struct c2c_dimension dim_tot_peer = {
	.header		= HEADER_SPAN("------- Load Peer -------", "Total", 2),
	.name		= "tot_peer",
	.cmp		= tot_peer_cmp,
	.entry		= tot_peer_entry,
	.width		= 7,
};

static struct c2c_dimension dim_lcl_peer = {
	.header		= HEADER_SPAN_LOW("Local"),
	.name		= "lcl_peer",
	.cmp		= lcl_peer_cmp,
	.entry		= lcl_peer_entry,
	.width		= 7,
};

static struct c2c_dimension dim_rmt_peer = {
	.header		= HEADER_SPAN_LOW("Remote"),
	.name		= "rmt_peer",
	.cmp		= rmt_peer_cmp,
	.entry		= rmt_peer_entry,
	.width		= 7,
};

static struct c2c_dimension dim_cl_rmt_hitm = {
	.header		= HEADER_SPAN("----- HITM -----", "Rmt", 1),
	.name		= "cl_rmt_hitm",
	.cmp		= rmt_hitm_cmp,
	.entry		= rmt_hitm_entry,
	.width		= 7,
};

static struct c2c_dimension dim_cl_lcl_hitm = {
	.header		= HEADER_SPAN_LOW("Lcl"),
	.name		= "cl_lcl_hitm",
	.cmp		= lcl_hitm_cmp,
	.entry		= lcl_hitm_entry,
	.width		= 7,
};

static struct c2c_dimension dim_cl_rmt_peer = {
	.header		= HEADER_SPAN("----- Peer -----", "Rmt", 1),
	.name		= "cl_rmt_peer",
	.cmp		= rmt_peer_cmp,
	.entry		= rmt_peer_entry,
	.width		= 7,
};

static struct c2c_dimension dim_cl_lcl_peer = {
	.header		= HEADER_SPAN_LOW("Lcl"),
	.name		= "cl_lcl_peer",
	.cmp		= lcl_peer_cmp,
	.entry		= lcl_peer_entry,
	.width		= 7,
};

static struct c2c_dimension dim_tot_stores = {
	.header		= HEADER_BOTH("Total", "Stores"),
	.name		= "tot_stores",
	.cmp		= store_cmp,
	.entry		= store_entry,
	.width		= 7,
};

static struct c2c_dimension dim_stores_l1hit = {
	.header		= HEADER_SPAN("--------- Stores --------", "L1Hit", 2),
	.name		= "stores_l1hit",
	.cmp		= st_l1hit_cmp,
	.entry		= st_l1hit_entry,
	.width		= 7,
};

static struct c2c_dimension dim_stores_l1miss = {
	.header		= HEADER_SPAN_LOW("L1Miss"),
	.name		= "stores_l1miss",
	.cmp		= st_l1miss_cmp,
	.entry		= st_l1miss_entry,
	.width		= 7,
};

static struct c2c_dimension dim_stores_na = {
	.header		= HEADER_SPAN_LOW("N/A"),
	.name		= "stores_na",
	.cmp		= st_na_cmp,
	.entry		= st_na_entry,
	.width		= 7,
};

static struct c2c_dimension dim_cl_stores_l1hit = {
	.header		= HEADER_SPAN("------- Store Refs ------", "L1 Hit", 2),
	.name		= "cl_stores_l1hit",
	.cmp		= st_l1hit_cmp,
	.entry		= st_l1hit_entry,
	.width		= 7,
};

static struct c2c_dimension dim_cl_stores_l1miss = {
	.header		= HEADER_SPAN_LOW("L1 Miss"),
	.name		= "cl_stores_l1miss",
	.cmp		= st_l1miss_cmp,
	.entry		= st_l1miss_entry,
	.width		= 7,
};

static struct c2c_dimension dim_cl_stores_na = {
	.header		= HEADER_SPAN_LOW("N/A"),
	.name		= "cl_stores_na",
	.cmp		= st_na_cmp,
	.entry		= st_na_entry,
	.width		= 7,
};

/* New percentage versions for cacheline view */
static struct c2c_dimension dim_percent_cl_stores_l1hit = {
	.header		= HEADER_SPAN("------ Store Refs % -----", "L1 Hit", 2),
	.name		= "percent_cl_stores_l1hit",
	.cmp		= st_l1hit_cmp,
	.entry		= percent_cl_stores_l1hit_entry,
	.color		= percent_cl_stores_l1hit_color,
	.width		= 7,
};

static struct c2c_dimension dim_percent_cl_stores_l1miss = {
	.header		= HEADER_SPAN_LOW("L1 Miss"),
	.name		= "percent_cl_stores_l1miss",
	.cmp		= percent_stores_l1miss_cmp,
	.entry		= percent_cl_stores_l1miss_entry,
	.width		= 7,
};

static struct c2c_dimension dim_percent_cl_stores_na = {
	.header		= HEADER_SPAN_LOW("N/A"),
	.name		= "percent_cl_stores_na",
	.cmp		= percent_stores_na_cmp,
	.entry		= percent_cl_stores_na_entry,
	.width		= 7,
};

static struct c2c_dimension dim_ld_fbhit = {
	.header		= HEADER_SPAN("----- Core Load Hit -----", "FB", 2),
	.name		= "ld_fbhit",
	.cmp		= ld_fbhit_cmp,
	.entry		= ld_fbhit_entry,
	.width		= 7,
};

static struct c2c_dimension dim_ld_l1hit = {
	.header		= HEADER_SPAN_LOW("L1"),
	.name		= "ld_l1hit",
	.cmp		= ld_l1hit_cmp,
	.entry		= ld_l1hit_entry,
	.width		= 7,
};

static struct c2c_dimension dim_ld_l2hit = {
	.header		= HEADER_SPAN_LOW("L2"),
	.name		= "ld_l2hit",
	.cmp		= ld_l2hit_cmp,
	.entry		= ld_l2hit_entry,
	.width		= 7,
};

static struct c2c_dimension dim_ld_llchit = {
	.header		= HEADER_SPAN("- LLC Load Hit --", "LclHit", 1),
	.name		= "ld_lclhit",
	.cmp		= ld_llchit_cmp,
	.entry		= ld_llchit_entry,
	.width		= 8,
};

static struct c2c_dimension dim_ld_rmthit = {
	.header		= HEADER_SPAN("- RMT Load Hit --", "RmtHit", 1),
	.name		= "ld_rmthit",
	.cmp		= rmt_hit_cmp,
	.entry		= rmt_hit_entry,
	.width		= 8,
};

static struct c2c_dimension dim_tot_recs = {
	.header		= HEADER_BOTH("Total", "records"),
	.name		= "tot_recs",
	.cmp		= tot_recs_cmp,
	.entry		= tot_recs_entry,
	.width		= 7,
};

static struct c2c_dimension dim_tot_loads = {
	.header		= HEADER_BOTH("Total", "Loads"),
	.name		= "tot_loads",
	.cmp		= tot_loads_cmp,
	.entry		= tot_loads_entry,
	.width		= 7,
};

static struct c2c_header percent_costly_snoop_header[] = {
	[DISPLAY_LCL_HITM] = HEADER_BOTH("Lcl", "Hitm"),
	[DISPLAY_RMT_HITM] = HEADER_BOTH("Rmt", "Hitm"),
	[DISPLAY_TOT_HITM] = HEADER_BOTH("Tot", "Hitm"),
	[DISPLAY_SNP_PEER] = HEADER_BOTH("Peer", "Snoop"),
};

static struct c2c_dimension dim_percent_costly_snoop = {
	.name		= "percent_costly_snoop",
	.cmp		= percent_costly_snoop_cmp,
	.entry		= percent_costly_snoop_entry,
	.color		= percent_costly_snoop_color,
	.width		= 7,
};

static struct c2c_dimension dim_percent_rmt_hitm = {
	.header		= HEADER_SPAN("----- HITM -----", "RmtHitm", 1),
	.name		= "percent_rmt_hitm",
	.cmp		= percent_rmt_hitm_cmp,
	.entry		= percent_rmt_hitm_entry,
	.color		= percent_rmt_hitm_color,
	.width		= 7,
};

static struct c2c_dimension dim_percent_lcl_hitm = {
	.header		= HEADER_SPAN_LOW("LclHitm"),
	.name		= "percent_lcl_hitm",
	.cmp		= percent_lcl_hitm_cmp,
	.entry		= percent_lcl_hitm_entry,
	.color		= percent_lcl_hitm_color,
	.width		= 7,
};

static struct c2c_dimension dim_percent_rmt_peer = {
	.header		= HEADER_SPAN("-- Peer Snoop --", "Rmt", 1),
	.name		= "percent_rmt_peer",
	.cmp		= percent_rmt_peer_cmp,
	.entry		= percent_rmt_peer_entry,
	.color		= percent_rmt_peer_color,
	.width		= 7,
};

static struct c2c_dimension dim_percent_lcl_peer = {
	.header		= HEADER_SPAN_LOW("Lcl"),
	.name		= "percent_lcl_peer",
	.cmp		= percent_lcl_peer_cmp,
	.entry		= percent_lcl_peer_entry,
	.color		= percent_lcl_peer_color,
	.width		= 7,
};

static struct c2c_dimension dim_percent_stores_l1hit = {
	.header		= HEADER_SPAN("------- Store Refs ------", "L1 Hit", 2),
	.name		= "percent_stores_l1hit",
	.cmp		= percent_stores_l1hit_cmp,
	.entry		= percent_stores_l1hit_entry,
	.color		= percent_stores_l1hit_color,
	.width		= 7,
};

static struct c2c_dimension dim_percent_stores_l1miss = {
	.header		= HEADER_SPAN_LOW("L1 Miss"),
	.name		= "percent_stores_l1miss",
	.cmp		= percent_stores_l1miss_cmp,
	.entry		= percent_stores_l1miss_entry,
	.color		= percent_stores_l1miss_color,
	.width		= 7,
};

static struct c2c_dimension dim_percent_stores_na = {
	.header		= HEADER_SPAN_LOW("N/A"),
	.name		= "percent_stores_na",
	.cmp		= percent_stores_na_cmp,
	.entry		= percent_stores_na_entry,
	.color		= percent_stores_na_color,
	.width		= 7,
};

static struct c2c_dimension dim_total_stores = {
    .header     = HEADER_LOW("Stores"),
    .name       = "total_stores",
    .cmp        = store_cmp,
    .entry      = total_stores_entry,
    .width      = 14,
};

/* Cacheline entry for symbol view */
static int
cacheline_symbol_entry(struct perf_hpp_fmt *fmt, struct perf_hpp *hpp,
                       struct hist_entry *he)
{
    uint64_t addr = 0;
    int width = c2c_width(fmt, hpp, he->hists);
    char buf[20];
    char out[40];

    /* Only display for cacheline entries - these are leaf nodes under related symbols */
    if (he->depth < 2 || !he->leaf) {
        return scnprintf(hpp->buf, hpp->size, "%-*s", width, "");
    }

    if (he->mem_info)
        addr = cl_address(mem_info__daddr(he->mem_info)->addr, chk_double_cl);

    /* Indent cacheline under child symbols to emphasize hierarchy */
    if (he->parent_he && he->parent_he->parent_he) {
        scnprintf(out, sizeof(out), "    %s", HEX_STR(buf, addr));
        return scnprintf(hpp->buf, hpp->size, "%-*s", width, out);
    }

    return scnprintf(hpp->buf, hpp->size, "%-*s", width, HEX_STR(buf, addr));
}

/* Cacheline column for symbol view */
static struct c2c_dimension dim_cacheline_symbol = {
    .header     = HEADER_LOW("Cacheline"),
    .name       = "cacheline_symbol",
    .cmp        = dcacheline_cmp,
    .entry      = cacheline_symbol_entry,
    .width      = 18,
};

static struct c2c_dimension dim_dram_lcl = {
	.header		= HEADER_SPAN("--- Load Dram ----", "Lcl", 1),
	.name		= "dram_lcl",
	.cmp		= lcl_dram_cmp,
	.entry		= lcl_dram_entry,
	.width		= 8,
};

static struct c2c_dimension dim_dram_rmt = {
	.header		= HEADER_SPAN_LOW("Rmt"),
	.name		= "dram_rmt",
	.cmp		= rmt_dram_cmp,
	.entry		= rmt_dram_entry,
	.width		= 8,
};

static struct c2c_dimension dim_pid = {
	.header		= HEADER_LOW("Pid"),
	.name		= "pid",
	.cmp		= pid_cmp,
	.entry		= pid_entry,
	.width		= 7,
};

static struct c2c_dimension dim_tid = {
	.header		= HEADER_LOW("Tid"),
	.name		= "tid",
	.se		= &sort_thread,
};

/* Custom symbol entry function to support expansion */
static int
symbol_entry(struct perf_hpp_fmt *fmt, struct perf_hpp *hpp,
	     struct hist_entry *he)
{
	struct c2c_fmt *c2c_fmt = container_of(fmt, struct c2c_fmt, fmt);
	struct c2c_dimension *dim = c2c_fmt->dim;
	size_t len = fmt->user_len;
	const char *symname = he->ms.sym ? he->ms.sym->name : "[unknown]";
	int width = c2c_width(fmt, hpp, he->hists);
	char buf[512];

	if (!len) {
		len = hists__col_len(he->hists, dim->se->se_width_idx);
		if (dim == &dim_symbol)
			len = symbol_width(he->hists, dim->se);
	}

	/* Hide Symbol for cacheline entries */
	if (he->depth == 2 && he->parent_he && he->parent_he->parent_he) {
		return scnprintf(hpp->buf, hpp->size, "%*s", width, "");
	}

	/* Build the symbol string with proper indentation and folding indicator */
	if (he->parent_he && he->parent_he->parent_he) {
		/* Cacheline grandchildren: no symbol display */
		return scnprintf(hpp->buf, hpp->size, "%*s", width, "");
	} else if (he->parent_he) {
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

static struct c2c_dimension dim_symbol = {
	.name		= "symbol",
	.se		= &sort_sym,
	.entry		= symbol_entry,
};

static struct c2c_dimension dim_dso = {
	.header		= HEADER_BOTH("Shared", "Object"),
	.name		= "dso",
	.se		= &sort_dso,
};

static struct c2c_dimension dim_node = {
	.name		= "node",
	.cmp		= empty_cmp,
	.entry		= node_entry,
	.width		= 4,
};

static struct c2c_dimension dim_mean_rmt = {
	.header		= HEADER_SPAN("---------- cycles ----------", "rmt hitm", 2),
	.name		= "mean_rmt",
	.cmp		= empty_cmp,
	.entry		= mean_rmt_entry,
	.width		= 8,
};

static struct c2c_dimension dim_mean_lcl = {
	.header		= HEADER_SPAN_LOW("lcl hitm"),
	.name		= "mean_lcl",
	.cmp		= empty_cmp,
	.entry		= mean_lcl_entry,
	.width		= 8,
};

static struct c2c_dimension dim_mean_load = {
	.header		= HEADER_SPAN_LOW("load"),
	.name		= "mean_load",
	.cmp		= empty_cmp,
	.entry		= mean_load_entry,
	.width		= 8,
};

static struct c2c_dimension dim_mean_rmt_peer = {
	.header		= HEADER_SPAN("---------- cycles ----------", "rmt peer", 2),
	.name		= "mean_rmt_peer",
	.cmp		= empty_cmp,
	.entry		= mean_rmt_peer_entry,
	.width		= 8,
};

static struct c2c_dimension dim_mean_lcl_peer = {
	.header		= HEADER_SPAN_LOW("lcl peer"),
	.name		= "mean_lcl_peer",
	.cmp		= empty_cmp,
	.entry		= mean_lcl_peer_entry,
	.width		= 8,
};

/* Entry functions for cycles calculations */
static int
cycles_rmt_hitm_entry(struct perf_hpp_fmt *fmt, struct perf_hpp *hpp,
		      struct hist_entry *he)
{
	struct c2c_hist_entry *c2c_he;
    int width = c2c_width(fmt, hpp, he->hists);
	uint64_t cycles;

	c2c_he = container_of(he, struct c2c_hist_entry, he);
    cycles = avg_stats(&c2c_he->cstats.rmt_hitm) * c2c_he->stats.rmt_hitm;

    if (he->parent_he) {
        /* Indent child metrics by 4 spaces */
        return scnprintf(hpp->buf, hpp->size, "    %llu", cycles);
    }

    return scnprintf(hpp->buf, hpp->size, "%*llu", width, cycles);
}

static int
cycles_lcl_hitm_entry(struct perf_hpp_fmt *fmt, struct perf_hpp *hpp,
		      struct hist_entry *he)
{
	struct c2c_hist_entry *c2c_he;
    int width = c2c_width(fmt, hpp, he->hists);
	uint64_t cycles;

	c2c_he = container_of(he, struct c2c_hist_entry, he);
    cycles = avg_stats(&c2c_he->cstats.lcl_hitm) * c2c_he->stats.lcl_hitm;

    if (he->parent_he) {
        char out[48];
        scnprintf(out, sizeof(out), "    %llu", cycles);
        return scnprintf(hpp->buf, hpp->size, "%-*s", width, out);
    }

    return scnprintf(hpp->buf, hpp->size, "%*llu", width, cycles);
}

static int
cycles_load_entry(struct perf_hpp_fmt *fmt, struct perf_hpp *hpp,
		  struct hist_entry *he)
{
	struct c2c_hist_entry *c2c_he;
    int width = c2c_width(fmt, hpp, he->hists);
	uint64_t cycles, other_load;

	c2c_he = container_of(he, struct c2c_hist_entry, he);
	other_load = c2c_he->stats.load - c2c_he->stats.rmt_hitm - c2c_he->stats.lcl_hitm;
    cycles = avg_stats(&c2c_he->cstats.load) * other_load;

    if (he->parent_he) {
        char out[48];
        scnprintf(out, sizeof(out), "    %llu", cycles);
        return scnprintf(hpp->buf, hpp->size, "%-*s", width, out);
    }

    return scnprintf(hpp->buf, hpp->size, "%*llu", width, cycles);
}

/* Helper function to calculate total cycles for a single c2c_hist_entry */
static uint64_t calculate_symbol_total_cycles(struct c2c_hist_entry *c2c_he)
{
	uint64_t cycles_rmt, cycles_lcl, cycles_load, other_load;

	/* Return cached value if available */
	if (c2c_he->total_cycles_valid)
		return c2c_he->total_cycles;

	cycles_rmt = avg_stats(&c2c_he->cstats.rmt_hitm) * c2c_he->stats.rmt_hitm;
	cycles_lcl = avg_stats(&c2c_he->cstats.lcl_hitm) * c2c_he->stats.lcl_hitm;
	other_load = c2c_he->stats.load - c2c_he->stats.rmt_hitm - c2c_he->stats.lcl_hitm;
	cycles_load = avg_stats(&c2c_he->cstats.load) * other_load;

	/* Cache the result */
	c2c_he->total_cycles = cycles_rmt + cycles_lcl + cycles_load;
	c2c_he->total_cycles_valid = true;

	return c2c_he->total_cycles;
}

static int
cycles_total_entry(struct perf_hpp_fmt *fmt, struct perf_hpp *hpp,
		   struct hist_entry *he)
{
	struct c2c_hist_entry *c2c_he;
    int width = c2c_width(fmt, hpp, he->hists);
	uint64_t total_cycles;

	c2c_he = container_of(he, struct c2c_hist_entry, he);
	total_cycles = calculate_symbol_total_cycles(c2c_he);

    if (he->parent_he) {
        return scnprintf(hpp->buf, hpp->size, "    %llu", total_cycles);
    }

    return scnprintf(hpp->buf, hpp->size, "%*llu", width, total_cycles);
}

static int
cnt_other_load_entry(struct perf_hpp_fmt *fmt, struct perf_hpp *hpp,
		     struct hist_entry *he)
{
	struct c2c_hist_entry *c2c_he;
    int width = c2c_width(fmt, hpp, he->hists);
	uint64_t other_load;

	c2c_he = container_of(he, struct c2c_hist_entry, he);
	other_load = c2c_he->stats.load - c2c_he->stats.rmt_hitm - c2c_he->stats.lcl_hitm;

    if (he->parent_he) {
        char out[48];
        scnprintf(out, sizeof(out), "    %llu", other_load);
        return scnprintf(hpp->buf, hpp->size, "%-*s", width, out);
    }

    return scnprintf(hpp->buf, hpp->size, "%*llu", width, other_load);
}

/* Function to calculate total cycles for all symbols for percentage calculation */
static uint64_t get_total_cycles_all_symbols(void)
{
	struct rb_node *nd;
	uint64_t total_cycles = 0;

	/* Use cached value if available to avoid O(n) scan per row */
	if (c2c.symbol_total_cycles_valid)
		return c2c.symbol_total_cycles;

	nd = rb_first_cached(&c2c.symbol_hists.hists.entries);
	while (nd) {
		struct hist_entry *he = rb_entry(nd, struct hist_entry, rb_node);
		struct c2c_hist_entry *c2c_he = container_of(he, struct c2c_hist_entry, he);

		total_cycles += calculate_symbol_total_cycles(c2c_he);
		nd = rb_next(nd);
	}

	c2c.symbol_total_cycles = total_cycles;
	c2c.symbol_total_cycles_valid = true;
	return total_cycles;
}

static int
cycles_percent_entry(struct perf_hpp_fmt *fmt, struct perf_hpp *hpp,
		     struct hist_entry *he)
{
	struct c2c_hist_entry *c2c_he;
	int width = c2c_width(fmt, hpp, he->hists);
	uint64_t symbol_cycles;
	uint64_t total_cycles;
	double percent;

	/* Hide Cycles Percent for child symbols and cachelines */
	if (he->parent_he) {
		return scnprintf(hpp->buf, hpp->size, "%*s", width, "");
	}

    c2c_he = container_of(he, struct c2c_hist_entry, he);
    symbol_cycles = calculate_symbol_total_cycles(c2c_he);

    total_cycles = get_total_cycles_all_symbols();
    percent = total_cycles > 0 ? (double)symbol_cycles / total_cycles * 100.0 : 0.0;

	return scnprintf(hpp->buf, hpp->size, "%*.2f%%", width-1, percent);
}

/* Comparison function for cycles percentage sorting */
static int64_t
cycles_percent_cmp(struct perf_hpp_fmt *fmt __maybe_unused,
		   struct hist_entry *left, struct hist_entry *right)
{
	struct c2c_hist_entry *c2c_left = container_of(left, struct c2c_hist_entry, he);
	struct c2c_hist_entry *c2c_right = container_of(right, struct c2c_hist_entry, he);
	uint64_t cycles_left, cycles_right;

	cycles_left = calculate_symbol_total_cycles(c2c_left);
	cycles_right = calculate_symbol_total_cycles(c2c_right);

	return cycles_left - cycles_right;
}

static struct c2c_dimension dim_cpucnt = {
	.header		= HEADER_BOTH("cpu", "cnt"),
	.name		= "cpucnt",
	.cmp		= empty_cmp,
	.entry		= cpucnt_entry,
	.width		= 8,
};

/* New dimensions for latency and cycles calculations with English naming */
static struct c2c_dimension dim_latency_rmt_hitm = {
	.header		= HEADER_SPAN("------ Latency (cycles) ------", "Rmt HITM", 2),
	.name		= "latency_rmt_hitm",
	.cmp		= empty_cmp,
	.entry		= mean_rmt_entry,
	.width		= 9,
};

static struct c2c_dimension dim_latency_lcl_hitm = {
	.header		= HEADER_SPAN_LOW("Lcl HITM"),
	.name		= "latency_lcl_hitm",
	.cmp		= empty_cmp,
	.entry		= mean_lcl_entry,
	.width		= 9,
};

static struct c2c_dimension dim_latency_load = {
	.header		= HEADER_SPAN_LOW("Load"),
	.name		= "latency_load",
	.cmp		= empty_cmp,
	.entry		= mean_load_entry,
	.width		= 9,
};

static struct c2c_dimension dim_cnt_rmt_hitm = {
	.header		= HEADER_SPAN("-------- Count --------", "Rmt HITM", 2),
	.name		= "cnt_rmt_hitm",
	.cmp		= empty_cmp,
	.entry		= rmt_hitm_entry,
	.width		= 9,
};

static struct c2c_dimension dim_cnt_lcl_hitm = {
	.header		= HEADER_SPAN_LOW("Lcl HITM"),
	.name		= "cnt_lcl_hitm",
	.cmp		= empty_cmp,
	.entry		= lcl_hitm_entry,
	.width		= 9,
};

static struct c2c_dimension dim_cnt_other_load = {
	.header		= HEADER_SPAN_LOW("Load"),
	.name		= "cnt_other_load",
	.cmp		= empty_cmp,
	.entry		= cnt_other_load_entry,
	.width		= 9,
};

static struct c2c_dimension dim_cycles_rmt_hitm = {
	.header		= HEADER_SPAN("------- Total Cycles -------", "Rmt HITM", 2),
	.name		= "cycles_rmt_hitm",
	.cmp		= empty_cmp,
	.entry		= cycles_rmt_hitm_entry,
	.width		= 10,
};

static struct c2c_dimension dim_cycles_lcl_hitm = {
	.header		= HEADER_SPAN_LOW("Lcl HITM"),
	.name		= "cycles_lcl_hitm",
	.cmp		= empty_cmp,
	.entry		= cycles_lcl_hitm_entry,
	.width		= 10,
};

static struct c2c_dimension dim_cycles_load = {
	.header		= HEADER_SPAN_LOW("Load"),
	.name		= "cycles_load",
	.cmp		= empty_cmp,
	.entry		= cycles_load_entry,
	.width		= 10,
};

static struct c2c_dimension dim_cycles_total = {
	.header		= HEADER_SPAN_LOW("Total"),
	.name		= "cycles_total",
	.cmp		= empty_cmp,
	.entry		= cycles_total_entry,
	.width		= 11,
};

static struct c2c_dimension dim_cycles_percent = {
	.header		= HEADER_BOTH("Cycles", "Percent"),
	.name		= "cycles_percent",
	.cmp		= cycles_percent_cmp,
	.entry		= cycles_percent_entry,
	.width		= 8,
};

static struct c2c_dimension dim_srcline = {
	.name		= "cl_srcline",
	.se		= &sort_srcline,
};

static struct c2c_dimension dim_dcacheline_idx = {
	.header		= HEADER_LOW("Index"),
	.name		= "cl_idx",
	.cmp		= empty_cmp,
	.entry		= cl_idx_entry,
	.width		= 5,
};

static struct c2c_dimension dim_dcacheline_num = {
	.header		= HEADER_LOW("Num"),
	.name		= "cl_num",
	.cmp		= empty_cmp,
	.entry		= cl_idx_entry,
	.width		= 5,
};

static struct c2c_dimension dim_dcacheline_num_empty = {
	.header		= HEADER_LOW("Num"),
	.name		= "cl_num_empty",
	.cmp		= empty_cmp,
	.entry		= cl_idx_empty_entry,
	.width		= 5,
};

static struct c2c_dimension *dimensions[] = {
	&dim_dcacheline,
	&dim_dcacheline_node,
	&dim_dcacheline_count,
	&dim_offset,
	&dim_offset_node,
	&dim_iaddr,
	&dim_tot_hitm,
	&dim_lcl_hitm,
	&dim_rmt_hitm,
	&dim_tot_peer,
	&dim_lcl_peer,
	&dim_rmt_peer,
	&dim_cl_lcl_hitm,
	&dim_cl_rmt_hitm,
	&dim_cl_lcl_peer,
	&dim_cl_rmt_peer,
	&dim_tot_stores,
	&dim_stores_l1hit,
	&dim_stores_l1miss,
	&dim_stores_na,
	&dim_cl_stores_l1hit,
	&dim_cl_stores_l1miss,
	&dim_cl_stores_na,
	&dim_percent_cl_stores_l1hit,
	&dim_percent_cl_stores_l1miss,
	&dim_percent_cl_stores_na,
	&dim_ld_fbhit,
	&dim_ld_l1hit,
	&dim_ld_l2hit,
	&dim_ld_llchit,
	&dim_ld_rmthit,
	&dim_tot_recs,
	&dim_tot_loads,
	&dim_percent_costly_snoop,
	&dim_percent_rmt_hitm,
	&dim_percent_lcl_hitm,
	&dim_percent_rmt_peer,
	&dim_percent_lcl_peer,
	&dim_percent_stores_l1hit,
	&dim_percent_stores_l1miss,
	&dim_percent_stores_na,
	&dim_total_stores,
	&dim_cacheline_symbol,
	&dim_dram_lcl,
	&dim_dram_rmt,
	&dim_pid,
	&dim_tid,
	&dim_symbol,
	&dim_dso,
	&dim_node,
	&dim_mean_rmt,
	&dim_mean_lcl,
	&dim_mean_rmt_peer,
	&dim_mean_lcl_peer,
	&dim_mean_load,
	&dim_cpucnt,
	&dim_latency_rmt_hitm,
	&dim_latency_lcl_hitm,
	&dim_latency_load,
	&dim_cnt_rmt_hitm,
	&dim_cnt_lcl_hitm,
	&dim_cnt_other_load,
	&dim_cycles_rmt_hitm,
	&dim_cycles_lcl_hitm,
	&dim_cycles_load,
	&dim_cycles_total,
	&dim_cycles_percent,
	&dim_srcline,
	&dim_dcacheline_idx,
	&dim_dcacheline_num,
	&dim_dcacheline_num_empty,
	NULL,
};

static void fmt_free(struct perf_hpp_fmt *fmt)
{
	struct c2c_fmt *c2c_fmt;

	c2c_fmt = container_of(fmt, struct c2c_fmt, fmt);
	free(c2c_fmt);
}

static bool fmt_equal(struct perf_hpp_fmt *a, struct perf_hpp_fmt *b)
{
	struct c2c_fmt *c2c_a = container_of(a, struct c2c_fmt, fmt);
	struct c2c_fmt *c2c_b = container_of(b, struct c2c_fmt, fmt);

	return c2c_a->dim == c2c_b->dim;
}

static struct c2c_dimension *get_dimension(const char *name)
{
	unsigned int i;

	for (i = 0; dimensions[i]; i++) {
		struct c2c_dimension *dim = dimensions[i];

		if (!strcmp(dim->name, name))
			return dim;
	}

	return NULL;
}

static int c2c_se_entry(struct perf_hpp_fmt *fmt, struct perf_hpp *hpp,
			struct hist_entry *he)
{
	struct c2c_fmt *c2c_fmt = container_of(fmt, struct c2c_fmt, fmt);
	struct c2c_dimension *dim = c2c_fmt->dim;
	size_t len = fmt->user_len;

	if (!len) {
		len = hists__col_len(he->hists, dim->se->se_width_idx);

		if (dim == &dim_symbol || dim == &dim_srcline)
			len = symbol_width(he->hists, dim->se);
	}

	/* Use custom symbol entry only in symbol view to avoid altering cacheline view alignment */
	if (dim == &dim_symbol && he->hists == &c2c.symbol_hists.hists)
		return symbol_entry(fmt, hpp, he);

	return dim->se->se_snprintf(he, hpp->buf, hpp->size, len);
}

static int64_t c2c_se_cmp(struct perf_hpp_fmt *fmt,
			  struct hist_entry *a, struct hist_entry *b)
{
	struct c2c_fmt *c2c_fmt = container_of(fmt, struct c2c_fmt, fmt);
	struct c2c_dimension *dim = c2c_fmt->dim;

	return dim->se->se_cmp(a, b);
}

static int64_t c2c_se_collapse(struct perf_hpp_fmt *fmt,
			       struct hist_entry *a, struct hist_entry *b)
{
	struct c2c_fmt *c2c_fmt = container_of(fmt, struct c2c_fmt, fmt);
	struct c2c_dimension *dim = c2c_fmt->dim;
	int64_t (*collapse_fn)(struct hist_entry *, struct hist_entry *);

	collapse_fn = dim->se->se_collapse ?: dim->se->se_cmp;
	return collapse_fn(a, b);
}

static struct c2c_fmt *get_format(const char *name)
{
	struct c2c_dimension *dim = get_dimension(name);
	struct c2c_fmt *c2c_fmt;
	struct perf_hpp_fmt *fmt;

	if (!dim)
		return NULL;

	c2c_fmt = zalloc(sizeof(*c2c_fmt));
	if (!c2c_fmt)
		return NULL;

	c2c_fmt->dim = dim;

	fmt = &c2c_fmt->fmt;
	INIT_LIST_HEAD(&fmt->list);
	INIT_LIST_HEAD(&fmt->sort_list);

	fmt->cmp	= dim->se ? c2c_se_cmp   : dim->cmp;
	fmt->sort	= dim->se ? c2c_se_cmp   : dim->cmp;
	fmt->color	= dim->se ? NULL	 : dim->color;
	fmt->entry	= dim->se ? c2c_se_entry : dim->entry;
	fmt->header	= c2c_header;
	fmt->width	= c2c_width;
	fmt->collapse	= dim->se ? c2c_se_collapse : dim->cmp;
	fmt->equal	= fmt_equal;
	fmt->free	= fmt_free;

	return c2c_fmt;
}

static int c2c_hists__init_output(struct perf_hpp_list *hpp_list, char *name,
				  struct perf_env *env __maybe_unused)
{
	struct c2c_fmt *c2c_fmt = get_format(name);
	int level = 0;

	if (!c2c_fmt) {
		reset_dimensions();
		return output_field_add(hpp_list, name, &level);
	}

	perf_hpp_list__column_register(hpp_list, &c2c_fmt->fmt);
	return 0;
}

static int c2c_hists__init_sort(struct perf_hpp_list *hpp_list, char *name, struct perf_env *env)
{
	struct c2c_fmt *c2c_fmt = get_format(name);
	struct c2c_dimension *dim;

	if (!c2c_fmt) {
		reset_dimensions();
		return sort_dimension__add(hpp_list, name, /*evlist=*/NULL, env, /*level=*/0);
	}

	dim = c2c_fmt->dim;
	if (dim == &dim_dso)
		hpp_list->dso = 1;

	perf_hpp_list__register_sort_field(hpp_list, &c2c_fmt->fmt);
	return 0;
}

#define PARSE_LIST(_list, _fn)							\
	do {									\
		char *tmp, *tok;						\
		ret = 0;							\
										\
		if (!_list)							\
			break;							\
										\
		for (tok = strtok_r((char *)_list, ", ", &tmp);			\
				tok; tok = strtok_r(NULL, ", ", &tmp)) {	\
			ret = _fn(hpp_list, tok, env);				\
			if (ret == -EINVAL) {					\
				pr_err("Invalid --fields key: `%s'", tok);	\
				break;						\
			} else if (ret == -ESRCH) {				\
				pr_err("Unknown --fields key: `%s'", tok);	\
				break;						\
			}							\
		}								\
	} while (0)

static int hpp_list__parse(struct perf_hpp_list *hpp_list,
			   const char *output_,
			   const char *sort_,
			   struct perf_env *env)
{
	char *output = output_ ? strdup(output_) : NULL;
	char *sort   = sort_   ? strdup(sort_) : NULL;
	int ret;

	PARSE_LIST(output, c2c_hists__init_output);
	PARSE_LIST(sort,   c2c_hists__init_sort);

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

static int c2c_hists__init(struct c2c_hists *hists,
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

	return hpp_list__parse(&hists->list, /*output=*/NULL, sort, env);
}

static int c2c_hists__reinit(struct c2c_hists *c2c_hists,
			     const char *output,
			     const char *sort,
			     struct perf_env *env)
{
	perf_hpp__reset_output_field(&c2c_hists->list);
	return hpp_list__parse(&c2c_hists->list, output, sort, env);
}

#define DISPLAY_LINE_LIMIT  0.001

static u8 filter_display(u32 val, u32 sum)
{
	if (sum == 0 || ((double)val / sum) < DISPLAY_LINE_LIMIT)
		return HIST_FILTER__C2C;

	return 0;
}

static bool he__display(struct hist_entry *he, struct c2c_stats *stats)
{
	struct c2c_hist_entry *c2c_he;

	if (c2c.show_all)
		return true;

	c2c_he = container_of(he, struct c2c_hist_entry, he);

	switch (c2c.display) {
	case DISPLAY_LCL_HITM:
		he->filtered = filter_display(c2c_he->stats.lcl_hitm,
					      stats->lcl_hitm);
		break;
	case DISPLAY_RMT_HITM:
		he->filtered = filter_display(c2c_he->stats.rmt_hitm,
					      stats->rmt_hitm);
		break;
	case DISPLAY_TOT_HITM:
		he->filtered = filter_display(c2c_he->stats.tot_hitm,
					      stats->tot_hitm);
		break;
	case DISPLAY_SNP_PEER:
		he->filtered = filter_display(c2c_he->stats.tot_peer,
					      stats->tot_peer);
		break;
	default:
		break;
	}

	return he->filtered == 0;
}

static inline bool is_valid_hist_entry(struct hist_entry *he)
{
	struct c2c_hist_entry *c2c_he;
	bool has_record = false;

	c2c_he = container_of(he, struct c2c_hist_entry, he);

	/* It's a valid entry if contains stores */
	if (c2c_he->stats.store)
		return true;

	switch (c2c.display) {
	case DISPLAY_LCL_HITM:
		has_record = !!c2c_he->stats.lcl_hitm;
		break;
	case DISPLAY_RMT_HITM:
		has_record = !!c2c_he->stats.rmt_hitm;
		break;
	case DISPLAY_TOT_HITM:
		has_record = !!c2c_he->stats.tot_hitm;
		break;
	case DISPLAY_SNP_PEER:
		has_record = !!c2c_he->stats.tot_peer;
	default:
		break;
	}

	return has_record;
}

static void set_node_width(struct c2c_hist_entry *c2c_he, int len)
{
	struct c2c_dimension *dim;

	dim = &c2c.hists == c2c_he->hists ?
	      &dim_dcacheline_node : &dim_offset_node;

	if (len > dim->width)
		dim->width = len;
}

static int set_nodestr(struct c2c_hist_entry *c2c_he)
{
	char buf[30];
	int len;

	if (c2c_he->nodestr)
		return 0;

	if (!bitmap_empty(c2c_he->nodeset, c2c.nodes_cnt)) {
		len = bitmap_scnprintf(c2c_he->nodeset, c2c.nodes_cnt,
				      buf, sizeof(buf));
	} else {
		len = scnprintf(buf, sizeof(buf), "N/A");
	}

	set_node_width(c2c_he, len);
	c2c_he->nodestr = strdup(buf);
	return c2c_he->nodestr ? 0 : -ENOMEM;
}

static void calc_width(struct c2c_hist_entry *c2c_he)
{
	struct c2c_hists *c2c_hists;

	c2c_hists = container_of(c2c_he->he.hists, struct c2c_hists, hists);
	hists__calc_col_len(&c2c_hists->hists, &c2c_he->he);
	set_nodestr(c2c_he);
}

static int filter_cb(struct hist_entry *he, void *arg __maybe_unused)
{
	struct c2c_hist_entry *c2c_he;

	c2c_he = container_of(he, struct c2c_hist_entry, he);

	if (c2c.show_src && !he->srcline)
		he->srcline = hist_entry__srcline(he);

	calc_width(c2c_he);

	if (!is_valid_hist_entry(he))
		he->filtered = HIST_FILTER__C2C;

	return 0;
}

static int resort_cl_cb(struct hist_entry *he, void *arg)
{
	struct perf_env *env = arg;
	struct c2c_hist_entry *c2c_he;
	struct c2c_hists *c2c_hists;
	bool display = he__display(he, &c2c.shared_clines_stats);

	c2c_he = container_of(he, struct c2c_hist_entry, he);
	c2c_hists = c2c_he->hists;

	if (display && c2c_hists) {
		static unsigned int idx;

		c2c_he->cacheline_idx = idx++;
		calc_width(c2c_he);

		c2c_hists__reinit(c2c_hists, c2c.cl_output, c2c.cl_resort, env);

		hists__collapse_resort(&c2c_hists->hists, NULL);
		hists__output_resort_cb(&c2c_hists->hists, NULL, filter_cb);
	}

	return 0;
}

static struct c2c_header header_node_0 = HEADER_LOW("Node");
static struct c2c_header header_node_1_hitms_stores =
		HEADER_LOW("Node{cpus %hitms %stores}");
static struct c2c_header header_node_1_peers_stores =
		HEADER_LOW("Node{cpus %peers %stores}");
static struct c2c_header header_node_2 = HEADER_LOW("Node{cpu list}");

static void setup_nodes_header(void)
{
	switch (c2c.node_info) {
	case 0:
		dim_node.header = header_node_0;
		break;
	case 1:
		if (c2c.display == DISPLAY_SNP_PEER)
			dim_node.header = header_node_1_peers_stores;
		else
			dim_node.header = header_node_1_hitms_stores;
		break;
	case 2:
		dim_node.header = header_node_2;
		break;
	default:
		break;
	}

	return;
}

static int setup_nodes(struct perf_session *session)
{
	struct numa_node *n;
	unsigned long **nodes;
	int node, idx;
	struct perf_cpu cpu;
	int *cpu2node;
	struct perf_env *env = perf_session__env(session);

	if (c2c.node_info > 2)
		c2c.node_info = 2;

	c2c.nodes_cnt = env->nr_numa_nodes;
	c2c.cpus_cnt  = env->nr_cpus_avail;

	n = env->numa_nodes;
	if (!n)
		return -EINVAL;

	nodes = zalloc(sizeof(unsigned long *) * c2c.nodes_cnt);
	if (!nodes)
		return -ENOMEM;

	c2c.nodes = nodes;

	cpu2node = zalloc(sizeof(int) * c2c.cpus_cnt);
	if (!cpu2node)
		return -ENOMEM;

	for (idx = 0; idx < c2c.cpus_cnt; idx++)
		cpu2node[idx] = -1;

	c2c.cpu2node = cpu2node;

	for (node = 0; node < c2c.nodes_cnt; node++) {
		struct perf_cpu_map *map = n[node].map;
		unsigned long *set;

		set = bitmap_zalloc(c2c.cpus_cnt);
		if (!set)
			return -ENOMEM;

		nodes[node] = set;

		perf_cpu_map__for_each_cpu_skip_any(cpu, idx, map) {
			__set_bit(cpu.cpu, set);

			if (WARN_ONCE(cpu2node[cpu.cpu] != -1, "node/cpu topology bug"))
				return -EINVAL;

			cpu2node[cpu.cpu] = node;
		}
	}

	setup_nodes_header();
	return 0;
}

#define HAS_HITMS(__h) ((__h)->stats.lcl_hitm || (__h)->stats.rmt_hitm)
#define HAS_PEER(__h) ((__h)->stats.lcl_peer || (__h)->stats.rmt_peer)

static int resort_shared_cl_cb(struct hist_entry *he, void *arg __maybe_unused)
{
	struct c2c_hist_entry *c2c_he;
	c2c_he = container_of(he, struct c2c_hist_entry, he);

	if (HAS_HITMS(c2c_he) || HAS_PEER(c2c_he)) {
		c2c.shared_clines++;
		c2c_add_stats(&c2c.shared_clines_stats, &c2c_he->stats);
	}

	return 0;
}

static int hists__iterate_cb(struct hists *hists, hists__resort_cb_t cb, void *arg)
{
	struct rb_node *next = rb_first_cached(&hists->entries);
	int ret = 0;

	while (next) {
		struct hist_entry *he;

		he = rb_entry(next, struct hist_entry, rb_node);
		ret = cb(he, arg);
		if (ret)
			break;
		next = rb_next(&he->rb_node);
	}

	return ret;
}

static void print_c2c__display_stats(FILE *out)
{
	int llc_misses;
	struct c2c_stats *stats = &c2c.hists.stats;

	llc_misses = get_load_llc_misses(stats);

	fprintf(out, "=================================================\n");
	fprintf(out, "            Trace Event Information              \n");
	fprintf(out, "=================================================\n");
	fprintf(out, "  Total records                     : %10d\n", stats->nr_entries);
	fprintf(out, "  Locked Load/Store Operations      : %10d\n", stats->locks);
	fprintf(out, "  Load Operations                   : %10d\n", stats->load);
	fprintf(out, "  Loads - uncacheable               : %10d\n", stats->ld_uncache);
	fprintf(out, "  Loads - IO                        : %10d\n", stats->ld_io);
	fprintf(out, "  Loads - Miss                      : %10d\n", stats->ld_miss);
	fprintf(out, "  Loads - no mapping                : %10d\n", stats->ld_noadrs);
	fprintf(out, "  Load Fill Buffer Hit              : %10d\n", stats->ld_fbhit);
	fprintf(out, "  Load L1D hit                      : %10d\n", stats->ld_l1hit);
	fprintf(out, "  Load L2D hit                      : %10d\n", stats->ld_l2hit);
	fprintf(out, "  Load LLC hit                      : %10d\n", stats->ld_llchit + stats->lcl_hitm);
	fprintf(out, "  Load Local HITM                   : %10d\n", stats->lcl_hitm);
	fprintf(out, "  Load Remote HITM                  : %10d\n", stats->rmt_hitm);
	fprintf(out, "  Load Remote HIT                   : %10d\n", stats->rmt_hit);
	fprintf(out, "  Load Local DRAM                   : %10d\n", stats->lcl_dram);
	fprintf(out, "  Load Remote DRAM                  : %10d\n", stats->rmt_dram);
	fprintf(out, "  Load MESI State Exclusive         : %10d\n", stats->ld_excl);
	fprintf(out, "  Load MESI State Shared            : %10d\n", stats->ld_shared);
	fprintf(out, "  Load LLC Misses                   : %10d\n", llc_misses);
	fprintf(out, "  Load access blocked by data       : %10d\n", stats->blk_data);
	fprintf(out, "  Load access blocked by address    : %10d\n", stats->blk_addr);
	fprintf(out, "  Load HIT Local Peer               : %10d\n", stats->lcl_peer);
	fprintf(out, "  Load HIT Remote Peer              : %10d\n", stats->rmt_peer);
	fprintf(out, "  LLC Misses to Local DRAM          : %10.1f%%\n", ((double)stats->lcl_dram/(double)llc_misses) * 100.);
	fprintf(out, "  LLC Misses to Remote DRAM         : %10.1f%%\n", ((double)stats->rmt_dram/(double)llc_misses) * 100.);
	fprintf(out, "  LLC Misses to Remote cache (HIT)  : %10.1f%%\n", ((double)stats->rmt_hit /(double)llc_misses) * 100.);
	fprintf(out, "  LLC Misses to Remote cache (HITM) : %10.1f%%\n", ((double)stats->rmt_hitm/(double)llc_misses) * 100.);
	fprintf(out, "  Store Operations                  : %10d\n", stats->store);
	fprintf(out, "  Store - uncacheable               : %10d\n", stats->st_uncache);
	fprintf(out, "  Store - no mapping                : %10d\n", stats->st_noadrs);
	fprintf(out, "  Store L1D Hit                     : %10d\n", stats->st_l1hit);
	fprintf(out, "  Store L1D Miss                    : %10d\n", stats->st_l1miss);
	fprintf(out, "  Store No available memory level   : %10d\n", stats->st_na);
	fprintf(out, "  No Page Map Rejects               : %10d\n", stats->nomap);
	fprintf(out, "  Unable to parse data source       : %10d\n", stats->noparse);
}

static void print_shared_cacheline_info(FILE *out)
{
	struct c2c_stats *stats = &c2c.shared_clines_stats;
	int hitm_cnt = stats->lcl_hitm + stats->rmt_hitm;

	fprintf(out, "=================================================\n");
	fprintf(out, "    Global Shared Cache Line Event Information   \n");
	fprintf(out, "=================================================\n");
	fprintf(out, "  Total Shared Cache Lines          : %10d\n", c2c.shared_clines);
	fprintf(out, "  Load HITs on shared lines         : %10d\n", stats->load);
	fprintf(out, "  Fill Buffer Hits on shared lines  : %10d\n", stats->ld_fbhit);
	fprintf(out, "  L1D hits on shared lines          : %10d\n", stats->ld_l1hit);
	fprintf(out, "  L2D hits on shared lines          : %10d\n", stats->ld_l2hit);
	fprintf(out, "  LLC hits on shared lines          : %10d\n", stats->ld_llchit + stats->lcl_hitm);
	fprintf(out, "  Load hits on peer cache or nodes  : %10d\n", stats->lcl_peer + stats->rmt_peer);
	fprintf(out, "  Locked Access on shared lines     : %10d\n", stats->locks);
	fprintf(out, "  Blocked Access on shared lines    : %10d\n", stats->blk_data + stats->blk_addr);
	fprintf(out, "  Store HITs on shared lines        : %10d\n", stats->store);
	fprintf(out, "  Store L1D hits on shared lines    : %10d\n", stats->st_l1hit);
	fprintf(out, "  Store No available memory level   : %10d\n", stats->st_na);
	fprintf(out, "  Total Merged records              : %10d\n", hitm_cnt + stats->store);
}

static void print_cacheline(struct c2c_hists *c2c_hists,
			    struct hist_entry *he_cl,
			    struct perf_hpp_list *hpp_list,
			    FILE *out)
{
	char bf[1000];
	struct perf_hpp hpp = {
		.buf            = bf,
		.size           = 1000,
	};
	static bool once;

	if (!once) {
		hists__fprintf_headers(&c2c_hists->hists, out);
		once = true;
	} else {
		fprintf(out, "\n");
	}

	fprintf(out, "  ----------------------------------------------------------------------\n");
	__hist_entry__snprintf(he_cl, &hpp, hpp_list);
	fprintf(out, "%s\n", bf);
	fprintf(out, "  ----------------------------------------------------------------------\n");

	hists__fprintf(&c2c_hists->hists, false, 0, 0, 0, out, false);
}

static void print_pareto(FILE *out, struct perf_env *env)
{
	struct perf_hpp_list hpp_list;
	struct rb_node *nd;
	int ret;
	const char *cl_output;

	if (c2c.display != DISPLAY_SNP_PEER)
		cl_output = "cl_num,"
			    "cl_rmt_hitm,"
			    "cl_lcl_hitm,"
			    "cl_stores_l1hit,"
			    "cl_stores_l1miss,"
			    "cl_stores_na,"
			    "dcacheline";
	else
		cl_output = "cl_num,"
			    "cl_rmt_peer,"
			    "cl_lcl_peer,"
			    "cl_stores_l1hit,"
			    "cl_stores_l1miss,"
			    "cl_stores_na,"
			    "dcacheline";

	perf_hpp_list__init(&hpp_list);
	ret = hpp_list__parse(&hpp_list, cl_output, /*evlist=*/NULL, env);

	if (WARN_ONCE(ret, "failed to setup sort entries\n"))
		return;

	nd = rb_first_cached(&c2c.hists.hists.entries);

	for (; nd; nd = rb_next(nd)) {
		struct hist_entry *he = rb_entry(nd, struct hist_entry, rb_node);
		struct c2c_hist_entry *c2c_he;

		if (he->filtered)
			continue;

		c2c_he = container_of(he, struct c2c_hist_entry, he);
		print_cacheline(c2c_he->hists, he, &hpp_list, out);
	}
}

static void print_c2c_info(FILE *out, struct perf_session *session)
{
	struct evlist *evlist = session->evlist;
	struct evsel *evsel;
	bool first = true;

	fprintf(out, "=================================================\n");
	fprintf(out, "                 c2c details                     \n");
	fprintf(out, "=================================================\n");

	evlist__for_each_entry(evlist, evsel) {
		fprintf(out, "%-36s: %s\n", first ? "  Events" : "", evsel__name(evsel));
		first = false;
	}
	fprintf(out, "  Cachelines sort on                : %s\n",
		display_str[c2c.display]);
	fprintf(out, "  Cacheline data grouping           : %s\n", c2c.cl_sort);
}

static void perf_c2c__hists_fprintf(FILE *out, struct perf_session *session)
{
	setup_pager();

	print_c2c__display_stats(out);
	fprintf(out, "\n");
	print_shared_cacheline_info(out);
	fprintf(out, "\n");
	print_c2c_info(out, session);

	if (c2c.stats_only)
		return;

	fprintf(out, "\n");
	fprintf(out, "=================================================\n");
	fprintf(out, "           Shared Data Cache Line Table          \n");
	fprintf(out, "=================================================\n");
	fprintf(out, "#\n");

	hists__fprintf(&c2c.hists.hists, true, 0, 0, 0, stdout, true);

	fprintf(out, "\n");
	fprintf(out, "=================================================\n");
	fprintf(out, "      Shared Cache Line Distribution Pareto      \n");
	fprintf(out, "=================================================\n");
	fprintf(out, "#\n");

	print_pareto(out, perf_session__env(session));

	/* Add symbol view in stdio mode */
	if (build_symbol_hists(perf_session__env(session)) == 0) {
		/* Count the number of entries */
		int symbol_entries = 0;
		struct rb_node *nd = rb_first_cached(&c2c.symbol_hists.hists.entries);
		while (nd) {
			struct hist_entry *he = rb_entry(nd, struct hist_entry, rb_node);
			if (!he->filtered)
				symbol_entries++;
			nd = rb_next(nd);
		}

		fprintf(out, "\n");
		fprintf(out, "Shared Data Symbols Table     (%d entries, sorted on Cycles Percent)\n", symbol_entries);
		fprintf(out, "#\n");

		hists__fprintf(&c2c.symbol_hists.hists, true, 0, 0, 0, stdout, true);
	}
}

#ifdef HAVE_SLANG_SUPPORT

/* Comparison function for sorting related symbols by stats.store descending */
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

struct grand_item {
	struct c2c_hist_entry *grand_c2c;
	struct hist_entry *grand_he;
	u64 stores;
};

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

/*
 * Helper function to validate and prepare for populating symbol children
 * Returns the c2c_hist_entry if valid, NULL otherwise
 */
static struct c2c_hist_entry *validate_and_prepare_entries(struct hist_entry *he)
{
	struct c2c_hist_entry *c2c_he;
	struct rb_root_cached *root;

	if (!he || !he->has_children)
		return NULL;

	root = &he->hroot_out;

	/* If already populated, return */
	if (!RB_EMPTY_ROOT(&root->rb_root))
		return NULL;

	c2c_he = container_of(he, struct c2c_hist_entry, he);
	if (!c2c_he)
		return NULL;

	/* Ensure related_symbols list is valid */
	if (list_empty(&c2c_he->related_symbols)) {
		he->has_children = false;  /* Reset inconsistent state */
		return NULL;
	}

	return c2c_he;
}

/*
 * Helper function to sort related symbols by stores descending
 * Returns allocated array of sorted related_symbol pointers, or NULL on error
 * Caller must free the returned array
 */
static struct related_symbol **sort_related_symbols_by_stores(struct c2c_hist_entry *c2c_he, int *num_rel_out)
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

/*
 * Helper function to create and initialize a symbol child entry
 * Returns the created hist_entry or NULL on error
 */
static struct hist_entry *create_symbol_child_entry(struct hist_entry *parent_he, 
						   struct related_symbol *rel_sym)
{
	struct c2c_hist_entry *child_c2c_he, *child_c2c;
	struct hist_entry *child_he;

	if (!rel_sym || !rel_sym->sym)
		return NULL;

	/* Allocate child hist_entry - simplified version for symbol children */
	child_c2c_he = zalloc(sizeof(*child_c2c_he));
	if (!child_c2c_he)
		return NULL;

	/* Initialize the related_symbols list */
	init_c2c_he_related_symbols(child_c2c_he);

	child_he = &child_c2c_he->he;

	/* Complete initialization - copy parent's map_symbol structure first */
	memcpy(&child_he->ms, &parent_he->ms, sizeof(struct map_symbol));
	/* Then override the symbol and address */
	child_he->ms.sym = rel_sym->sym;

	/* Create a synthetic mem_info to store the iaddr for proper display */
	if (parent_he->mem_info) {
		child_he->mem_info = memdup(parent_he->mem_info, sizeof(*parent_he->mem_info));
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
	child_he->hists = &c2c.symbol_hists.hists;
	child_he->filtered = false;  /* Make sure it's not filtered out */
	child_he->unfolded = false;
	child_he->has_children = false; /* Will be set to true only if grandchildren are added */
	child_he->has_no_entry = false;
	child_he->nr_rows = 0;
	child_he->row_offset = 0;

	/* Initialize stats properly */
	memset(&child_he->stat, 0, sizeof(child_he->stat));

	/* Set stat values based on c2c stats */
	child_he->stat.nr_events = rel_sym->stats.rmt_hitm + rel_sym->stats.lcl_hitm + 
				   rel_sym->stats.rmt_peer + rel_sym->stats.lcl_peer;
	child_he->stat.period = child_he->stat.nr_events;

	/* These weight fields are used by some columns */
	child_he->stat.weight1 = rel_sym->stats.rmt_hitm + rel_sym->stats.lcl_hitm;

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
	child_he->hpp_list = &c2c.symbol_hists.list;

	/* Copy c2c stats - this is what c2c columns use */
	child_c2c = container_of(child_he, struct c2c_hist_entry, he);
	memcpy(&child_c2c->stats, &rel_sym->stats, sizeof(rel_sym->stats));
	memcpy(&child_c2c->cstats, &rel_sym->cstats, sizeof(rel_sym->cstats));
	init_c2c_he_related_symbols(child_c2c);

	/* Build cacheline grandchildren under each related symbol child */
	child_c2c->hists = NULL;

	return child_he;
}

/* Cacheline-to-symbols index for performance optimization */
struct cacheline_symbol_entry {
	struct hist_entry *he_cl;
	struct c2c_hist_entry *c2c_he_cl;
	struct symbol_access {
		struct symbol *sym;
		uint64_t iaddr;
		struct c2c_stats stats;
		struct compute_stats cstats;
		struct symbol_access *next;
	} *symbol_accesses;
};

static struct cacheline_symbol_entry *cacheline_index = NULL;
static int cacheline_index_size = 0;
static int cacheline_index_capacity = 0;

/* Build index mapping cachelines to accessing symbols for performance */
static void build_cacheline_symbol_index(void)
{
	struct rb_node *nd_cl;
	int index = 0;

	/* Free existing index if any */
	if (cacheline_index) {
		for (int i = 0; i < cacheline_index_size; i++) {
			struct symbol_access *sa = cacheline_index[i].symbol_accesses;
			while (sa) {
				struct symbol_access *next = sa->next;
				free(sa);
				sa = next;
			}
		}
		free(cacheline_index);
		cacheline_index = NULL;
	}

	/* Build index in single pass with dynamic array growth */
	cacheline_index_size = 0;
	cacheline_index_capacity = 256; /* Start with reasonable size */
	cacheline_index = malloc(cacheline_index_capacity * sizeof(struct cacheline_symbol_entry));
	if (!cacheline_index) {
		cacheline_index_size = 0;
		return;
	}

	nd_cl = rb_first_cached(&c2c.hists.hists.entries);
	while (nd_cl) {
		struct hist_entry *he_cl;
		struct c2c_hist_entry *c2c_he_cl;
		
		/* Grow array if needed */
		if (index >= cacheline_index_capacity) {
			struct cacheline_symbol_entry *new_index;
			int cleanup_i;
			
			cacheline_index_capacity *= 2;
			new_index = realloc(cacheline_index,
				cacheline_index_capacity * sizeof(struct cacheline_symbol_entry));
			if (!new_index) {
				/* Cleanup on allocation failure */
				for (cleanup_i = 0; cleanup_i < cacheline_index_size; cleanup_i++) {
					struct symbol_access *sa = cacheline_index[cleanup_i].symbol_accesses;
					while (sa) {
						struct symbol_access *next = sa->next;
						free(sa);
						sa = next;
					}
				}
				free(cacheline_index);
				cacheline_index = NULL;
				cacheline_index_size = 0;
				return;
			}
			cacheline_index = new_index;
		}
		
		he_cl = rb_entry(nd_cl, struct hist_entry, rb_node);
		c2c_he_cl = container_of(he_cl, struct c2c_hist_entry, he);
		
		cacheline_index[index].he_cl = he_cl;
		cacheline_index[index].c2c_he_cl = c2c_he_cl;
		cacheline_index[index].symbol_accesses = NULL;

		/* Build symbol access list for this cacheline with proper aggregation */
		if (c2c_he_cl->hists && c2c_he_cl->hists->hists.entries.rb_root.rb_node) {
			struct rb_node *nd_d = rb_first_cached(&c2c_he_cl->hists->hists.entries);
			while (nd_d) {
				struct hist_entry *he_d = rb_entry(nd_d, struct hist_entry, rb_node);
				struct c2c_hist_entry *c2c_he_d = container_of(he_d, struct c2c_hist_entry, he);
				
				if (he_d->ms.sym && !he_d->filtered) {
					uint64_t iaddr_d = he_d->mem_info ? mem_info__iaddr(he_d->mem_info)->addr : he_d->ms.sym->start;
					struct symbol_access *cur = cacheline_index[index].symbol_accesses;
					bool merged = false;

					/* Check if we already have an entry for this symbol+iaddr combination */
					while (cur) {
						if (cur->sym == he_d->ms.sym && cur->iaddr == iaddr_d) {
							/* Aggregate statistics */
							c2c_add_stats(&cur->stats, &c2c_he_d->stats);
							c2c_add_cstats(&cur->cstats, &c2c_he_d->cstats);
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
							memcpy(&sa->stats, &c2c_he_d->stats, sizeof(sa->stats));
							memcpy(&sa->cstats, &c2c_he_d->cstats, sizeof(sa->cstats));
							sa->next = cacheline_index[index].symbol_accesses;
							cacheline_index[index].symbol_accesses = sa;
						}
					}
				}
				nd_d = rb_next(&he_d->rb_node);
			}
		}
		
		index++;
		cacheline_index_size = index;  /* Update size as we go */
		nd_cl = rb_next(nd_cl);
	}
}

/*
 * Optimized helper function to populate cacheline grandchildren for a symbol child entry
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
	for (int i = 0; i < cacheline_index_size; i++) {
		struct cacheline_symbol_entry *cl_entry = &cacheline_index[i];
		struct symbol_access *parent_access = NULL, *child_access = NULL;
		
		/* Check if both parent and child symbols access this cacheline */
		for (struct symbol_access *sa = cl_entry->symbol_accesses; sa; sa = sa->next) {
			if (symbol_name_equal(sa->sym, parent_he->ms.sym) && sa->iaddr == parent_iaddr) {
				parent_access = sa;
			} else if (symbol_name_equal(sa->sym, rel_sym->sym) && sa->iaddr == rel_sym->iaddr) {
				child_access = sa;
			}
			
			/* Early exit if both found */
			if (parent_access && child_access)
				break;
		}
		
		if (parent_access && child_access) {
			struct c2c_hist_entry *grand_c2c = zalloc(sizeof(*grand_c2c));
			struct hist_entry *grand_he;
			u64 child_stores = child_access->stats.store;
			
			if (!grand_c2c)
				break;
			
			init_c2c_he_related_symbols(grand_c2c);
			grand_he = &grand_c2c->he;
			/* copy ms from cacheline entry, but clear sym to print cacheline address */
			memcpy(&grand_he->ms, &cl_entry->he_cl->ms, sizeof(struct map_symbol));
			grand_he->ms.sym = NULL;
			grand_he->mem_info = mem_info__get(cl_entry->he_cl->mem_info);
			grand_he->thread = cl_entry->he_cl->thread;
			grand_he->cpumode = cl_entry->he_cl->cpumode;
			grand_he->cpu = cl_entry->he_cl->cpu;
			grand_he->socket = cl_entry->he_cl->socket;
			grand_he->parent_he = child_he;
			grand_he->depth = child_he->depth + 1;
			grand_he->leaf = true;
			grand_he->hists = &c2c.symbol_hists.hists;
			grand_he->filtered = false;
			grand_he->unfolded = false;
			grand_he->has_children = false;
			grand_he->nr_rows = 0;
			grand_he->row_offset = 0;
			memset(&grand_he->stat, 0, sizeof(grand_he->stat));
			grand_he->hroot_in = RB_ROOT_CACHED;
			grand_he->hroot_out = RB_ROOT_CACHED;
			INIT_LIST_HEAD(&grand_he->pairs.node);

			/* Initialize hierarchy pointers for grandchild */
			grand_he->hpp_list = &c2c.symbol_hists.list;
			
			/* Use pre-computed stats from index - eliminates redundant traversal */
			memcpy(&grand_c2c->stats, &child_access->stats, sizeof(grand_c2c->stats));
			memcpy(&grand_c2c->cstats, &child_access->cstats, sizeof(grand_c2c->cstats));
			/* stats for columns alignment */
			grand_he->stat.nr_events = grand_c2c->stats.lcl_hitm + grand_c2c->stats.rmt_hitm +
						grand_c2c->stats.lcl_peer + grand_c2c->stats.rmt_peer;
			grand_he->stat.period = grand_he->stat.nr_events;
			grand_he->stat.weight1 = grand_c2c->stats.rmt_hitm + grand_c2c->stats.lcl_hitm;

			/* Initialize stat_acc for grandchild if needed */
			if (symbol_conf.cumulate_callchain) {
				grand_he->stat_acc = calloc(1, sizeof(struct he_stat));
				if (grand_he->stat_acc)
					memcpy(grand_he->stat_acc, &grand_he->stat, sizeof(struct he_stat));
			}

			/* push into temp array */
			if (items_cnt == items_cap) {
				int new_cap = items_cap ? items_cap * 2 : 8;
				struct grand_item *ni = realloc(items, new_cap * sizeof(*items));
				if (!ni) {
					free(grand_c2c);
					break;
				}
				items = ni; items_cap = new_cap;
			}
			items[items_cnt].grand_c2c = grand_c2c;
			items[items_cnt].grand_he = grand_he;
			items[items_cnt].stores = child_stores;
			items_cnt++;
		}
	}

	/* sort by stores desc using qsort */
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

static void populate_symbol_children(struct hist_entry *he)
{
	struct c2c_hist_entry *c2c_he;
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

/*
 * Build symbol associations based on cacheline sharing
 * 
 * Logic: When multiple symbols access the same cacheline (false sharing),
 * they are considered related. The association count increases by 1 for
 * each shared cacheline between two symbols.
 */
static void build_symbol_associations(void)
{
	struct rb_node *nd_sym;
	struct hist_entry *he_sym;
	struct c2c_hist_entry *c2c_he_sym;
	int associations_found = 0;
	int cl_idx;

	/*
	 * Algorithm:
	 * 1. For each cacheline that has HITM events
	 * 2. Look at its detailed access records
	 * 3. Find all symbols that accessed it with HITM
	 * 4. Create associations between these symbols
	 */

	/* Phase 1: Use cached index to find symbol conflicts efficiently */
	/* Build cacheline index if not available */
	if (!cacheline_index) {
		build_cacheline_symbol_index();
	}

	/* Iterate through cached index instead of rb-tree */
	for (cl_idx = 0; cl_idx < cacheline_index_size; cl_idx++) {
		struct cacheline_symbol_entry *cl_entry = &cacheline_index[cl_idx];
		struct c2c_hist_entry *c2c_he_cl = cl_entry->c2c_he_cl;
		struct symbol_addr_pair {
			struct symbol *sym;
			uint64_t iaddr;
		} *symbols_with_hitm = NULL;
		int symbol_count = 0;
		int symbol_capacity = 0;
		struct symbol_access *sa;
		int i, j;

		/* Skip cachelines without HITM events */
		if ((c2c_he_cl->stats.rmt_hitm + c2c_he_cl->stats.lcl_hitm) == 0) {
			continue;
		}

		/* Collect all (symbol, address) pairs that accessed this cacheline with HITM */
		for (sa = cl_entry->symbol_accesses; sa; sa = sa->next) {
			if (sa->sym && (sa->stats.rmt_hitm + sa->stats.lcl_hitm) > 0) {
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
						symbol_capacity = symbol_capacity ? symbol_capacity * 2 : 4;
						new_symbols = realloc(symbols_with_hitm,
								    symbol_capacity * sizeof(struct symbol_addr_pair));
						if (!new_symbols) {
							/* Memory allocation failed, skip this symbol */
							continue;
						}
						symbols_with_hitm = new_symbols;
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
				nd_sym = rb_first_cached(&c2c.symbol_hists.hists.entries);
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
                            c2c_he_sym = container_of(he_sym, struct c2c_hist_entry, he);

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
                                            rel_sym->association_count++;
                                            break;
                                        }
                                    }

                                    if (!exists) {
                                        rel_sym = zalloc(sizeof(*rel_sym));
                                        if (rel_sym) {
                                            rel_sym->sym = symbols_with_hitm[j].sym;
                                            rel_sym->iaddr = symbols_with_hitm[j].iaddr;
                                            rel_sym->association_count = 1;
                                            /* zalloc already zeros memory, no need for memset */
                                            list_add_tail(&rel_sym->list, &c2c_he_sym->related_symbols);
                                            associations_found++;
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
	nd_sym = rb_first_cached(&c2c.symbol_hists.hists.entries);
	while (nd_sym) {
		struct related_symbol *rel_sym;

		he_sym = rb_entry(nd_sym, struct hist_entry, rb_node);
		c2c_he_sym = container_of(he_sym, struct c2c_hist_entry, he);

		/* For each related symbol, aggregate stats from shared cachelines using cached index */
		list_for_each_entry(rel_sym, &c2c_he_sym->related_symbols, list) {
			/* Precompute parent's iaddr once */
			uint64_t parent_iaddr = he_sym->mem_info ?
				mem_info__iaddr(he_sym->mem_info)->addr :
				(he_sym->ms.sym ? he_sym->ms.sym->start : 0);

			/* Use cached index instead of nested rb_next loops */
			for (cl_idx = 0; cl_idx < cacheline_index_size; cl_idx++) {
				struct cacheline_symbol_entry *cl_entry = &cacheline_index[cl_idx];
				struct symbol_access *sa;
				bool target_found = false;

				/* First pass: check if target symbol accessed this cacheline */
				for (sa = cl_entry->symbol_accesses; sa; sa = sa->next) {
					if (symbol_name_equal(sa->sym, he_sym->ms.sym) && sa->iaddr == parent_iaddr) {
						target_found = true;
						break;
					}
				}

				if (!target_found)
					continue;

				/* Second pass: aggregate related symbol stats */
				for (sa = cl_entry->symbol_accesses; sa; sa = sa->next) {
					if (symbol_name_equal(sa->sym, rel_sym->sym) && sa->iaddr == rel_sym->iaddr) {
						c2c_add_stats(&rel_sym->stats, &sa->stats);
						c2c_add_cstats(&rel_sym->cstats, &sa->cstats);
					}
				}
			}
		}

		nd_sym = rb_next(nd_sym);
	}

	/* Phase 3: Create child entries for symbols with associations */
	nd_sym = rb_first_cached(&c2c.symbol_hists.hists.entries);
	while (nd_sym) {
		he_sym = rb_entry(nd_sym, struct hist_entry, rb_node);
		if (he_sym->has_children) {
			populate_symbol_children(he_sym);
		}
		nd_sym = rb_next(nd_sym);
	}
}

/* Cleanup function for the cacheline symbol index */
static void cleanup_cacheline_symbol_index(void)
{
	if (cacheline_index) {
		for (int i = 0; i < cacheline_index_size; i++) {
			struct symbol_access *sa = cacheline_index[i].symbol_accesses;
			while (sa) {
				struct symbol_access *next = sa->next;
				free(sa);
				sa = next;
			}
		}
		free(cacheline_index);
		cacheline_index = NULL;
		cacheline_index_size = 0;
		cacheline_index_capacity = 0;
	}
}

/* Structure to aggregate symbol stats */
struct symbol_entry {
	uint64_t iaddr;
	struct symbol *sym;
	struct map *map;
	struct maps *maps;
	struct c2c_stats stats;
	struct compute_stats cstats;
	uint64_t samples;
	struct symbol_entry *next;
};

/* Simple hash table for symbol aggregation */
#define SYMBOL_HASH_SIZE 1024
static struct symbol_entry *symbol_hash[SYMBOL_HASH_SIZE];

static unsigned int symbol_hash_func(uint64_t iaddr, struct symbol *sym)
{
	unsigned int name_hash = 0;
	const char *name;
	
	if (!sym)
		return hash_64(iaddr, 10);  /* log2(1024) = 10 */
	
	/* Use kernel's hash_32 for better string hashing */
	name = sym->name;
	while (*name) {
		name_hash = hash_32(name_hash + *name, 16);
		name++;
	}
	
	return hash_64(iaddr ^ name_hash, 10);
}

static struct symbol_entry *find_or_create_symbol_entry(uint64_t iaddr, struct symbol *sym, struct map *map, struct maps *maps)
{
	unsigned int hash = symbol_hash_func(iaddr, sym);
	struct symbol_entry *entry;

	/* Search for existing entry */
	for (entry = symbol_hash[hash]; entry; entry = entry->next) {
		if (entry->iaddr == iaddr && 
		    symbol_name_equal(entry->sym, sym)) {
			return entry;
		}
	}

	/* Create new entry */
	entry = zalloc(sizeof(*entry));
	if (!entry)
		return NULL;

	entry->iaddr = iaddr;
	entry->sym = sym;
	entry->map = map;
	entry->maps = maps;
	entry->samples = 0;

	/* Add to hash table */
	entry->next = symbol_hash[hash];
	symbol_hash[hash] = entry;

	return entry;
}

static int build_symbol_hists(struct perf_env *env)
{
	struct rb_node *next;
	struct hist_entry *he_sym;
	struct c2c_hist_entry *c2c_he_sym;
	struct addr_location al;
	struct perf_sample sample = {};
	struct thread *synthetic_thread = NULL;
	struct symbol_entry *entry;
	int ret, hash_i;

	/* Invalidate cached total cycles before (re)building symbol histograms */
	c2c.symbol_total_cycles_valid = false;
	c2c.symbol_total_cycles = 0;

	next = rb_first_cached(&c2c.hists.hists.entries);

	/* Initialize symbol hash table */
	memset(symbol_hash, 0, sizeof(symbol_hash));

	/* Initialize symbol hists with sort by iaddr (code address) and symbol */
	ret = c2c_hists__init(&c2c.symbol_hists, "iaddr,symbol", 2, env);
	if (ret)
		return ret;

	/* Setup output fields for symbol view - sorted by cycles percentage (descending) */
    ret = c2c_hists__reinit(&c2c.symbol_hists,
        "cycles_percent,total_stores,iaddr,symbol,cacheline_symbol",
        "cycles_percent", env);
	if (ret)
		return ret;

	/* Get first thread for consistent aggregation */
	if (next) {
		struct hist_entry *first_he = rb_entry(next, struct hist_entry, rb_node);
		synthetic_thread = first_he->thread;
	}

	/* First pass: aggregate all stats by (iaddr, symbol) using optimized cached index */
	/* Build cacheline index if not already built for efficiency */
	if (!cacheline_index) {
		build_cacheline_symbol_index();
	}

	/* Use cached index instead of nested rb_next loops */
	for (hash_i = 0; hash_i < cacheline_index_size; hash_i++) {
		struct cacheline_symbol_entry *cl_entry = &cacheline_index[hash_i];
		struct symbol_access *sa = cl_entry->symbol_accesses;
		
		/* Process all symbol accesses for this cacheline */
		while (sa) {
			struct symbol *sym_cl = sa->sym;
			
			if (sym_cl) {
				uint64_t iaddr_cl = sa->iaddr ? sa->iaddr : sym_cl->start;
				
				/* Find map info from the original hist entry */
				struct hist_entry *he_cl = cl_entry->he_cl;
				struct map *map_cl = he_cl ? he_cl->ms.map : NULL;
				struct maps *maps_cl = he_cl ? he_cl->ms.maps : NULL;

				entry = find_or_create_symbol_entry(iaddr_cl, sym_cl, map_cl, maps_cl);
				if (entry) {
					c2c_add_stats(&entry->stats, &sa->stats);
					c2c_add_cstats(&entry->cstats, &sa->cstats);
					entry->samples++;
				}
			}
			sa = sa->next;
		}
	}

	/* Second pass: create histogram entries for all unique (iaddr, symbol) combinations */
	for (hash_i = 0; hash_i < SYMBOL_HASH_SIZE; hash_i++) {
		for (entry = symbol_hash[hash_i]; entry; entry = entry->next) {
			/* Create mem_info with proper instruction address for display */
			struct mem_info *mi_display = mem_info__new();
			if (mi_display) {
				mem_info__iaddr(mi_display)->addr = entry->iaddr;
				mem_info__iaddr(mi_display)->ms.maps = entry->maps;
				mem_info__iaddr(mi_display)->ms.map = entry->map;
				mem_info__iaddr(mi_display)->ms.sym = entry->sym;
				/* Set data address to 0 for consistent display */
				mem_info__daddr(mi_display)->addr = 0;
			}

			/* Create consistent address location for symbol aggregation */
			addr_location__init(&al);
			al.thread = synthetic_thread;
			al.maps = entry->maps;
			al.map = entry->map;
			al.sym = entry->sym;
			al.addr = entry->iaddr;
			al.level = PERF_RECORD_MISC_KERNEL;
			al.cpumode = PERF_RECORD_MISC_KERNEL;
			al.cpu = 0;
			al.socket = 0;
			al.filtered = 0;

			/* Create sample with consistent values */
			sample.period = 1;
			sample.weight = 1;
			sample.ip = entry->iaddr;
			sample.pid = synthetic_thread ? thread__pid(synthetic_thread) : 0;
			sample.tid = synthetic_thread ? thread__tid(synthetic_thread) : 0;
			sample.cpu = 0;
			sample.time = 0;
			sample.addr = 0;
			sample.id = 0;

			/* Add entry to histogram with mem_info for proper address display */
			he_sym = hists__add_entry_ops(&c2c.symbol_hists.hists,
						      &c2c_entry_ops,
						      &al, NULL, NULL, mi_display, NULL,
						      &sample, true);

			addr_location__exit(&al);
			if (mi_display)
				mem_info__put(mi_display);

            if (he_sym) {
				c2c_he_sym = container_of(he_sym, struct c2c_hist_entry, he);

				/* Copy aggregated stats to the symbol entry */
				c2c_he_sym->stats = entry->stats;
				c2c_he_sym->cstats = entry->cstats;
				c2c_add_stats(&c2c.symbol_hists.stats, &entry->stats);

                hists__inc_nr_samples(&c2c.symbol_hists.hists, he_sym->filtered);
                he_sym->hpp_list = &c2c.symbol_hists.list;
			}
		}
	}

	/* Clean up hash table */
	for (hash_i = 0; hash_i < SYMBOL_HASH_SIZE; hash_i++) {
		struct symbol_entry *curr = symbol_hash[hash_i];
		while (curr) {
			struct symbol_entry *next_entry = curr->next;
			free(curr);
			curr = next_entry;
		}
		symbol_hash[hash_i] = NULL;
	}

	/* Resort symbol hists */
	hists__collapse_resort(&c2c.symbol_hists.hists, NULL);
	hists__output_resort(&c2c.symbol_hists.hists, NULL);

	/* Enable hierarchy support for symbol view to allow multi-level display */
	c2c.symbol_hists.hists.symbol_filter_str = NULL;
	c2c.symbol_hists.hists.socket_filter = -1;

	/* Initialize the hist browser fields needed for hierarchy */
	c2c.symbol_hists.hists.nr_hpp_node = 0;

	/* Build symbol associations after hists are complete */
	build_symbol_associations();

	/* Clean up the cacheline index after use */
	cleanup_cacheline_symbol_index();

	/* Precompute and cache total cycles to speed up percent rendering */
	(void)get_total_cycles_all_symbols();

	return 0;
}

static void c2c_browser__update_nr_entries(struct hist_browser *hb)
{
	u64 nr_entries = 0;
	struct rb_node *nd = rb_first_cached(&hb->hists->entries);

	while (nd) {
		struct hist_entry *he = rb_entry(nd, struct hist_entry, rb_node);

		if (!he->filtered)
			nr_entries++;

		nd = rb_next(nd);
	}

	hb->nr_non_filtered_entries = nr_entries;
}

struct c2c_cacheline_browser {
	struct hist_browser	 hb;
	struct hist_entry	*he;
};

static int
perf_c2c_cacheline_browser__title(struct hist_browser *browser,
				  char *bf, size_t size)
{
	struct c2c_cacheline_browser *cl_browser;
	struct hist_entry *he;
	uint64_t addr = 0;

	cl_browser = container_of(browser, struct c2c_cacheline_browser, hb);
	he = cl_browser->he;

	if (he->mem_info)
		addr = cl_address(mem_info__daddr(he->mem_info)->addr, chk_double_cl);

	scnprintf(bf, size, "Cacheline 0x%lx", addr);
	return 0;
}

static struct c2c_cacheline_browser*
c2c_cacheline_browser__new(struct hists *hists, struct hist_entry *he)
{
	struct c2c_cacheline_browser *browser;

	browser = zalloc(sizeof(*browser));
	if (browser) {
		hist_browser__init(&browser->hb, hists);
		browser->hb.c2c_filter	= true;
		browser->hb.title	= perf_c2c_cacheline_browser__title;
		browser->he		= he;
	}

	return browser;
}

static int perf_c2c__browse_cacheline(struct hist_entry *he)
{
	struct c2c_hist_entry *c2c_he;
	struct c2c_hists *c2c_hists;
	struct c2c_cacheline_browser *cl_browser;
	struct hist_browser *browser;
	int key = -1;
	static const char help[] =
	" ENTER         Toggle callchains (if present) \n"
	" n             Toggle Node details info \n"
	" s             Toggle full length of symbol and source line columns \n"
	" q             Return back to cacheline list \n";

	if (!he)
		return 0;

	/* Display compact version first. */
	c2c.symbol_full = false;

	c2c_he = container_of(he, struct c2c_hist_entry, he);
	c2c_hists = c2c_he->hists;

	cl_browser = c2c_cacheline_browser__new(&c2c_hists->hists, he);
	if (cl_browser == NULL)
		return -1;

	browser = &cl_browser->hb;

	/* reset abort key so that it can get Ctrl-C as a key */
	SLang_reset_tty();
	SLang_init_tty(0, 0, 0);

	c2c_browser__update_nr_entries(browser);

	while (1) {
		key = hist_browser__run(browser, "? - help", true, 0);

		switch (key) {
		case 's':
			c2c.symbol_full = !c2c.symbol_full;
			break;
		case 'n':
			c2c.node_info = (c2c.node_info + 1) % 3;
			setup_nodes_header();
			break;
		case 'q':
			goto out;
		case '?':
			ui_browser__help_window(&browser->b, help);
			break;
		default:
			break;
		}
	}

out:
	free(cl_browser);
	return 0;
}

static int perf_c2c_browser__title(struct hist_browser *browser,
				   char *bf, size_t size)
{
	scnprintf(bf, size,
		  "Shared Data Cache Line Table     "
		  "(%lu entries, sorted on %s)",
		  browser->nr_non_filtered_entries,
		  display_str[c2c.display]);
	return 0;
}

/* Custom title for pair-filtered Shared Data Cache Line Table */
static int perf_c2c_symbol_browser__title(struct hist_browser *browser,
					  char *bf, size_t size)
{
	scnprintf(bf, size,
		  "Shared Data Symbols Table     "
		  "(%lu entries, sorted on %s)",
		  browser->nr_non_filtered_entries,
		  "Cycles Percent");
	return 0;
}

static struct hist_browser*
perf_c2c_browser__new(struct hists *hists)
{
	struct hist_browser *browser = hist_browser__new(hists);

	if (browser) {
		browser->title = perf_c2c_browser__title;
		browser->c2c_filter = true;
	}

	return browser;
}

/*
 * Browse a specific cacheline showing only entries for the parent and child symbols
 */
static int perf_c2c__browse_symbol_pair_cacheline(struct hist_entry *he_grandchild)
{
    struct hist_entry *he_child, *he_parent;
    struct c2c_hist_entry *c2c_he_cl;
    struct c2c_hists *c2c_hists_cl;
    struct hist_browser *cl_browser;
    struct c2c_cacheline_browser *c2c_cl_browser;
    struct rb_node *nd;
    u64 cl_addr = 0;
    int key = -1;
    static const char help[] =
        " s             Toggle full length of symbol and source line columns \n"
        " n             Toggle Node details info \n"
        " q             Return back to symbol list \n";

    if (!he_grandchild || !he_grandchild->parent_he || !he_grandchild->parent_he->parent_he)
        return 0;

    he_child = he_grandchild->parent_he;
    he_parent = he_child->parent_he;

    /* Get the cacheline address from the grandchild */
    if (he_grandchild->mem_info && mem_info__daddr(he_grandchild->mem_info))
        cl_addr = cl_address(mem_info__daddr(he_grandchild->mem_info)->addr, chk_double_cl);
    else
        return 0;

    /* Find the cacheline entry in the main c2c.hists */
    nd = rb_first_cached(&c2c.hists.hists.entries);
    while (nd) {
        struct hist_entry *he_cl = rb_entry(nd, struct hist_entry, rb_node);
        if (he_cl->mem_info && mem_info__daddr(he_cl->mem_info)) {
            u64 this_cl = cl_address(mem_info__daddr(he_cl->mem_info)->addr, chk_double_cl);
            if (this_cl == cl_addr) {
                /* Found the cacheline, now filter its details */
                c2c_he_cl = container_of(he_cl, struct c2c_hist_entry, he);
                c2c_hists_cl = c2c_he_cl->hists;

                if (!c2c_hists_cl)
                    return 0;

                /* Create a browser for the filtered cacheline */
                c2c_cl_browser = c2c_cacheline_browser__new(&c2c_hists_cl->hists, he_cl);
                if (c2c_cl_browser == NULL)
                    return -1;

                cl_browser = &c2c_cl_browser->hb;

                /* Apply filter to show only parent and child symbol entries and sort by offset */
                {
                    struct rb_node *nd_detail;

                    /* Save original filtered state */
                    struct {
                        struct hist_entry *he;
                        bool orig_filtered;
                    } *saved_states = NULL;
                    int saved_count = 0, saved_capacity = 0;

                    /* First pass: save original state and apply filter */
                    nd_detail = rb_first_cached(&c2c_hists_cl->hists.entries);
                    while (nd_detail) {
                        struct hist_entry *he_detail = rb_entry(nd_detail, struct hist_entry, rb_node);
                        bool keep = false;

                        /* Save original filtered state */
                        if (saved_count >= saved_capacity) {
                            saved_capacity = saved_capacity ? saved_capacity * 2 : 16;
                            saved_states = realloc(saved_states, saved_capacity * sizeof(*saved_states));
                            if (!saved_states)
                                break;
                        }
                        saved_states[saved_count].he = he_detail;
                        saved_states[saved_count].orig_filtered = he_detail->filtered;
                        saved_count++;

                        /* Keep only entries matching parent or child symbols */
                        if (he_detail->ms.sym) {
                            /* Check if it matches parent symbol */
                            if (he_parent->ms.sym && symbol_name_equal(he_detail->ms.sym, he_parent->ms.sym)) {
                                if (he_parent->mem_info && he_detail->mem_info) {
                                    u64 parent_iaddr = mem_info__iaddr(he_parent->mem_info)->addr;
                                    u64 detail_iaddr = mem_info__iaddr(he_detail->mem_info)->addr;
                                    if (parent_iaddr == detail_iaddr)
                                        keep = true;
                                }
                            }

                            /* Check if it matches child symbol */
                            if (!keep && he_child->ms.sym && symbol_name_equal(he_detail->ms.sym, he_child->ms.sym)) {
                                if (he_child->mem_info && he_detail->mem_info) {
                                    u64 child_iaddr = mem_info__iaddr(he_child->mem_info)->addr;
                                    u64 detail_iaddr = mem_info__iaddr(he_detail->mem_info)->addr;
                                    if (child_iaddr == detail_iaddr)
                                        keep = true;
                                }
                            }
                        }

                        he_detail->filtered = !keep;
                        nd_detail = rb_next(&he_detail->rb_node);
                    }

                    /* Resort by offset after filtering to match cacheline view ordering */
                    hists__output_resort(&c2c_hists_cl->hists, NULL);

                    /* Use the standard cacheline details title */
                    cl_browser->title = perf_c2c_cacheline_browser__title;

                    /* Reset tty and run browser */
                    SLang_reset_tty();
                    SLang_init_tty(0, 0, 0);
                    c2c_browser__update_nr_entries(cl_browser);

                    while (1) {
                        key = hist_browser__run(cl_browser, "? - help", true, 0);

                        switch (key) {
                        case 's':
                            c2c.symbol_full = !c2c.symbol_full;
                            break;
                        case 'n':
                            c2c.node_info = (c2c.node_info + 1) % 3;
                            setup_nodes_header();
                            break;
                        case 'q':
                            goto out;
                        case '?':
                            ui_browser__help_window(&cl_browser->b, help);
                            break;
                        default:
                            break;
                        }
                    }

out:
                    /* Restore original filtered states */
                    for (int i = 0; i < saved_count; i++) {
                        saved_states[i].he->filtered = saved_states[i].orig_filtered;
                    }
                    free(saved_states);
                }

                free(c2c_cl_browser);
                return 0;
            }
        }
        nd = rb_next(&he_cl->rb_node);
    }

    return 0;
}

/*
 * Browse a Shared Data Cache Line Table filtered to cachelines shared by
 * the selected related symbol (child) and its parent symbol. This uses the
 * standard cacheline columns and title, and supports 'd' to open cacheline details.
 */
static int perf_c2c__hists_browse(struct hists *hists, struct perf_session *session)
{
	struct hist_browser *cl_browser = NULL;
	struct hist_browser *sym_browser = NULL;
	struct hist_browser *active_browser;
	bool is_symbol_view = false;
	int key = -1;
	int ret;
    static const char help[] =
    " d             Display details (cacheline details for selected item) \n"
    " e             Expand/collapse related symbols (Symbol view only) \n"
    " TAB           Switch between Cacheline/Symbol view \n"
    " ENTER         Open filtered Shared Data Cache Line Table for selected related symbol \n"
    " q             Quit \n";

	/* Build symbol hists */
	ret = build_symbol_hists(perf_session__env(session));
	if (ret) {
		ui__error("Failed to build symbol view\n");
		/* Continue with cacheline view only */
	}

	cl_browser = perf_c2c_browser__new(hists);
	if (cl_browser == NULL)
		return -1;

	sym_browser = hist_browser__new(&c2c.symbol_hists.hists);
	if (sym_browser) {
		sym_browser->title = perf_c2c_symbol_browser__title;
		sym_browser->c2c_filter = true;
		/* Enable hierarchy display for symbol view */
		sym_browser->show_headers = true;
		sym_browser->min_pcnt = 0.0;
	}

	active_browser = cl_browser;
	/* Default to non-hierarchy for cacheline view */
	symbol_conf.report_hierarchy = false;

	/* reset abort key so that it can get Ctrl-C as a key */
	SLang_reset_tty();
	SLang_init_tty(0, 0, 0);

	c2c_browser__update_nr_entries(active_browser);

	while (1) {
		key = hist_browser__run(active_browser, "? - help", true, 0);

        switch (key) {
		case 'q':
			goto out;
        case 'd':
            if (!is_symbol_view && active_browser->he_selection) {
                perf_c2c__browse_cacheline(active_browser->he_selection);
            } else if (is_symbol_view && active_browser->he_selection) {
                struct hist_entry *he = active_browser->he_selection;
                /* Check if this is a cacheline grandchild entry */
                if (!he->ms.sym && he->mem_info && he->parent_he && he->parent_he->parent_he) {
                    /* Browse filtered cacheline view for this cacheline */
                    perf_c2c__browse_symbol_pair_cacheline(he);
                }
            }
            break;
		case 'e':
		case '+':
			/* Expand/collapse related symbols in symbol view */
			if (is_symbol_view && active_browser->he_selection) {
				struct hist_entry *he = active_browser->he_selection;

				if (he->has_children) {
					/* Create child entries if not already done */
					if (RB_EMPTY_ROOT(&he->hroot_out.rb_root)) {
						/* Rebuild index if needed for interactive use */
						if (!cacheline_index)
							build_cacheline_symbol_index();
						populate_symbol_children(he);
					}

                    /* Toggle the folded state since we have children */
                    he->unfolded = !he->unfolded;
                    /* Update the browser to reflect hierarchy changes */
                    c2c_browser__update_nr_entries(active_browser);
                    active_browser->b.seek(&active_browser->b, SEEK_SET, 0);
				}
			}
			break;
		case '\t':
			if (sym_browser) {
				is_symbol_view = !is_symbol_view;
				active_browser = is_symbol_view ? sym_browser : cl_browser;
				c2c_browser__update_nr_entries(active_browser);
			}
			break;
		case '?':
			ui_browser__help_window(&active_browser->b, help);
			break;
		default:
			break;
		}
	}

out:
	if (cl_browser)
		hist_browser__delete(cl_browser);
	if (sym_browser)
		hist_browser__delete(sym_browser);
	return 0;
}

static void perf_c2c_display(struct perf_session *session)
{
	if (use_browser == 0)
		perf_c2c__hists_fprintf(stdout, session);
	else
		perf_c2c__hists_browse(&c2c.hists.hists, session);
}
#else
static void perf_c2c_display(struct perf_session *session)
{
	use_browser = 0;
	perf_c2c__hists_fprintf(stdout, session);
}
#endif /* HAVE_SLANG_SUPPORT */

static char *fill_line(const char *orig, int len)
{
	int i, j, olen = strlen(orig);
	char *buf;

	buf = zalloc(len + 1);
	if (!buf)
		return NULL;

	j = len / 2 - olen / 2;

	for (i = 0; i < j - 1; i++)
		buf[i] = '-';

	buf[i++] = ' ';

	strcpy(buf + i, orig);

	i += olen;

	buf[i++] = ' ';

	for (; i < len; i++)
		buf[i] = '-';

	return buf;
}

static int ui_quirks(void)
{
	const char *nodestr = "Data address";
	char *buf;

	if (!c2c.use_stdio) {
		dim_offset.width  = 5;
		dim_offset.header = header_offset_tui;
		nodestr = chk_double_cl ? "Double-CL" : "CL";
	}

	dim_percent_costly_snoop.header = percent_costly_snoop_header[c2c.display];

	/* Fix the zero line for dcacheline column. */
	buf = fill_line(chk_double_cl ? "Double-Cacheline" : "Cacheline",
				dim_dcacheline.width +
				dim_dcacheline_node.width +
				dim_dcacheline_count.width + 4);
	if (!buf)
		return -ENOMEM;

	dim_dcacheline.header.line[0].text = buf;

	/* Fix the zero line for offset column. */
	buf = fill_line(nodestr, dim_offset.width +
			         dim_offset_node.width +
				 dim_dcacheline_count.width + 4);
	if (!buf)
		return -ENOMEM;

	dim_offset.header.line[0].text = buf;

	return 0;
}

#define CALLCHAIN_DEFAULT_OPT  "graph,0.5,caller,function,percent"

const char callchain_help[] = "Display call graph (stack chain/backtrace):\n\n"
				CALLCHAIN_REPORT_HELP
				"\n\t\t\t\tDefault: " CALLCHAIN_DEFAULT_OPT;

static int
parse_callchain_opt(const struct option *opt, const char *arg, int unset)
{
	struct callchain_param *callchain = opt->value;

	callchain->enabled = !unset;
	/*
	 * --no-call-graph
	 */
	if (unset) {
		symbol_conf.use_callchain = false;
		callchain->mode = CHAIN_NONE;
		return 0;
	}

	return parse_callchain_report_opt(arg);
}

static int setup_callchain(struct evlist *evlist)
{
	u64 sample_type = evlist__combined_sample_type(evlist);
	enum perf_call_graph_mode mode = CALLCHAIN_NONE;

	if ((sample_type & PERF_SAMPLE_REGS_USER) &&
	    (sample_type & PERF_SAMPLE_STACK_USER)) {
		mode = CALLCHAIN_DWARF;
		dwarf_callchain_users = true;
	} else if (sample_type & PERF_SAMPLE_BRANCH_STACK)
		mode = CALLCHAIN_LBR;
	else if (sample_type & PERF_SAMPLE_CALLCHAIN)
		mode = CALLCHAIN_FP;

	if (!callchain_param.enabled &&
	    callchain_param.mode != CHAIN_NONE &&
	    mode != CALLCHAIN_NONE) {
		symbol_conf.use_callchain = true;
		if (callchain_register_param(&callchain_param) < 0) {
			ui__error("Can't register callchain params.\n");
			return -EINVAL;
		}
	}

	if (c2c.stitch_lbr && (mode != CALLCHAIN_LBR)) {
		ui__warning("Can't find LBR callchain. Switch off --stitch-lbr.\n"
			    "Please apply --call-graph lbr when recording.\n");
		c2c.stitch_lbr = false;
	}

	callchain_param.record_mode = mode;
	callchain_param.min_percent = 0;
	return 0;
}

static int setup_display(const char *str)
{
	const char *display = str;

	if (!strcmp(display, "tot"))
		c2c.display = DISPLAY_TOT_HITM;
	else if (!strcmp(display, "rmt"))
		c2c.display = DISPLAY_RMT_HITM;
	else if (!strcmp(display, "lcl"))
		c2c.display = DISPLAY_LCL_HITM;
	else if (!strcmp(display, "peer"))
		c2c.display = DISPLAY_SNP_PEER;
	else {
		pr_err("failed: unknown display type: %s\n", str);
		return -1;
	}

	return 0;
}

#define for_each_token(__tok, __buf, __sep, __tmp)		\
	for (__tok = strtok_r(__buf, __sep, &__tmp); __tok;	\
	     __tok = strtok_r(NULL,  __sep, &__tmp))

static int build_cl_output(char *cl_sort, bool no_source)
{
	char *tok, *tmp, *buf = strdup(cl_sort);
	bool add_pid   = false;
	bool add_tid   = false;
	bool add_iaddr = false;
	bool add_sym   = false;
	bool add_dso   = false;
	bool add_src   = false;
	int ret = 0;

	if (!buf)
		return -ENOMEM;

	for_each_token(tok, buf, ",", tmp) {
		if (!strcmp(tok, "tid")) {
			add_tid = true;
		} else if (!strcmp(tok, "pid")) {
			add_pid = true;
		} else if (!strcmp(tok, "iaddr")) {
			add_iaddr = true;
			add_sym   = true;
			add_dso   = true;
			add_src   = no_source ? false : true;
		} else if (!strcmp(tok, "dso")) {
			add_dso = true;
		} else if (strcmp(tok, "offset")) {
			pr_err("unrecognized sort token: %s\n", tok);
			ret = -EINVAL;
			goto err;
		}
	}

	if (asprintf(&c2c.cl_output,
		"%s%s%s%s%s%s%s%s%s%s%s%s",
		c2c.use_stdio ? "cl_num_empty," : "",
		c2c.display == DISPLAY_SNP_PEER ? "percent_rmt_peer,"
						  "percent_lcl_peer," :
						  "percent_rmt_hitm,"
						  "percent_lcl_hitm,",
		"percent_stores_l1miss,"
		"percent_stores_na,"
		"offset,offset_node,dcacheline_count,",
		add_pid   ? "pid," : "",
		add_tid   ? "tid," : "",
		add_iaddr ? "iaddr," : "",
		c2c.display == DISPLAY_SNP_PEER ? "mean_rmt_peer,"
						  "mean_lcl_peer," :
						  "mean_rmt,"
						  "mean_lcl,",
		"mean_load,"
		"tot_recs,"
		"cpucnt,",
		add_sym ? "symbol," : "",
		add_dso ? "dso," : "",
		add_src ? "cl_srcline," : "",
		"node") < 0) {
		ret = -ENOMEM;
		goto err;
	}

	c2c.show_src = add_src;
err:
	free(buf);
	return ret;
}

static int setup_coalesce(const char *coalesce, bool no_source)
{
	const char *c = coalesce ?: coalesce_default;
	const char *sort_str = NULL;

	if (asprintf(&c2c.cl_sort, "offset,%s", c) < 0)
		return -ENOMEM;

	if (build_cl_output(c2c.cl_sort, no_source))
		return -1;

	if (c2c.display == DISPLAY_TOT_HITM)
		sort_str = "tot_hitm";
	else if (c2c.display == DISPLAY_RMT_HITM)
		sort_str = "rmt_hitm,lcl_hitm";
	else if (c2c.display == DISPLAY_LCL_HITM)
		sort_str = "lcl_hitm,rmt_hitm";
	else if (c2c.display == DISPLAY_SNP_PEER)
		sort_str = "tot_peer";

	if (asprintf(&c2c.cl_resort, "offset,%s", sort_str) < 0)
		return -ENOMEM;

	pr_debug("coalesce sort   fields: %s\n", c2c.cl_sort);
	pr_debug("coalesce resort fields: %s\n", c2c.cl_resort);
	pr_debug("coalesce output fields: %s\n", c2c.cl_output);
	return 0;
}

static int perf_c2c__report(int argc, const char **argv)
{
	struct itrace_synth_opts itrace_synth_opts = {
		.set = true,
		.mem = true,	/* Only enable memory event */
		.default_no_sample = true,
	};

	struct perf_session *session;
	struct ui_progress prog;
	struct perf_data data = {
		.mode = PERF_DATA_MODE_READ,
	};
	char callchain_default_opt[] = CALLCHAIN_DEFAULT_OPT;
	const char *display = NULL;
	const char *coalesce = NULL;
	bool no_source = false;
	const struct option options[] = {
	OPT_STRING('k', "vmlinux", &symbol_conf.vmlinux_name,
		   "file", "vmlinux pathname"),
	OPT_STRING('i', "input", &input_name, "file",
		   "the input file to process"),
	OPT_INCR('N', "node-info", &c2c.node_info,
		 "show extra node info in report (repeat for more info)"),
	OPT_BOOLEAN(0, "stdio", &c2c.use_stdio, "Use the stdio interface"),
	OPT_BOOLEAN(0, "stats", &c2c.stats_only,
		    "Display only statistic tables (implies --stdio)"),
	OPT_BOOLEAN(0, "full-symbols", &c2c.symbol_full,
		    "Display full length of symbols"),
	OPT_BOOLEAN(0, "no-source", &no_source,
		    "Do not display Source Line column"),
	OPT_BOOLEAN(0, "show-all", &c2c.show_all,
		    "Show all captured HITM lines."),
	OPT_CALLBACK_DEFAULT('g', "call-graph", &callchain_param,
			     "print_type,threshold[,print_limit],order,sort_key[,branch],value",
			     callchain_help, &parse_callchain_opt,
			     callchain_default_opt),
	OPT_STRING('d', "display", &display, "Switch HITM output type", "tot,lcl,rmt,peer"),
	OPT_STRING('c', "coalesce", &coalesce, "coalesce fields",
		   "coalesce fields: pid,tid,iaddr,dso"),
	OPT_BOOLEAN('f', "force", &symbol_conf.force, "don't complain, do it"),
	OPT_BOOLEAN(0, "stitch-lbr", &c2c.stitch_lbr,
		    "Enable LBR callgraph stitching approach"),
	OPT_BOOLEAN(0, "double-cl", &chk_double_cl, "Detect adjacent cacheline false sharing"),
	OPT_PARENT(c2c_options),
	OPT_END()
	};
	int err = 0;
	const char *output_str, *sort_str = NULL;
	struct perf_env *env;

	argc = parse_options(argc, argv, options, report_c2c_usage,
			     PARSE_OPT_STOP_AT_NON_OPTION);
	if (argc)
		usage_with_options(report_c2c_usage, options);

#ifndef HAVE_SLANG_SUPPORT
	c2c.use_stdio = true;
#endif

	if (c2c.stats_only)
		c2c.use_stdio = true;

	err = symbol__validate_sym_arguments();
	if (err)
		goto out;

	if (!input_name || !strlen(input_name))
		input_name = "perf.data";

	data.path  = input_name;
	data.force = symbol_conf.force;

	perf_tool__init(&c2c.tool, /*ordered_events=*/true);
	c2c.tool.sample		= process_sample_event;
	c2c.tool.mmap		= perf_event__process_mmap;
	c2c.tool.mmap2		= perf_event__process_mmap2;
	c2c.tool.comm		= perf_event__process_comm;
	c2c.tool.exit		= perf_event__process_exit;
	c2c.tool.fork		= perf_event__process_fork;
	c2c.tool.lost		= perf_event__process_lost;
	c2c.tool.attr		= perf_event__process_attr;
	c2c.tool.auxtrace_info  = perf_event__process_auxtrace_info;
	c2c.tool.auxtrace       = perf_event__process_auxtrace;
	c2c.tool.auxtrace_error = perf_event__process_auxtrace_error;
	c2c.tool.ordering_requires_timestamps = true;
	session = perf_session__new(&data, &c2c.tool);
	if (IS_ERR(session)) {
		err = PTR_ERR(session);
		pr_debug("Error creating perf session\n");
		goto out;
	}
	env = perf_session__env(session);
	/*
	 * Use the 'tot' as default display type if user doesn't specify it;
	 * since Arm64 platform doesn't support HITMs flag, use 'peer' as the
	 * default display type.
	 */
	if (!display) {
		if (!strcmp(perf_env__arch(env), "arm64"))
			display = "peer";
		else
			display = "tot";
	}

	err = setup_display(display);
	if (err)
		goto out_session;

	err = setup_coalesce(coalesce, no_source);
	if (err) {
		pr_debug("Failed to initialize hists\n");
		goto out_session;
	}

	err = c2c_hists__init(&c2c.hists, "dcacheline", 2, perf_session__env(session));
	if (err) {
		pr_debug("Failed to initialize hists\n");
		goto out_session;
	}

	session->itrace_synth_opts = &itrace_synth_opts;

	err = setup_nodes(session);
	if (err) {
		pr_err("Failed setup nodes\n");
		goto out_session;
	}

	err = mem2node__init(&c2c.mem2node, env);
	if (err)
		goto out_session;

	err = setup_callchain(session->evlist);
	if (err)
		goto out_mem2node;

	if (symbol__init(env) < 0)
		goto out_mem2node;

	/* No pipe support at the moment. */
	if (perf_data__is_pipe(session->data)) {
		pr_debug("No pipe support at the moment.\n");
		goto out_mem2node;
	}

	if (c2c.use_stdio)
		use_browser = 0;
	else
		use_browser = 1;

	setup_browser(false);

	err = perf_session__process_events(session);
	if (err) {
		pr_err("failed to process sample\n");
		goto out_mem2node;
	}

	if (c2c.display != DISPLAY_SNP_PEER)
		output_str = "cl_idx,"
			     "dcacheline,"
			     "dcacheline_node,"
			     "dcacheline_count,"
			     "percent_costly_snoop,"
			     "tot_hitm,lcl_hitm,rmt_hitm,"
			     "tot_recs,"
			     "tot_loads,"
			     "tot_stores,"
			     "stores_l1hit,stores_l1miss,stores_na,"
			     "ld_fbhit,ld_l1hit,ld_l2hit,"
			     "ld_lclhit,lcl_hitm,"
			     "ld_rmthit,rmt_hitm,"
			     "dram_lcl,dram_rmt";
	else
		output_str = "cl_idx,"
			     "dcacheline,"
			     "dcacheline_node,"
			     "dcacheline_count,"
			     "percent_costly_snoop,"
			     "tot_peer,lcl_peer,rmt_peer,"
			     "tot_recs,"
			     "tot_loads,"
			     "tot_stores,"
			     "stores_l1hit,stores_l1miss,stores_na,"
			     "ld_fbhit,ld_l1hit,ld_l2hit,"
			     "ld_lclhit,lcl_hitm,"
			     "ld_rmthit,rmt_hitm,"
			     "dram_lcl,dram_rmt";

	if (c2c.display == DISPLAY_TOT_HITM)
		sort_str = "tot_hitm";
	else if (c2c.display == DISPLAY_RMT_HITM)
		sort_str = "rmt_hitm";
	else if (c2c.display == DISPLAY_LCL_HITM)
		sort_str = "lcl_hitm";
	else if (c2c.display == DISPLAY_SNP_PEER)
		sort_str = "tot_peer";

	c2c_hists__reinit(&c2c.hists, output_str, sort_str, perf_session__env(session));

	ui_progress__init(&prog, c2c.hists.hists.nr_entries, "Sorting...");

	hists__collapse_resort(&c2c.hists.hists, NULL);
	hists__output_resort_cb(&c2c.hists.hists, &prog, resort_shared_cl_cb);
	hists__iterate_cb(&c2c.hists.hists, resort_cl_cb, perf_session__env(session));

	ui_progress__finish();

	if (ui_quirks()) {
		pr_err("failed to setup UI\n");
		goto out_mem2node;
	}

	perf_c2c_display(session);

out_mem2node:
	mem2node__exit(&c2c.mem2node);
out_session:
	perf_session__delete(session);
out:
	return err;
}

static int parse_record_events(const struct option *opt,
			       const char *str, int unset __maybe_unused)
{
	bool *event_set = (bool *) opt->value;
	struct perf_pmu *pmu;

	pmu = perf_mem_events_find_pmu();
	if (!pmu) {
		pr_err("failed: there is no PMU that supports perf c2c\n");
		exit(-1);
	}

	if (!strcmp(str, "list")) {
		perf_pmu__mem_events_list(pmu);
		exit(0);
	}
	if (perf_pmu__mem_events_parse(pmu, str))
		exit(-1);

	*event_set = true;
	return 0;
}


static const char * const __usage_record[] = {
	"perf c2c record [<options>] [<command>]",
	"perf c2c record [<options>] -- <command> [<options>]",
	NULL
};

static const char * const *record_mem_usage = __usage_record;

static int perf_c2c__record(int argc, const char **argv)
{
	int rec_argc, i = 0, j;
	const char **rec_argv;
	char *event_name_storage = NULL;
	int ret;
	bool all_user = false, all_kernel = false;
	bool event_set = false;
	struct perf_mem_event *e;
	struct perf_pmu *pmu;
	struct option options[] = {
	OPT_CALLBACK('e', "event", &event_set, "event",
		     "event selector. Use 'perf c2c record -e list' to list available events",
		     parse_record_events),
	OPT_BOOLEAN('u', "all-user", &all_user, "collect only user level data"),
	OPT_BOOLEAN('k', "all-kernel", &all_kernel, "collect only kernel level data"),
	OPT_UINTEGER('l', "ldlat", &perf_mem_events__loads_ldlat, "setup mem-loads latency"),
	OPT_PARENT(c2c_options),
	OPT_END()
	};

	pmu = perf_mem_events_find_pmu();
	if (!pmu) {
		pr_err("failed: no PMU supports the memory events\n");
		return -1;
	}

	if (perf_pmu__mem_events_init()) {
		pr_err("failed: memory events not supported\n");
		return -1;
	}

	argc = parse_options(argc, argv, options, record_mem_usage,
			     PARSE_OPT_KEEP_UNKNOWN);

	/* Max number of arguments multiplied by number of PMUs that can support them. */
	rec_argc = argc + 11 * (perf_pmu__mem_events_num_mem_pmus(pmu) + 1);

	rec_argv = calloc(rec_argc + 1, sizeof(char *));
	if (!rec_argv)
		return -1;

	rec_argv[i++] = "record";

	if (!event_set) {
		e = perf_pmu__mem_events_ptr(pmu, PERF_MEM_EVENTS__LOAD_STORE);
		/*
		 * The load and store operations are required, use the event
		 * PERF_MEM_EVENTS__LOAD_STORE if it is supported.
		 */
		if (e->tag) {
			perf_mem_record[PERF_MEM_EVENTS__LOAD_STORE] = true;
			rec_argv[i++] = "-W";
		} else {
			perf_mem_record[PERF_MEM_EVENTS__LOAD] = true;
			perf_mem_record[PERF_MEM_EVENTS__STORE] = true;
		}
	}

	if (perf_mem_record[PERF_MEM_EVENTS__LOAD])
		rec_argv[i++] = "-W";

	rec_argv[i++] = "-d";
	rec_argv[i++] = "--phys-data";
	rec_argv[i++] = "--sample-cpu";

	ret = perf_mem_events__record_args(rec_argv, &i, &event_name_storage);
	if (ret)
		goto out;

	if (all_user)
		rec_argv[i++] = "--all-user";

	if (all_kernel)
		rec_argv[i++] = "--all-kernel";

	for (j = 0; j < argc; j++, i++)
		rec_argv[i] = argv[j];

	if (verbose > 0) {
		pr_debug("calling: ");

		j = 0;

		while (rec_argv[j]) {
			pr_debug("%s ", rec_argv[j]);
			j++;
		}
		pr_debug("\n");
	}

	ret = cmd_record(i, rec_argv);
out:
	free(event_name_storage);
	free(rec_argv);
	return ret;
}

int cmd_c2c(int argc, const char **argv)
{
	argc = parse_options(argc, argv, c2c_options, c2c_usage,
			     PARSE_OPT_STOP_AT_NON_OPTION);

	if (!argc)
		usage_with_options(c2c_usage, c2c_options);

	if (strlen(argv[0]) > 2 && strstarts("record", argv[0])) {
		return perf_c2c__record(argc, argv);
	} else if (strlen(argv[0]) > 2 && strstarts("report", argv[0])) {
		return perf_c2c__report(argc, argv);
	} else {
		usage_with_options(c2c_usage, c2c_options);
	}

	return 0;
}
