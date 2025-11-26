/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _PERF_BUILTIN_C2C_H_
#define _PERF_BUILTIN_C2C_H_ 1

#include <linux/list.h>
#include <linux/rbtree.h>
#include <stdbool.h>
#include <stdint.h>

#include "ui/browser.h"
#include "ui/browsers/hists.h"
#include "util/mem-events.h"
#include "util/mem2node.h"
#include "util/hist.h"
#include "util/symbol.h"
#include "util/tool.h"

/* Forward declarations */
struct perf_session;
struct perf_env;
struct symbol;
struct map;
struct maps;
struct hist_entry;

/*
 * ============================================================================
 * Shared structures for C2C symbol view
 * ============================================================================
 */

/**
 * struct compute_stats - Statistics computed from memory access samples
 * @lcl_hitm: Local HITM statistics
 * @rmt_hitm: Remote HITM statistics
 * @lcl_peer: Local peer snoop statistics
 * @rmt_peer: Remote peer snoop statistics
 * @load: Load statistics
 */
struct compute_stats {
	struct stats		 lcl_hitm;
	struct stats		 rmt_hitm;
	struct stats		 lcl_peer;
	struct stats		 rmt_peer;
	struct stats		 load;
};

/**
 * struct c2c_hists - C2C histogram container
 * @hists: Base histogram structure
 * @list: HPP list for column formatting
 * @stats: Aggregated C2C statistics
 */
struct c2c_hists {
	struct hists		hists;
	struct perf_hpp_list	list;
	struct c2c_stats	stats;
};

/**
 * struct c2c_hist_entry - Extended histogram entry for C2C analysis
 * @hists: Pointer to child histograms (for cacheline entries)
 * @stats: C2C statistics for this entry
 * @cpuset: Bitmap of CPUs that accessed this entry
 * @nodeset: Bitmap of NUMA nodes that accessed this entry
 * @node_stats: Per-node statistics
 * @cacheline_idx: Index of this cacheline in the sorted list
 * @cstats: Computed statistics (latency averages, etc.)
 * @paddr: Physical address
 * @paddr_cnt: Count of physical addresses seen
 * @paddr_zero: Whether physical address is zero
 * @nodestr: String representation of accessing nodes
 * @related_symbols: List of symbols that share this cacheline
 * @total_cycles: Cached total cycles for this entry
 * @total_cycles_valid: Whether the cached total cycles is valid
 * @he: Base histogram entry (must be last due to dynamic callchain)
 */
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
	struct list_head	related_symbols;

	/* Cached total cycles for this entry to avoid repeated calculations */
	uint64_t		 total_cycles;
	bool			 total_cycles_valid;

	/*
	 * must be at the end,
	 * because of its callchain dynamic entry
	 */
	struct hist_entry	he;
};

/**
 * struct related_symbol - Symbol that shares a cacheline with another symbol
 * @list: List node for linking in c2c_hist_entry.related_symbols
 * @sym: Pointer to the symbol
 * @iaddr: Code address (instruction address)
 * @stats: Aggregated C2C stats for this symbol's accesses
 * @cstats: Computed statistics for this symbol
 */
struct related_symbol {
	struct list_head	 list;
	struct symbol		*sym;
	uint64_t		 iaddr;
	struct c2c_stats	 stats;
	struct compute_stats	 cstats;
};

/**
 * struct symbol_access - Record of a symbol accessing a cacheline
 * @sym: Pointer to the accessing symbol
 * @iaddr: Instruction address of the access
 * @map: Map containing the symbol
 * @maps: Maps container
 * @stats: C2C statistics for this access
 * @cstats: Computed statistics for this access
 * @next: Next symbol access in the linked list
 */
struct symbol_access {
	struct symbol		*sym;
	uint64_t		 iaddr;
	struct map		*map;
	struct maps		*maps;
	struct c2c_stats	 stats;
	struct compute_stats	 cstats;
	struct symbol_access	*next;
};

/**
 * struct cacheline_symbol_entry - Index entry mapping cacheline to accessing symbols
 * @he_cl: Histogram entry for this cacheline
 * @c2c_he_cl: C2C histogram entry for this cacheline
 * @symbol_accesses: Linked list of symbols that access this cacheline
 */
struct cacheline_symbol_entry {
	struct hist_entry	*he_cl;
	struct c2c_hist_entry	*c2c_he_cl;
	struct symbol_access	*symbol_accesses;
};

/**
 * struct perf_c2c - Main C2C analysis context
 * @tool: Base perf tool structure
 * @hists: Main cacheline histograms
 * @symbol_hists: Symbol-grouped histograms
 * @mem2node: Memory to node mapping
 * @nodes: Array of CPU bitmaps per node
 * @nodes_cnt: Number of NUMA nodes
 * @cpus_cnt: Number of CPUs
 * @cpu2node: CPU to node mapping
 * @node_info: Node display mode (0, 1, or 2)
 * @show_src: Show source line information
 * @show_all: Show all entries (not just shared)
 * @use_stdio: Use stdio instead of TUI
 * @stats_only: Show statistics only
 * @symbol_full: Show full symbol names
 * @stitch_lbr: Stitch LBR callchains
 * @shared_clines_stats: Statistics for shared cachelines
 * @shared_clines: Count of shared cachelines
 * @display: Current display mode
 * @symbol_total_cycles: Cached total cycles across all symbols
 * @symbol_total_cycles_valid: Whether symbol_total_cycles is valid
 * @coalesce: Coalesce settings
 * @cl_sort: Cacheline sort string
 * @cl_resort: Cacheline resort string
 * @cl_output: Cacheline output columns
 * @cacheline_index: Index of cachelines to symbols
 * @cacheline_index_size: Number of entries in cacheline_index
 * @cacheline_index_capacity: Capacity of cacheline_index array
 * @cacheline_index_built: Whether the index has been built
 */
struct perf_c2c {
	struct perf_tool	tool;
	struct c2c_hists	hists;
	struct c2c_hists	symbol_hists;
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

	/* Cacheline-to-symbols index for performance optimization */
	struct cacheline_symbol_entry *cacheline_index;
	int			cacheline_index_size;
	int			cacheline_index_capacity;
	bool			cacheline_index_built;
};

/* Global C2C context - defined in builtin-c2c.c */
extern struct perf_c2c c2c;

/* Note: chk_double_cl is declared in util/sort.h */

/*
 * ============================================================================
 * C2C Symbol Browser API - implemented in ui/browsers/c2c-symbol.c
 * ============================================================================
 */

/**
 * struct c2c_symbol_browser - Symbol browser for C2C analysis
 * @hb: Base histogram browser
 * @hists: Symbol histograms to display
 * @session: Perf session for data access
 *
 * This browser displays symbol-level view of cacheline sharing,
 * allowing users to see which symbols (functions) share cachelines
 * and cause false sharing issues.
 */
struct c2c_symbol_browser {
	struct hist_browser	hb;
	struct hists		*hists;
	struct perf_session	*session;
};

/**
 * c2c_symbol_browser__new - Create a new C2C symbol browser
 * @hists: Symbol histograms to display
 * @session: Perf session for accessing symbol information
 *
 * Returns: Pointer to newly created browser, or NULL on error
 */
struct c2c_symbol_browser *c2c_symbol_browser__new(struct hists *hists,
						   struct perf_session *session);

/**
 * c2c_symbol_browser__delete - Free a C2C symbol browser
 * @browser: Browser to free
 */
void c2c_symbol_browser__delete(struct c2c_symbol_browser *browser);

/**
 * c2c_symbol_browser__handle_expand - Handle expand/collapse operation
 * @browser: Symbol browser instance
 *
 * Returns: 0 on success, negative value on error
 */
int c2c_symbol_browser__handle_expand(struct c2c_symbol_browser *browser);

/**
 * c2c_symbol_browser__browse_cacheline_detail - Handle cacheline detail view
 * @browser: Symbol browser instance
 * @he_selection: Selected histogram entry
 * @main_hists: Main cacheline hists
 *
 * Returns: 0 on success, negative value on error
 */
int c2c_symbol_browser__browse_cacheline_detail(struct c2c_symbol_browser *browser,
					       struct hist_entry *he_selection,
					       struct hists *main_hists);

/*
 * ============================================================================
 * Symbol View Data Processing - implemented in ui/browsers/c2c-symbol.c
 * ============================================================================
 */

/**
 * build_symbol_hists - Build symbol-level histograms from cacheline data
 * @env: Perf environment containing symbol tables
 *
 * Creates symbol_hists by aggregating cacheline data by symbol,
 * building the cacheline index, and establishing symbol associations.
 *
 * Returns: 0 on success, negative error code on failure
 */
int build_symbol_hists(struct perf_env *env);

/**
 * build_cacheline_symbol_index - Build index mapping cachelines to symbols
 *
 * Creates an optimized index structure for looking up which symbols
 * access each cacheline. This is used for building symbol associations
 * and populating child entries efficiently.
 */
void build_cacheline_symbol_index(void);

/**
 * cleanup_cacheline_symbol_index - Free the cacheline symbol index
 *
 * Releases all memory associated with the cacheline index.
 * Should be called at program exit.
 */
void cleanup_cacheline_symbol_index(void);

/**
 * populate_symbol_children - Create child entries for a symbol
 * @he: Parent histogram entry to populate
 *
 * Creates child entries (related symbols) under the given parent entry.
 * Each child represents a symbol that shares a cacheline with the parent.
 */
void populate_symbol_children(struct hist_entry *he);

/*
 * ============================================================================
 * Cacheline Browser API - implemented in builtin-c2c.c
 * ============================================================================
 */

/**
 * perf_c2c__browse_cacheline - Display cacheline details browser
 * @he: Histogram entry for the cacheline to browse
 *
 * Returns: 0 on success, negative error code on failure
 */
int perf_c2c__browse_cacheline(struct hist_entry *he);

/*
 * ============================================================================
 * Utility Functions - shared between builtin-c2c.c and c2c-symbol.c
 * ============================================================================
 */

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
 * init_c2c_he_related_symbols - Initialize related_symbols list
 * @c2c_he: C2C histogram entry to initialize
 */
static inline void init_c2c_he_related_symbols(struct c2c_hist_entry *c2c_he)
{
	INIT_LIST_HEAD(&c2c_he->related_symbols);
}

/**
 * c2c_he_invalidate_total_cycles_cache - Invalidate cached total cycles
 * @c2c_he: C2C histogram entry
 */
static inline void c2c_he_invalidate_total_cycles_cache(struct c2c_hist_entry *c2c_he)
{
	c2c_he->total_cycles_valid = false;
}

/**
 * c2c_add_cstats - Merge compute_stats from src into dest
 * @dest: Destination statistics
 * @src: Source statistics to merge
 */
void c2c_add_cstats(struct compute_stats *dest, struct compute_stats *src);

/**
 * c2c_hists__init - Initialize C2C histograms
 * @hists: C2C hists to initialize
 * @sort: Sort string
 * @nr_header_lines: Number of header lines
 * @env: Perf environment
 *
 * Returns: 0 on success, negative error code on failure
 */
int c2c_hists__init(struct c2c_hists *hists, const char *sort, int nr_header_lines, struct perf_env *env);

/**
 * c2c_hists__reinit - Reinitialize C2C histograms with new output/sort
 * @hists: C2C hists to reinitialize
 * @output: Output columns string
 * @sort: Sort string
 * @env: Perf environment
 *
 * Returns: 0 on success, negative error code on failure
 */
int c2c_hists__reinit(struct c2c_hists *hists, const char *output, const char *sort, struct perf_env *env);

/**
 * c2c_entry_ops - Histogram entry operations for C2C
 */
extern struct hist_entry_ops c2c_entry_ops;

#endif /* _PERF_BUILTIN_C2C_H_ */
