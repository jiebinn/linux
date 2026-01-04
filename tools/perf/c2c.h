/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _PERF_C2C_H_
#define _PERF_C2C_H_ 1

/* Constants */
#define SYMBOL_WIDTH 30
#define C2C_HEADER_MAX 2

/* Header macros for dimension definitions */
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

/**
 * struct c2c_header - Column header definition for C2C display
 * @line: Array of header lines with text and span
 */
struct c2c_header {
	struct {
		const char *text;
		int	    span;
	} line[C2C_HEADER_MAX];
};

/**
 * struct c2c_dimension - Definition of a display column for C2C
 * @header: Column header text and span
 * @name: Column name for configuration
 * @width: Default column width
 * @se: Sort entry if this dimension uses standard sorting
 * @cmp: Comparison function for sorting
 * @entry: Entry rendering function
 * @color: Colored entry rendering function (optional)
 */
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

/**
 * struct c2c_fmt - Format wrapper for C2C dimensions
 * @fmt: Base perf HPP format structure
 * @dim: Pointer to the C2C dimension
 */
struct c2c_fmt {
	struct perf_hpp_fmt	 fmt;
	struct c2c_dimension	*dim;
};

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

	/*
	 * must be at the end,
	 * because of its callchain dynamic entry
	 */
	struct hist_entry	he;
};

/**
 * struct c2c_hist_entry_ext - Extended histogram entry for C2C analysis
 * @related_symbols: List of symbols that share this cacheline
 * @c2c_he: Base histogram entry structure (must be last due to dynamic callchain)
 *
 * Note: c2c_he must be the last field because hist_entry (inside c2c_he) has
 * dynamic callchain data that is allocated immediately after it.
 */
struct c2c_hist_entry_ext {
	/* Symbol association support */
	struct list_head	related_symbols;

	struct c2c_hist_entry c2c_he;
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
 * @coalesce: Coalesce settings
 * @cl_sort: Cacheline sort string
 * @cl_resort: Cacheline resort string
 * @cl_output: Cacheline output columns
 */
struct perf_c2c {
	struct perf_tool	tool;
	struct c2c_hists	hists;
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

	const char		*coalesce;
	char			*cl_sort;
	char			*cl_resort;
	char			*cl_output;
};

/**
 * struct perf_c2c_ext - Extended C2C analysis context for symbol view
 * @c2c: Base C2C analysis context
 * @symbol_hists: Symbol-grouped histograms for symbol view
 * @symbol_total_cycles: Cached total cycles across all symbols for percent column
 * @symbol_total_cycles_valid: Whether symbol_total_cycles is valid
 * @cacheline_index: Index of cachelines to symbols for performance optimization
 * @cacheline_index_size: Number of entries in cacheline_index
 * @cacheline_index_capacity: Capacity of cacheline_index array
 * @cacheline_index_built: Whether the index has been built
 *
 * This extended structure is used only in tools/perf/ui/browsers/c2c-symbol.c
 * for symbol view functionality, while the base perf_c2c is used in
 * tools/perf/builtin-c2c.c for cacheline view functionality.
 */
struct perf_c2c_ext {
	struct perf_c2c		c2c;

	/* Symbol view histograms */
	struct c2c_hists	symbol_hists;

	/* Cached total cycles across all symbols for percent column */
	uint64_t		symbol_total_cycles;
	bool			symbol_total_cycles_valid;

	/* Cacheline-to-symbols index for performance optimization */
	struct cacheline_symbol_entry *cacheline_index;
	int			cacheline_index_size;
	int			cacheline_index_capacity;
	bool		cacheline_index_built;
};

/* Global C2C context - defined in builtin-c2c.c */
extern struct perf_c2c c2c;
extern struct perf_c2c_ext c2c_ext;



/**
 * struct c2c_symbol_browser - Symbol browser for C2C analysis
 * @hb: Base histogram browser
 * @hists: Symbol histograms to display
 *
 * This browser displays symbol-level view of cacheline sharing,
 * allowing users to see which symbols (functions) share cachelines
 * and cause false sharing issues.
 */
struct c2c_symbol_browser {
	struct hist_browser	hb;
	struct hists		*hists;
};

/**
 * perf_c2c__browse_cacheline - Display cacheline details browser
 * @he: Histogram entry for the cacheline to browse
 *
 * Returns: 0 on success, negative error code on failure
 */
int perf_c2c__browse_cacheline(struct hist_entry *he);

/**
 * perf_c2c__browse_symbol_view - Browse symbol view browser
 * @hists: Main cacheline histograms
 *
 * Returns: 0 on success, negative error code on failure
 */
int perf_c2c__browse_symbol_view(struct hists *hists);

/**
 * cleanup_cacheline_symbol_index - Free the cacheline symbol index
 *
 * Releases all memory associated with the cacheline index.
 * Should be called at program exit.
 */
void cleanup_cacheline_symbol_index(void);

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

#endif /* _PERF_C2C_H_ */
