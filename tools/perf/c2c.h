/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _PERF_C2C_H_
#define _PERF_C2C_H_ 1

struct compute_stats {
	struct stats		 lcl_hitm;
	struct stats		 rmt_hitm;
	struct stats		 lcl_peer;
	struct stats		 rmt_peer;
	struct stats		 load;
};

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
 * struct related_symbol - Symbol that shares a cacheline with another symbol
 * @list: List node for linking in c2c_hist_entry.related_symbols
 * @iaddr: Code address (instruction address)
 * @stats: Aggregated C2C stats for this symbol's accesses
 * @cstats: Computed statistics for this symbol
 */
struct related_symbol {
	uint64_t		 iaddr;
	struct list_head	 list;
	struct c2c_stats	 stats;
	struct compute_stats	 cstats;
};

/**
 * struct symbol_access - Record of a symbol accessing a cacheline
 * @list: List node for linking in cacheline_symbol_entry.symbol_accesses
 * @iaddr: Instruction address of the access
 * @map: Map containing the symbol
 * @maps: Maps container
 * @stats: C2C statistics for this access
 * @cstats: Computed statistics for this access
 */
struct symbol_access {
	uint64_t		 iaddr;
	struct map		*map;
	struct maps		*maps;
	struct list_head	 list;
	struct c2c_stats	 stats;
	struct compute_stats	 cstats;
};

/**
 * struct cacheline_symbol_entry - Index entry mapping cacheline to accessing symbols
 * @c2c_he_cl: C2C histogram entry for this cacheline (contains hist_entry via ->he)
 * @symbol_accesses: Linked list of symbols that access this cacheline
 */
struct cacheline_symbol_entry {
	struct list_head	symbol_accesses;
	struct c2c_hist_entry	*c2c_he_cl;
};

/**
 * struct symbol_relations_entry - Entry in the symbol relations lookup table
 * @node: RB-tree node for symbol lookup
 * @parent_iaddr: Parent symbol's instruction address
 * @related_symbols: List of related symbols that share cachelines with parent
 *
 * This structure maps a parent symbol (identified by iaddr) to its related symbols,
 * enabling efficient lookup without embedding the relationship data in hist_entry.
 */
struct symbol_relations_entry {
	uint64_t		 parent_iaddr;
	struct rb_node		 node;
	struct list_head	 related_symbols;
};

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
 * @symbol_hists: Symbol-grouped histograms for symbol view
 * @symbol_total_cycles: Cached total cycles across all symbols for percent column
 * @symbol_total_cycles_valid: Whether symbol_total_cycles is valid
 * @cacheline_index: Index of cachelines to symbols for performance optimization
 * @cacheline_index_size: Number of entries in cacheline_index
 * @cacheline_index_capacity: Capacity of cacheline_index array
 * @cacheline_index_built: Whether the index has been built
 * @relations_root: RB-tree root for symbol relationships lookup
 *
 * This extended structure is used only in tools/perf/ui/browsers/c2c-symbol.c
 * for symbol view functionality, while the base perf_c2c is used in
 * tools/perf/builtin-c2c.c for cacheline view functionality.
 */
struct perf_c2c_ext {
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

	/* Symbol relationships lookup table */
	struct rb_root		relations_root;
};

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
 * symbol_relations_init - Initialize the symbol relations table
 * @relations_root: RB-tree root to initialize
 */
void symbol_relations_init(struct rb_root *relations_root);

/**
 * symbol_relations_destroy - Destroy and free all symbol relations
 * @relations_root: RB-tree root containing relations
 */
void symbol_relations_destroy(struct rb_root *relations_root);

/**
 * symbol_relations_add - Add a related symbol to the relations table
 * @relations_root: RB-tree root for symbol relations
 * @parent_iaddr: Parent symbol's instruction address
 * @rel_sym: Related symbol to add
 *
 * Returns: 0 on success, negative error code on failure
 */
int symbol_relations_add(struct rb_root *relations_root,
			 uint64_t parent_iaddr,
			 struct related_symbol *rel_sym);

/**
 * symbol_relations_lookup - Look up related symbols for a parent iaddr
 * @relations_root: RB-tree root for symbol relations
 * @parent_iaddr: Parent symbol's instruction address
 *
 * Returns: List of related symbols, or NULL if not found
 */
struct list_head *symbol_relations_lookup(struct rb_root *relations_root,
					  uint64_t parent_iaddr);

#endif /* _PERF_C2C_H_ */
