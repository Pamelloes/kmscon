/*
 * This file has been directly lifted from util-linux. It is
 * licensed under the LGPL, which as far as I can tell is
 * compatible with the current license. I believe this means the
 * entire project now needs to be LGPL licensed, although as
 * of right now it is just for personal use so I don't believe there
 * are any issues.
 */

#include <string.h>
#include <stdlib.h>

#include "color-names.h"

#ifdef __GNUC__
# define __must_be_array(a) \
	UL_BUILD_BUG_ON_ZERO(__builtin_types_compatible_p(__typeof__(a), __typeof__(&a[0])))
#else
# define __must_be_array(a) 0
#endif

#define UL_BUILD_BUG_ON_ZERO(e) __extension__ (sizeof(struct { int:-!!(e); }))

#ifndef ARRAY_SIZE
# define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]) +  __must_be_array(arr))
#endif

struct ul_color_name {
	const char *name;
	const char *seq;
};

/*
 * qsort/bsearch buddy
 */
static int cmp_color_name(const void *a0, const void *b0)
{
	struct ul_color_name	*a = (struct ul_color_name *) a0,
				*b = (struct ul_color_name *) b0;
	return strcmp(a->name, b->name);
}

/*
 * Maintains human readable color names
 */
const char *color_sequence_from_colorname(const char *str)
{
	static const struct ul_color_name basic_schemes[] = {
		{ "black",	UL_COLOR_BLACK           },
		{ "blink",      UL_COLOR_BLINK           },
		{ "blue",	UL_COLOR_BLUE            },
		{ "bold",       UL_COLOR_BOLD		 },
		{ "brown",	UL_COLOR_BROWN           },
		{ "cyan",	UL_COLOR_CYAN            },
		{ "darkgray",	UL_COLOR_DARK_GRAY       },
		{ "gray",	UL_COLOR_GRAY            },
		{ "green",	UL_COLOR_GREEN           },
		{ "halfbright", UL_COLOR_HALFBRIGHT	 },
		{ "lightblue",	UL_COLOR_BOLD_BLUE       },
		{ "lightcyan",	UL_COLOR_BOLD_CYAN       },
		{ "lightgray,",	UL_COLOR_GRAY            },
		{ "lightgreen", UL_COLOR_BOLD_GREEN      },
		{ "lightmagenta", UL_COLOR_BOLD_MAGENTA  },
		{ "lightred",	UL_COLOR_BOLD_RED        },
		{ "magenta",	UL_COLOR_MAGENTA         },
		{ "red",	UL_COLOR_RED             },
		{ "reset",      UL_COLOR_RESET,          },
		{ "reverse",    UL_COLOR_REVERSE         },
		{ "yellow",	UL_COLOR_BOLD_YELLOW     },
	};
	struct ul_color_name key = { .name = (char *) str }, *res;

	if (!str)
		return NULL;

	res = bsearch(&key, basic_schemes, ARRAY_SIZE(basic_schemes),
				sizeof(struct ul_color_name),
				cmp_color_name);
	return res ? res->seq : NULL;
}
