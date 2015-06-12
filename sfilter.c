// runs our filters on packet data

#include <linux/kernel.h>

#include "defs.h"


static bool run_sfilter(struct sfilter *sf, char *s)
{
    int i = 0;
    char *last = NULL;
    char *match = NULL;

    last = s;
    for (i = 0; i < sf->num_matches; ++i)
    {
        match = sf->matches[i];

        last = strstr(last, match);
        if (!last)
        {
            return false;
        }

        last += strlen(match);
    }

    return true;
}

bool run_sfilters(char *s)
{
    int i = 0;

    for (i = 0; i < num_sfilters; ++i)
    {
        if (run_sfilter(&sfilters[i], s))
        {
            return true;
        }
    }

    return false;
}