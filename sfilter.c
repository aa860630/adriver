// runs our filters on packet data

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kernel.h>
#include <linux/string.h>

#include "defs.h"


static void print_sfilter(const struct sfilter *sf)
{
    int i = 0;

    pr_debug("sfilter matches: ");
    for (i = 0; i < sf->num_matches; ++i)
    {
        pr_debug("'%s', ", sf->matches[i]);
    }
    pr_debug("\n");
}

static bool run_sfilter(const struct sfilter *sf, const struct buf *buf)
{
    int i = 0;
    char *pos = NULL;
    size_t left = 0;

    char *match = NULL;
    size_t match_len = 0;

    pos = buf->data;
    left = buf->len;
    for (i = 0; i < sf->num_matches; ++i)
    {
        match = sf->matches[i];
        match_len = strlen(match);
       
        pos = memmem(pos, left, match, match_len);
        if (!pos)
        {
            return false;
        }

        pos += match_len;
        left -= match_len;
    }

    print_sfilter(sf); // for debugging
    return true;
}

static bool run_sfilters(const struct sfilter *sfilters, size_t num_sfilters, const struct buf *buf)
{
    int i = 0;

    for (i = 0; i < num_sfilters; ++i)
    {
        if (run_sfilter(&sfilters[i], buf))
        {
            return true;
        }
    }

    return false;
}

bool run_get_sfilters(const struct buf *buf)
{
    return run_sfilters(get_sfilters, num_get_sfilters, buf);
}

bool run_dns_sfilters(const struct buf *buf)
{
    return run_sfilters(dns_sfilters, num_dns_sfilters, buf);
}
