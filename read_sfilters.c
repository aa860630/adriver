// Kernel file I/O, yay
// don't ever run this file
// better change to ioctls or sth

#include <linux/kernel.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/string.h>

#include "defs.h"

struct sfilter *get_sfilters;
char *raw_get_sfilters;
size_t num_get_sfilters;

struct sfilter *dns_sfilters;
char *raw_dns_sfilters;
size_t num_dns_sfilters;

// count occurences of c in s[:n]
static size_t memcnt(const void *s, int c, size_t n)
{
    const char *pos = NULL;
    const char *last_pos = NULL;
    size_t left = 0;
    size_t count = 0;

    pos = (const char*)s;
    left = n;
    while (1)
    {
        last_pos = pos;
        pos = memchr(pos, c, left);
        if (!pos)
        {
            break;
        }

        count++;

        left -= (pos - last_pos);

        if (0 == left)
        {
            break;
        }

        left--;
        pos++;
    }

    return count;
}

static bool read_all(struct file *filp, char *buf, size_t size)
{
    loff_t pos = 0;
    ssize_t bytes = 0;

    while (pos < size)
    {
        bytes = kernel_read(filp, pos, buf + pos, size - pos);

        if (0 >= bytes)
        {
            return false;
        }

        pos += bytes;
    }

    return true;
}

// reads the sfilters config file and returns raw data
// free with vfree
static char *read_all_file(const char *file, size_t *len)
{
    struct file *filp = NULL;
    struct kstat stat;
    char *raw_data = NULL;

    filp = filp_open(file, O_RDONLY, 0);
    if (!filp)
    {
        goto error;
    }

    if (vfs_getattr(&filp->f_path, &stat) || 0 == stat.size)
    {
        goto error;
    }

    raw_data = vmalloc(stat.size);
    if (!raw_data)
    {
        goto error;
    }

    if (!read_all(filp, raw_data, stat.size))
    {
        goto error;
    }

    filp_close(filp, NULL);
    filp = NULL;

    *len = stat.size;
    return raw_data;

error:
    if (NULL != filp)
    {
        filp_close(filp, NULL);
    }
    if (NULL != raw_data)
    {
        vfree(raw_data);
    }
    return NULL;
}

static bool parse_single_sfilter(struct sfilter *sf, char *s)
{
    char *pos = NULL;
    char *next = NULL;
    size_t i = 0;

    pos = s;
    while (pos)
    {
        next = strchr(pos, ' ');
        if (next) // if required
        {
            *next = '\0';
        }

        sf->matches[i++] = pos;

        pos = next;
    }
    sf->num_matches = i;
}

static struct sfilter *parse_sfilters(char *raw_data, size_t len, size_t *num_sfilters)
{
    size_t num_sfilters = 0;
    struct sfilter *sfilters = NULL;
    size_t i = 0;
    char *s = NULL;

    // count lines
    *num_sfilters = memcnt(raw_data, '\n', len);
    sfilters = kmalloc(sizeof(struct sfilter) * (*num_sfilters));
    if (!sfilters)
    {
        goto error;
    }

    s = raw_data
    for (i = 0; i < *num_sfilters; ++i)
    {
        *strchr(s, '\n') = '\0'; // it's 5 am
        parse_single_sfilter(&sfilters[i], s);
        s += strlen(s) + 1;
    }

    return sfilters;

error:
    if (NULL != sfilters)
    {
        kfree(sfilters);
    }
    return NULL;
}

static struct sfilter *read_and_parse_sfilters(const char *filename, char **raw_data, size_t *num_sfilters)
{
    size_t raw_len = 0;
    struct sfilter *sfilters = NULL;

    *raw_data = read_all_file(filename, &raw_len);
    if (!raw_data)
    {
        return NULL;
    }

    sfilters = parse_sfilters(*raw_data, raw_len, num_sfilters);
    if (!sfilters)
    {
        vfree(*raw_data);
        return NULL;
    }

    return sfilters;
}

bool read_config(void)
{
    get_sfilters = read_and_parse_sfilters(GET_SFILTERS_FILE, &raw_get_sfilters, &num_get_sfilters);
    if (NULL == get_sfilters)
    {
        return NULL;
    }

    dns_sfilters = read_and_parse_sfilters(DNS_SFILTERS_FILE, &raw_dns_sfilters, &num_dns_sfilters);
    return NULL != dns_sfilters;
}

void free_config(void)
{
    if (get_sfilters)
    {
        kfree(get_sfilters);
    }
    if (raw_get_sfilters)
    {
        vfree(raw_get_sfilters);
    }
    if (dns_sfilters)
    {
        kfree(dns_sfilters);
    }
    if (raw_dns_sfilters)
    {
        vfree(raw_get_sfilters);
    }
}