#include <linux/string.h>


void *memmem(const void *haystack, size_t haystack_len, const void *needle, size_t needle_len)
{
    const char *pos = NULL;
    const char *last_pos = NULL;
    size_t left = 0;
    int needle_first = 0;

    // edge cases I don't wanna mess with
    if (0 == needle_len || needle_len > haystack_len)
    {
        return NULL;
    }

    pos = haystack;
    left = haystack_len;
    needle_first = *(const char*)needle;

    while (1)
    {
        last_pos = pos;
        pos = memchr(last_pos, needle_first, left);
        if (!pos)
        {
            break;
        }

        left -= (pos - last_pos);
        if (needle_len > left)
        {
            break;
        }

        if (0 == memcmp(pos, needle, needle_len))
        {
            return (void*)pos;
        }

        pos++;
        if (0 == left)
        {
            break;
        }
        left--;
    }

    return NULL;
}