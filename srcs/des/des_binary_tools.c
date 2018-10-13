#include <ft_ssl.h>

uint32_t rotl_28(uint32_t n, uint32_t x)
{
	return ((x << n) | (x >> (28 - n)));
}
