#include <ft_ssl.h>

int8_t	permutate(const int8_t *in, int8_t *out, const int *permutation, size_t size)
{
		size_t	i;
		char b[64];
		char	*buffer;

		if (size <= 64)
			buffer = b;
	else
			buffer = malloc(size);

		if (!buffer)
				return (0);
		i = 0;
		while (i < size)
		{
			buffer[i] = in[permutation[i] - 1];
			i++;
		}
		ft_memcpy(out, buffer, size);
		if (size > 64)
			free(buffer);
		return (1);
}