#include <ft_ssl.h>

/*
	* Effectuates the permutation given in the permutation on in.
	* The output is stored in the out parameter. in and out can overlap.
	* in, out, and permutation must be at least size bytes long.
	* The permutation parameter is given as in the FIPS Pub 46-3.
	*
	* Return value : 1 if successfull, 0 else.
	* This function allocates temporary memory if size > 64.
	*  it can't fail if size <= 64.
*/

int8_t	permutate(const int8_t *in, int8_t *out, const int *permutation,
	size_t size)
{
	size_t		i;
	char		b[64];
	char		*buffer;

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
