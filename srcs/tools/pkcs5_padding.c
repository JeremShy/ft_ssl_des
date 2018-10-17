#include <ft_ssl.h>

/*
	* Padds the given data according to the pkcs5 specifications.
	* Dynamically allocates memory, so be sure to free the output when done
	*  using it.
	* The new size will be stored in size.
*/

uint8_t	*pkcs5_padding(const uint8_t *original_data, size_t *size, size_t padd_multiple)
{
	size_t	new_size;

	new_size = (*size + 1) / padd_multiple * padd_multiple;
	return (NULL);
}
