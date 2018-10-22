#include <ft_ssl.h>

// D_i = HASH^count(D_(i-1) || data || salt)
// sizeof(D_I) = 16

int	bytes_to_key_md5(t_btk_md5_params *params)
{
	uint8_t	*buffer;
	int		required_rounds;
	int		i;
	size_t	salt_len;
	uint8_t	*rez;
	int		offset;

	rez = malloc(params->key_len + params->iv_len);
	buffer = malloc(16 + params->data_len + 8);
	required_rounds = (params->key_len + params->iv_len) / (16);
	if ((size_t)required_rounds * 16 != params->key_len + params->iv_len)
		required_rounds++;
	salt_len = 0;
	if (params->salt != NULL)
		salt_len = 8;
	i = 0;
	offset = 0;
	while (i < required_rounds)
	{
		if (i != 0)
		{
			offset = 16;
			ft_memcpy(rez + i * 16, rez + (i - 1) * 16, 16);
		}
		ft_memcpy(buffer, params->data + offset, params->data_len);
		if (params->salt != NULL)
			ft_memcpy(buffer + params->data_len + offset, params->salt, 8);
		i++;
	}
	// copy rez
	free(rez);
	return (0);
}
