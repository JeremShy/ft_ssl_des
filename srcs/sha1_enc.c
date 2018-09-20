#include <ft_ssl.h>

# define MASK 0x0000000F

static uint32_t	f(uint32_t t, uint32_t b, uint32_t c, uint32_t d)
{
	if (t < 20)
		return ((b & c) | ((~b) & d));
	else if (t < 40)
		return (b ^ c ^ d);
	else if (t < 60)
		return ((b & c) | (b & d) | (c & d));
	else if (t < 80)
		return (b ^ c ^ d);
	else
	{
		ft_putstr_fd("ERROR 15\n", 2);
		return (-1);
	}
}

static void	init_constants(uint32_t k[80], uint32_t h[5])
{
	int	i;

	i = 0;
	while (i < 80)
	{
		if (i < 20)
			k[i] = 0x5A827999;
		else if (i < 40)
			k[i] = 0x6ED9EBA1;
		else if (i < 60)
			k[i] = 0x8F1BBCDC;
		else if (i < 80)
			k[i] = 0xCA62C1D6;
		i++;
	}
	h[0] = 0x67452301;
	h[1] = 0xEFCDAB89;
	h[2] = 0x98BADCFE;
	h[3] = 0x10325476;
	h[4] = 0xC3D2E1F0;
}

static	char *sha_padding(void *in, size_t original_len, size_t *size)
{
	char		*ret;

	(*size) = ((original_len / 64 + 1) * 64);
	if ((*size) - original_len <= 8)
		(*size) += 64;
	if (!(ret = malloc((*size) * sizeof(char))))
		return (NULL);
	ft_memcpy(ret, in, original_len);
	((uint8_t*)ret)[original_len] = 0x80;
	ft_bzero(ret + original_len + 1, (*size) - original_len - 8 - 1);
	*(uint64_t*)(ret + (*size) - 8) = end_conv_64(original_len << 3);
	return (ret);
}

static void	compute_round(uint32_t h[5], const uint32_t k[80], void *m)
{
	uint32_t	w[80];
	uint32_t	t;
	uint32_t	temp;
	uint32_t	abcde[5];

	t = 0;
	while (t < 16)
	{
		w[t] = end_conv_32(((uint32_t*)m)[t]);
		t++;
	}

	t = 16;
	while (t < 80)
	{
		w[t] = rotl(1, w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16]);
		t++;
	}

	abcde[0] = h[0];
	abcde[1] = h[1];
	abcde[2] = h[2];
	abcde[3] = h[3];
	abcde[4] = h[4];
	t = 0;
	while (t < 80)
	{
		temp = rotl(5, abcde[0]) + f(t, abcde[1], abcde[2], abcde[3]) + abcde[4] + w[t] + k[t];
		abcde[4] = abcde[3];
		abcde[3] = abcde[2];
		abcde[2] = rotl(30, abcde[1]);
		abcde[1] = abcde[0];
		abcde[0] = temp;
		t++;
	}
	h[0] = h[0] + abcde[0];
	h[1] = h[1] + abcde[1];
	h[2] = h[2] + abcde[2];
	h[3] = h[3] + abcde[3];
	h[4] = h[4] + abcde[4];
}

void	fill_out(char out[41], uint32_t h[5])
{
	int	i;

	i = 0;
	h[0] = end_conv_32(h[0]);
	h[1] = end_conv_32(h[1]);
	h[2] = end_conv_32(h[2]);
	h[3] = end_conv_32(h[3]);
	h[4] = end_conv_32(h[4]);
	while (i < 20)
	{
		out[i * 2] = ((((char *)h)[i] & 0xf0) >> 4) + '0';
		out[i * 2] > '9' ? out[i * 2] = out[i * 2] - '9' - 1 + 'a' : 0;
		out[i * 2 + 1] = (((char *)h)[i] & 0xf) + '0';
		out[i * 2 + 1] > '9' ?
			out[i * 2 + 1] = out[i * 2 + 1] - '9' - 1 + 'a' : 0;
		i++;
	}
	out[40] = '\0';
}

uint32_t	*compute_sha1(void *in, size_t len) // Len is in bytes
{
	uint32_t			k[80];
	size_t				n;
	uint32_t			*h;

	h = (uint32_t*)malloc(5 * sizeof(uint32_t));
	init_constants(k, h);
	n = 0;
	while (n < len / 64)
	{
		compute_round(h, k, in + (n * 64));
		n++;
	}
	h[0] = end_conv_32(h[0]);
	h[1] = end_conv_32(h[1]);
	h[2] = end_conv_32(h[2]);
	h[3] = end_conv_32(h[3]);
	h[4] = end_conv_32(h[4]);
	free(in);
	return (h);
}

uint32_t	*sha1_encode(void *in, size_t len)
{
	size_t		padded_size;

	if (!(in = sha_padding(in, len, &padded_size)))
		return (NULL);
	return (compute_sha1(in, padded_size));
}
