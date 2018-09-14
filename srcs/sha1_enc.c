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
	printf("Padded_size : %lu\n", (*size));
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
		w[t] = ((uint32_t*)m)[t];
		t++;
	}
	t = 16;
	while (t < 80)
	{
		w[t] = rotl(1, w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16]); //S^1(W(t-3) XOR W(t-8) XOR W(t-14) XOR W(t-16))
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
		temp = rotl(5, abcde[0]) + f(t, abcde[1], abcde[2], abcde[3]) + abcde[4] + w[t] + k[t]; //TEMP = S^5(A) + f(t;B,C,D) + E + W(t) + K(t);
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

// static void	compute_round(uint32_t h[5], const uint32_t k[80], void *m)
// {
// 	uint32_t		*w;
// 	size_t	t;
// 	size_t	s;
// 	uint32_t		temp;
// 	uint32_t		abcde[5];

// 	w = (uint32_t*)m;
// 	abcde[0] = h[0];
// 	abcde[1] = h[1];
// 	abcde[2] = h[2];
// 	abcde[3] = h[3];
// 	abcde[4] = h[4];
// 	t = 0;
// 	while (t <= 79)
// 	{
// 		s = t & MASK;
// 		if (t >= 16)
// 		{
// 			w[s] = rotl(1,	w[(s + 13) & MASK] ^
// 											w[(s + 8) & MASK] ^
// 											w[(s + 2) & MASK] ^
// 											w[s]);
// 		}
// 		temp = rotl(5, abcde[0]) + f(t, abcde[1], abcde[2], abcde[3]) + abcde[4] + w[s] + k[t]; //TEMP = S^5(A) + f(t;B,C,D) + E + W[s] + K(t);
// 		abcde[4] = abcde[3];
// 		abcde[3] = abcde[2];
// 		abcde[2] = rotl(30, abcde[1]);
// 		abcde[1] = abcde[0];
// 		abcde[0] = temp;
// 		t++;
// 	}
// 	h[0] = h[0] + abcde[0];
// 	h[1] = h[1] + abcde[1];
// 	h[2] = h[2] + abcde[2];
// 	h[3] = h[3] + abcde[3];
// 	h[4] = h[4] + abcde[4];
// }

/*
	** Blocks of 512 bits = 64 bytes = 16 words
*/

char	*compute_sha1(void *in, size_t len) // Len is in bytes
{
	char		*out;
	uint32_t			h[5];
	uint32_t			k[80];
	size_t	n;

	if (!(out = (char*)malloc(10 * sizeof(char))))
		return NULL;

	printf("Padded_size : %zu\n", len);
	init_constants(k, h);
	n = 0;
	while (n < len / 64)
	{
		compute_round(h, k, in + (n * 64));
		printf("round %zu {block_start : %zu, block_end : %zu}\n", n / 64, n * 64, (n + 1) * 64 - 1);
		n++;
	}
	printf("%08x%08x%08x%08x%08x\n", h[0], h[1], h[2], h[3], h[4]);
	free(in);
	return (out);
}

char	*sha1_encode(void *in, size_t len)
{
	size_t		padded_size;

	printf("Encoding string [%s], len = %zu\n", (char*)in, len);
	in = sha_padding(in, len, &padded_size);
	print_memory(in, padded_size);
	return (compute_sha1(in, padded_size));
}
