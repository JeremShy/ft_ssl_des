#include <ft_ssl.h>

# define MASK 0x0000000F

static int	f(int t, int b, int c, int d)
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

static void	init_constants(int k[80], int h[5])
{
	ft_memset(k, 0x5A827999, 20);
	ft_memset(k + 20, 0x6ED9EBA1, 20);
	ft_memset(k + 40, 0x8F1BBCDC, 20);
	ft_memset(k + 60, 0xCA62C1D6, 20);
	h[0] = 0x67452301;
	h[1] = 0xEFCDAB89;
	h[2] = 0x98BADCFE;
	h[3] = 0x10325476;
	h[4] = 0xC3D2E1F0;
}

static	char *sha_padding(char *in, size_t original_len, size_t *size)
{
	char		*ret;

	(*size) = (original_len / 64 + 1 * 64);
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

static void	compute_round(int h[5], int k[80], void *m)
{
	char		*w;
	size_t	t;
	size_t	s;
	char		temp;
	char		abcde[5];

	w = (char*)m;
	abcde[0] = h[0];
	abcde[1] = h[1];
	abcde[2] = h[2];
	abcde[3] = h[3];
	abcde[4] = h[4];
	t = 0;
	while (t <= 79)
	{
		s = t & MASK;
		if (t >= 16)
		{
			w[s] = rotl(1,	w[(s + 13) & MASK] ^
											w[(s + 8) & MASK] ^
											w[(s + 2) & MASK] ^
											w[s]);
		}
		temp = rotl(5, abcde[0]) + f(t, abcde[1], abcde[2], abcde[3]) + abcde[4] + w[s] + k[t]; //TEMP = S^5(A) + f(t;B,C,D) + E + W[s] + K(t);
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

char	*compute_sha1(void *in, size_t len)
{
	char		*out;
	int			h[5];
	int			k[80];
	size_t	n;

	if (!(out = (char*)malloc(10 * sizeof(char))))
		return NULL;

	init_constants(k, h);
	n = 0;
	while (n < len / 16)
	{
		compute_round(h, k, in + n);
		printf("round %zu\n", n);
		n++;
	}
	printf("%08x%08x%08x%08x%08x\n", h[0], h[1], h[2], h[3], h[4]);
	return (out);
}

char	*sha1_encode(char *in, size_t len)
{
	size_t		padded_size;

	in = sha_padding(in, len, &padded_size);
	return (compute_sha1(in, padded_size));
}
