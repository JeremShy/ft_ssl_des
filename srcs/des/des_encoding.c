#include <ft_ssl.h>

/*
	* Datalen is in bytes size. 
*/

void	print_block_as_char(uint64_t in)
{
	printf("block : %c%c%c%c%c%c%c%c\n", (char)in, *(((char*)&in) + 1), *(((char*)&in) + 2), *(((char*)&in) + 3), *(((char*)&in) + 4), *(((char*)&in) + 5), *(((char*)&in) + 6), *(((char*)&in) + 7));
}

void	print_half_block_as_char(uint32_t in)
{
	printf("half_block : %c%c%c%c\n", (char)in, *(((char*)&in) + 1), *(((char*)&in) + 2), *(((char*)&in) + 3));
}

uint64_t	encode_block(t_des *des, const uint64_t in, t_uint48 ks[16])
{
	uint64_t	out;
	uint32_t	l;
	uint32_t	r;
	uint32_t	lp;
	uint32_t	rp;
	uint64_t	eed;

	(void)des;
	(void)ks;
	printf("size : %zu\n", sizeof(t_uint48));
	print_block_as_char(in);
	print_binary((void*)&in, 64, 4);
	printf("\n");
	permutate((const void*)&in, (void *)&out, g_des_ip, 64);
	printf("permutated : \n");
	print_binary((void*)&out, 64, 4);
	printf("\n");

	l = *(uint32_t*)&out;
	r = *(((uint32_t*)&out) + 1);

	printf("l : ");
	print_binary((void*)&l, 32, 4);
	printf("\n");
	printf("r : ");
	print_binary((void*)&r, 32, 4);
	printf("\n");
	int	i = 0;
	while (i < 16)
	{
		lp = r;
		permutate((void*)&r, (void*)&eed, g_des_e, 48);
		printf("after passing through e : ");
		print_binary((void*)&eed, 48, 6);
		printf("\n");
		exit(0);
		i++;
	}

	permutate((const void*)&out, (void *)&out, g_des_ip_inv, 64);
	return (out);
}

uint32_t	*des_encode(t_des *des, const uint8_t *data, size_t datalen, t_mode mode)
{
	size_t				n;
	uint64_t		*ret;
	const uint64_t	*in;
	t_uint48	ks[16];

	(void)mode;
	compute_key_schedule(ks, *(uint64_t*)des->key);
	printf("About to encode : [%s] - size : %zu\n", data, datalen);
	if (!(ret = malloc(datalen * sizeof(char))))
	{
		ft_putendl_fd("Error : Could not allocate enough space.", 2);
		return (NULL);
	}
	in = (const void*)data;
	n = 0;
	while (n < datalen / 8)
	{
		ret[n] = encode_block(des, in[n], ks);
		n++;
	}
	printf("Encoded value : %.*s\n", (int)datalen, (void*)ret);
	return (NULL);
}

/*
	* encode_block encodes a 64bit (8 bytes) long block, into another 64bit
	*  long block.
	* There are 8 chars in a block.
*/
