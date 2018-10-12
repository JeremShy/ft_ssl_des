#include <ft_ssl.h>

/*
	* Datalen is in bytes size. 
*/

void	print_block_as_char(uint64_t in)
{
	printf("in1 : %c%c%c%c%c%c%c%c\n", (char)in, *(((char*)&in) + 1), *(((char*)&in) + 2), *(((char*)&in) + 3), *(((char*)&in) + 4), *(((char*)&in) + 5), *(((char*)&in) + 6), *(((char*)&in) + 7));
}

uint64_t	encode_block(t_des *des, const uint64_t in)
{
	uint64_t out;
	print_block_as_char(in);

	permutate((const void*)&in, (void *)&out, g_des_ip, 64);



	permutate((const void*)&out, (void *)&out, g_des_ip_inv, 64);
	return (out);
}

uint32_t	*des_encode(t_des *des, const uint8_t *data, size_t datalen, t_mode mode)
{
	int				n;
	uint64_t		*ret;
	const uint64_t	*in;

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
		ret[n] = encode_block(des, in[n]);
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
