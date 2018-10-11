SRC_NAME = \
		main.c \
		get_file.c \
		parsing.c \
\
		tools/bitwise_operations.c \
		tools/debug.c \
		tools/general_operations.c \
		tools/hex_string_to_bytes.c \
		tools/permutate.c \
\
		md5/md5_main.c \
		md5/md5_parsing.c \
		md5/md5_parsing_2.c \
		md5/md5_stages.c \
		md5/md5_fghi.c \
		md5/md5_init.c \
\
		sha256/sha256_main.c \
		sha256/sha256_main_2.c \
		sha256/sha256_functions.c \
		sha256/sha256_functions_2.c \
		sha256/sha256_compute_buffer.c \
\
		base64/base64_main.c \
		base64/base64_encode.c \
		base64/base64_decode.c \
\
		des/des_main.c \
		des/des_globals.c \
		des/des_encoding.c \
\
		sha1/sha1_enc.c \
		sha1/sha1_main.c \
\
		hmac_sha1_main.c \
		pbkdf2_hmac_sha1.c

OBJ_PATH = ./obj/

INC_PATH = ./includes ./libsrcs/libft/includes/

SRC_PATH = ./srcs/

NAME = ft_ssl

CC = gcc
CFLAGS =  -Wextra -Wall -g
# CFLAGS =  -Wextra -Wall -Werror -g
LFLAGS = -lft
LIB_DIR=./lib/

OBJ_NAME = $(SRC_NAME:.c=.o)

SRC = $(addprefix $(SRC_PATH),$(SRC_NAME))
OBJ = $(addprefix $(OBJ_PATH),$(OBJ_NAME))
OBJ_NAME = $(SRC_NAME:.c=.o)

INC = $(addprefix -I,$(INC_PATH))

TEST = $(addprefix $(SRC_PATH),tests/tests.py)
TESTS_NAME = run_tests.py

all : $(LIB_DIR) $(TESTS_NAME) $(NAME)

$(TESTS_NAME):
	@ln -sv $(TEST) $(TESTS_NAME)
	@chmod +x $(TEST)

$(LIB_DIR):
	@mkdir -p $(LIB_DIR)

$(NAME) : $(OBJ)
	make -C libsrcs/libft
	$(CC) $(CFLAGS) $(OBJ) -L $(LIB_DIR) $(LFLAGS) -o $@

$(OBJ_PATH)%.o: $(SRC_PATH)%.c
	@mkdir -p $(shell dirname $@)
	@mkdir -p $(OBJ_PATH)
	$(CC) $(CFLAGS) $(INC) -o $@ -c $<

partial_clean:
	@rm -fv $(OBJ)
	@rmdir -p $(OBJ_PATH) 2> /dev/null || true

clean:
	@rm -fv $(OBJ)
	@rm -rfv $(OBJ_PATH) 2> /dev/null
	@make -C libsrcs/libft clean

fclean: clean
	@rm -fv $(NAME)
	@make -C libsrcs/libft fclean
	@rmdir lib 2> /dev/null || true

re: fclean all

.PHONY : all clean fclean re
