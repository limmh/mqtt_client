/*
MIT License

Copyright (c) 2017 MH Lim

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined _WIN32 || defined _WIN64
#include <Windows.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

typedef int (*getchar_fptr_s)(void);

char *utils_strdup(const char *src)
{
	size_t length = strlen(src);
	size_t size = length + 1;
	char *str = (char*) malloc(size);
	if (str) {
		strncpy(str, src, length);
		str[length] = '\0';
	}
	return str;
}

void utils_delete(void *mem)
{
	free(mem);
}

size_t utils_gets_internal(char **in, getchar_fptr_s fn)
{
	if (!in)
		return 0;

	if (*in)
		free(*in);

	size_t buffer_size = 128, count = 0;
	*in = (char*) malloc(buffer_size);
	if (NULL == *in)
		return 0;

	int c = fn();
	while (c != '\n') {
		if (c != '\b') {
			(*in)[count] = (char) c;
			++count;
		} else {
			if (count > 0) {
				--count;
				(*in)[count] = '\0';
			}
		}

		if (count >= buffer_size) {
			size_t new_size = buffer_size + buffer_size;
			char *p = (char*) realloc(*in, new_size);
			if (!p) {
				count--;
				(*in)[count] = '\0';
				return count;
			}
			*in = p;
			buffer_size = new_size;
		}
		c = fn();
	}

	(*in)[count] = '\0';
	return count;
}

static int utils_getchar_password(void)
{
	char c;
#if defined _WIN32 || defined _WIN64
	static int n = 0;
	DWORD nread = 0;
	HANDLE h = GetStdHandle(STD_INPUT_HANDLE);
	ReadConsoleA(h, &c, 1, &nread, NULL);
	if ('\r' == c)
		c = '\n';
	switch (c) {
	case '\b':
		if (n > 0) {
			printf("\b \b");
			n--;
		}
		break;
	case '\n':
		printf("\n");
		break;
	default:
		printf("*");
		n++;
		break;
	}
#else
	c = (char) fgetc(stdin);
#endif
	return c;
}

size_t utils_get_stdin(char **in)
{
	return utils_gets_internal(in, getchar);
}

size_t utils_gets_quiet(char **in)
{
	size_t len = 0;
#if defined _WIN32 || defined _WIN64
	HANDLE h;
	DWORD con_orig, con_quiet;
	h  = GetStdHandle(STD_INPUT_HANDLE);
	GetConsoleMode(h, &con_orig);
	con_quiet &= ~ENABLE_ECHO_INPUT;
	con_quiet &= ~ENABLE_LINE_INPUT;
	SetConsoleMode(h, con_quiet);
	len = utils_gets_internal(in, utils_getchar_password);
	SetConsoleMode(h, con_orig);
	return len;
#else
	struct termios ts_quiet, ts_orig;
	tcgetattr(0, &ts_orig);
	ts_quiet = ts_orig;
	ts_quiet.c_lflag &= ~ECHO;
	tcsetattr(0, TCSANOW, &ts_quiet);
	len = utils_gets_internal(in, utils_getchar_password);
	tcsetattr(0, TCSANOW, &ts_orig);
	return len;
#endif
}

size_t utils_read_file(const char *file, void **out)
{
	if (*out)
		free(*out);

	size_t size = 0;
	FILE *fp = fopen(file, "rb");
	if (!fp)
		return size;

	size_t buffer_size = 128;
	*out = malloc(buffer_size);
	if (NULL == *out) {
		fclose(fp);
		return size;
	}

	char *buffer = (char*) *out;
	int c = fgetc(fp);
	while (EOF != c) {
		buffer[size] = (char) c;
		size++;
		if (size >= buffer_size) {
			size_t new_size = buffer_size + buffer_size;
			char *p = (char*) realloc(buffer, new_size);
			if (!p)
				return size;
			buffer = p;
			*out = buffer;
			buffer_size = new_size;
		}
		c = fgetc(fp);
	}
	return size;
}

void utils_generate_random_sequence(const char *pattern, size_t pattern_size, char *buffer, size_t buffer_size)
{
	size_t n = buffer_size - 1;
	for (size_t i = 0; i < n; ++i)
		buffer[i] = pattern[rand() % pattern_size];
	buffer[buffer_size - 1] = '\0';
}

static unsigned char hex_to_nibble(unsigned char hex)
{
	if (hex >= '0' && hex <= '9')
		return (hex - '0');
	if (hex >= 'A' && hex <= 'F')
		return (hex - 'A' + 10);
	if (hex >= 'a' && hex <= 'f')
		return (hex - 'a' + 10);
	return 0;
}

int utils_hex_sequence_is_valid(const char *hex_sequence)
{
	const char *h = hex_sequence;
	size_t count = 0;
	while (*h) {
		char c = *h;
		int valid = ((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f'));
		if (!valid)
			return 0;
		++h;
		++count;
	}

	if ((count % 2) != 0)
		return 0;

	return 1;
}

size_t utils_hex_sequence_to_binary_data(const char *hex_sequence, void **output)
{
	size_t len = strlen(hex_sequence);
	if ((len % 2) != 0)
		len--;

	if (*output)
		free(*output);

	if (len < 1) {
		*output = NULL;
		return 0;
	}

	size_t count = 0;
	size_t buffer_size = 32;
	*output = malloc(buffer_size);
	unsigned char *p = (unsigned char*) *output;

	for (size_t i = 0; i < len; i += 2) {
		unsigned char h = hex_to_nibble((unsigned char) hex_sequence[i]);
		unsigned char l = hex_to_nibble((unsigned char) hex_sequence[i + 1]);
		p[count] = (h << 4) | l;
		count++;
		if (count >= buffer_size) {
			size_t new_size = buffer_size + buffer_size;
			void *buf_new = realloc(*output, new_size);
			if (!buf_new)
				return count;
			*output = buf_new;
			buffer_size = new_size;
		}
	}
	return count;
}
