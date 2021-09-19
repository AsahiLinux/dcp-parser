#include <stdio.h>
#include <stdint.h>
#include <errno.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;

#define OSSERIALIZE_HDR 0xd3

int parse(u8 *blob, size_t size)
{
	if (size < 4)
		return -EINVAL;

	/* Parse the header */
	u32 *header = (u32 *) blob;

	if (*header != OSSERIALIZE_HDR)
		return -EINVAL;

	return 0;
}

int main(int argc, const char **argv) {
	FILE *fp = fopen("test.bin", "rb");
	u8 dump[53];
	fread(dump, 1, sizeof(dump), fp);
	fclose(fp);

	parse(dump, sizeof(dump));
}
