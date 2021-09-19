#include <stdio.h>
#include <stdint.h>
#include <errno.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;

#define OSSERIALIZE_HDR 0xd3

struct ctx {
	void *blob;
	u32 pos, len;
};

int parse(void *blob, size_t size)
{
	struct ctx ctx = {
		.blob = blob,
		.len = size,
		.pos = 0,
	};

	u32 *header = ctx.blob + ctx.pos;

	/* Parse the header */
	if (ctx.pos + sizeof(*header) > ctx.len)
		return -EINVAL;

	if (*header != OSSERIALIZE_HDR)
		return -EINVAL;

	return 0;
}

int main(int argc, const char **argv) {
	FILE *fp = fopen("test.bin", "rb");
	u8 dump[53];
	fread(dump, 1, sizeof(dump), fp);
	fclose(fp);

	int ret;
	ret = parse(dump, sizeof(dump));
	printf("%u\n", ret);
}
