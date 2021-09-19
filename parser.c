#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

#define round_up(x, y) ((x + (y - 1)) & ~(y - 1))
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;

#define OSSERIALIZE_HDR 0xd3

struct ctx {
	void *blob;
	u32 pos, len;
};

int parse_u32(struct ctx *ctx, u32 *out)
{
	if (ctx->pos + sizeof(*out) > ctx->len)
		return -EINVAL;

	memcpy(out, ctx->blob + ctx->pos, sizeof(*out));
	ctx->pos += sizeof(*out);
	return 0;
}

int parse_obj(struct ctx *ctx)
{
	int ret;
	u32 tag;

	/* Align to 32-bits */
	ctx->pos = round_up(ctx->pos, 4);

	ret = parse_u32(ctx, &tag);
	if (ret)
		return ret;

	printf("Tag: %X\n", tag);

	return 0;
}

int parse(void *blob, size_t size)
{
	struct ctx ctx = {
		.blob = blob,
		.len = size,
		.pos = 0,
	};

	int ret;
	u32 header;

	ret = parse_u32(&ctx, &header);
	if (ret)
		return ret;

	if (header != OSSERIALIZE_HDR)
		return -EINVAL;

	parse_obj(&ctx);

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
