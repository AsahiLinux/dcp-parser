#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <assert.h>
#include <errno.h>

#define WARN_ON(cond) assert(!cond)
#define round_up(x, y) ((x + (y - 1)) & ~(y - 1))
#define __packed __attribute__((packed))
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
#define ERR_PTR(err) NULL
#define PTR_ERR(ptr) -EINVAL
#define IS_ERR(ptr) (ptr == NULL)

#define OSSERIALIZE_HDR 0xd3

enum os_otype {
	OS_OTYPE_DICTIONARY = 1,
	OS_OTYPE_ARRAY = 2,
	OS_OTYPE_INT64 = 4,
	OS_OTYPE_STRING = 9,
	OS_OTYPE_BLOB = 10,
	OS_OTYPE_BOOL = 11
};

struct os_tag {
	unsigned int size : 24;
	enum os_otype type : 5;
	unsigned int padding : 2;
	bool last : 1;
} __packed;

struct ctx {
	void *blob;
	u32 pos, len;
};

void *parse_bytes(struct ctx *ctx, size_t count)
{
	void *ptr = ctx->blob + ctx->pos;

	if (ctx->pos + count > ctx->len)
		return ERR_PTR(-EINVAL);

	ctx->pos += count;
	return ptr;
}

u32 *parse_u32(struct ctx *ctx)
{
	return parse_bytes(ctx, sizeof(u32));
}

struct os_tag *parse_tag(struct ctx *ctx)
{
	return parse_bytes(ctx, sizeof(struct os_tag));
}

int parse_obj(struct ctx *ctx)
{
	struct os_tag *tag;

	/* Align to 32-bits */
	ctx->pos = round_up(ctx->pos, 4);

	tag = parse_tag(ctx);
	if (IS_ERR(tag))
		return PTR_ERR(ret);

	WARN_ON(tag->padding != 0);

	printf("Tag: %u %u %u\n", tag->last, tag->type, tag->size);

	switch (tag->type) {
	case OS_OTYPE_DICTIONARY:
	case OS_OTYPE_ARRAY:
	case OS_OTYPE_INT64:
	case OS_OTYPE_STRING:
	case OS_OTYPE_BLOB:
	case OS_OTYPE_BOOL:
	default:
		printf("TODO!\n");
		return -EINVAL;
	}

	return 0;
}

int parse(void *blob, size_t size)
{
	struct ctx ctx = {
		.blob = blob,
		.len = size,
		.pos = 0,
	};

	u32 *header = parse_u32(&ctx);
	if (IS_ERR(header))
		return PTR_ERR(header);

	if (*header != OSSERIALIZE_HDR)
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
