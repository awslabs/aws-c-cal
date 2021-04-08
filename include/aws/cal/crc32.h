#ifndef AWS_CAL_CRC32_H_
#define AWS_CAL_CRC32_H_

#include <aws/cal/hash.h>

struct aws_hash *aws_crc32_default_new(struct aws_allocator *allocator);
struct aws_hash *aws_crc32c_default_new(struct aws_allocator *allocator);

#endif /* AWS_CAL_CRC32_H_ */
