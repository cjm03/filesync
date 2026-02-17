#ifndef FRAME_H
#define FRAME_H

#include <stdint.h>
#include <stddef.h>

#define PROTO_VER 1

typedef enum {
    MSG_HELLO       = 1,
    MSG_MANIFEST    = 2,
    MSG_DIFF        = 3,
    MSG_ERR         = 4,
    MSG_FILE_BEGIN  = 5,
    MSG_FILE_DATA   = 6,
    MSG_FILE_END    = 7,
    MSG_OK          = 8,
    MSG_DONE        = 9
} msg_type_t;

typedef struct {
    uint32_t payload_len;
    uint16_t type;
    uint8_t version;
    uint8_t flags;
} frame_header_t;

/*
    Send a frame with payload (can be null if len = 0)
*/
int FrameSend(int fd, msg_type_t type, const void* payload, uint32_t len);

/*
    Receive a frame header + payload (allocates payload, caller frees);
*/
int FrameRecv(int fd, frame_header_t* hdr, void** payload);

#endif // FRAME_H
