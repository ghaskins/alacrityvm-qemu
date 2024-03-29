/*
 * Copyright (c) 2003-2008 Fabrice Bellard
 * Copyright (c) 2009 Red Hat, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#ifndef QEMU_NET_QUEUE_H
#define QEMU_NET_QUEUE_H

#include "qemu-common.h"

typedef struct NetPacket NetPacket;
typedef struct NetQueue NetQueue;

typedef void (NetPacketSent) (VLANClientState *sender, ssize_t ret);

typedef ssize_t (NetPacketDeliver) (VLANClientState *sender,
                                    const uint8_t *buf,
                                    size_t size,
                                    int raw,
                                    void *opaque);

typedef ssize_t (NetPacketDeliverIOV) (VLANClientState *sender,
                                       const struct iovec *iov,
                                       int iovcnt,
                                       void *opaque);

NetQueue *qemu_new_net_queue(NetPacketDeliver *deliver,
                             NetPacketDeliverIOV *deliver_iov,
                             void *opaque);
void qemu_del_net_queue(NetQueue *queue);

ssize_t qemu_net_queue_send(NetQueue *queue,
                            VLANClientState *sender,
                            const uint8_t *data,
                            size_t size,
                            int raw,
                            NetPacketSent *sent_cb);

ssize_t qemu_net_queue_send_iov(NetQueue *queue,
                                VLANClientState *sender,
                                const struct iovec *iov,
                                int iovcnt,
                                NetPacketSent *sent_cb);

void qemu_net_queue_purge(NetQueue *queue, VLANClientState *from);
void qemu_net_queue_flush(NetQueue *queue);

#endif /* QEMU_NET_QUEUE_H */
