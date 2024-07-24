#ifndef BUFFER_H
#define BUFFER_H

#include <stdint.h>
#include <sys/queue.h>
#include <linux/perf_event.h>

typedef struct event {
	struct perf_event_header hdr;
	uint32_t size;
	uint64_t type;
	uint8_t data[0];
}__attribute__((packed)) event_t;

typedef struct lost_event{
	struct perf_event_header hdr;
	uint64_t id;
	uint64_t lost;
} lost_event_t;

typedef struct evhandler {
	TAILQ_ENTRY(evhandler) node;
	uint64_t type;
	void* priv;
	int (*handle)(event_t* ev, void* priv);
} evhandler_t;

typedef struct evqueue {
	int fd;
	struct perf_event_mmap_page* mem;
	void* buf;
} evqueue_t;


typedef struct evpipe {
	int mapfd;
	uint32_t ncpus;
	struct pollfd* poll;
	evqueue_t* q;
} evpipe_t;

extern int evpipe_init(evpipe_t* evp, size_t qsize);
extern void evhandler_register(evhandler_t* evh);
#endif
