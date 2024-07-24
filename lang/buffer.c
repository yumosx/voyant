#include <string.h>
#include <stdio.h>
#include <poll.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/queue.h>
#include <linux/version.h>
#include <linux/bpf.h>
#include <inttypes.h>
#include <inttypes.h>

#include "buffer.h"
#include "syscall.h"
#include "ut.h"

static uint64_t next_type = 0;

TAILQ_HEAD(evhandlers, evhandler);
static struct evhandlers evh_list = TAILQ_HEAD_INITIALIZER(evh_list);

void evhandler_register(evhandler_t* evh) {
	evh->type = next_type++;
	TAILQ_INSERT_TAIL(&evh_list, evh, node);
}

static evhandler_t* evhandler_find(uint64_t type) {
	evhandler_t* evh;

	TAILQ_FOREACH(evh, &evh_list, node) {
		if (evh->type == type)
			return evh;
	}

	return NULL;
}

static int event_handle(event_t* ev, size_t size) {
	evhandler_t* evh;
	evh = evhandler_find(ev->type);
	if (!evh) {
		_error("unknown event: type:%#"PRIx64" size:%#zx\n", 
				ev->size, size);	
		return -1;
	}

	return evh->handle(ev, evh->priv);
}

void evqueue_init(evpipe_t* evp, uint32_t cpu, size_t size) {
	struct perf_event_attr attr = {0};
	evqueue_t* q = &evp->q[cpu];	
	int err;

	attr.type = PERF_TYPE_SOFTWARE;
	attr.config = PERF_COUNT_SW_BPF_OUTPUT;
	attr.sample_type = PERF_SAMPLE_RAW;
	attr.wakeup_events = 1;

	q->fd = perf_event_open(&attr, -1, cpu, -1, 0);
	if (q->fd < 0) {
		_errno("could not create queue");
		return q->fd;
	}

	err = bpf_map_update(evp->mapfd, &cpu, &q->fd, BPF_ANY);
	if (err) {
		_errno("could not link map to queue");
		return err;
	}
	

	size += sysconf(_SC_PAGESIZE);
	q->mem = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, q->fd, 0);
	if (q->mem == MAP_FAILED) {
		_errno("clould not mmap queue");
		return -1;
	}

	evp->poll[cpu].fd = q->fd;
	evp->poll[cpu].events = POLLIN;

	return 0;
}


int evpipe_init(evpipe_t* evp, size_t qsize) {
	uint32_t cpu;
	int err;
	
	evp->ncpus = sysconf(_SC_NPROCESSORS_ONLN);
	evp->mapfd = bpf_map_create(BPF_MAP_TYPE_PERF_EVENT_ARRAY, sizeof(uint32_t), sizeof(int), evp->ncpus);
	
	if (evp->mapfd < 0) {
		_errno("clould not create map");
		return evp->mapfd;
	}

	evp->q = checked_calloc(evp->ncpus, sizeof(*evp->q)); 
	evp->poll = checked_calloc(evp->ncpus, sizeof(*evp->poll));	

	for (cpu = 0; cpu < evp->ncpus; cpu++) {
		evqueue_init(evp, cpu, qsize);
	}
}


static inline uint64_t __get_head(struct perf_event_mmap_page* mem) {
	uint64_t head = *((volatile uint64_t *)&mem->data_head);

	asm volatile("" ::: "memory");
	return head;
}

static inline void __set_tail(struct perf_event_mmap_page* mem, uint64_t tail) {
	asm volatile("" ::: "memory");	
	mem->data_tail = tail;
}


int evqueue_drain(evqueue_t* q, int strict) {
	struct lost_event* lost;
	uint16_t size, offs, head, tail;
	uint8_t* base, *this, *next;
	event_t* ev;
	int err = 0;

	size = q->mem->data_size;
	offs = q->mem->data_offset;
	base = (uint8_t*)q->mem + offs;

	for (head = __get_head(q->mem); q->mem->data_tail != head; ) {
		tail = q->mem->data_tail;

		this = base + (tail % size);
		ev = (void*) this;
		next = base + (tail + ev->hdr.size) % size;

		if (next < this) {
			size_t left = (base + size) - this;
			q->buf = realloc(q->buf, ev->hdr.size);
			memcpy(q->buf, this, left);
			memcpy(q->buf + left, base, ev->hdr.size - left);
			ev = q->buf;
		}

		switch(ev->hdr.type) {
			case PERF_RECORD_SAMPLE:
				err = event_handle(ev, ev->hdr.size);
				break;
			case PERF_RECORD_LOST:
				lost = (void*) ev;
				if (strict) {
					_error("lost");
				}
				break;
			default:
				err = -1;	
				_error("unknown");
				break;
		}

		if (err)
			break;
	}
}


int evpipe_loop(evpipe_t* evp, int* sig, int strict) {
	int cpu, err, ready;

	for (;!(*sig);) {
		ready = poll(evp->poll, evp->ncpus, -1);
		if (ready <= 0) return ready ? : 0; 
		
		for (cpu = 0; ready && (cpu < evp->ncpus); cpu++) {
			if (!(evp->poll[cpu].revents & POLLIN))
				continue;
			err = evqueue_drain(&evp->q[cpu], strict);
			if (err) 
				return err;
			ready--;
		}
	}
}
