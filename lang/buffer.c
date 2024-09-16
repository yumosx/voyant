#include <string.h>
#include <stdio.h>
#include <poll.h>
#include <assert.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/queue.h>
#include <linux/bpf.h>
#include <inttypes.h>
#include <linux/version.h>

#include "buffer.h"
#include "errno.h"
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

static struct ret_value event_handle(event_t* ev, size_t size) {
	evhandler_t* evh;
	evh = evhandler_find(ev->type);
	if (!evh) {
		verror("unknown event: type:%#"PRIx64" size:%#zx\n", 
				ev->size, size);	
		return (struct ret_value) { .err = 1, .val = ENOSYS};
	}

	evh->handle(ev, evh->priv);
	return (struct ret_value) {};
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
		verror("could not create queue");
		return q->fd;
	}

	err = bpf_map_update(evp->mapfd, &cpu, &q->fd, BPF_ANY);
	if (err) {
		verror("could not link map to queue");
		return err;
	}
	

	size += sysconf(_SC_PAGESIZE);
	q->mem = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, q->fd, 0);
	if (q->mem == MAP_FAILED) {
		verror("clould not mmap queue");
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
		verror("clould not create map in evpipe init");
		return evp->mapfd;
	}

	evp->q = vcalloc(evp->ncpus, sizeof(*evp->q)); 
	evp->poll = vcalloc(evp->ncpus, sizeof(*evp->poll));	

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


struct ret_value evqueue_drain(evqueue_t* q) {
	struct lost_event* lost;
	struct ret_value ret = {};

	uint16_t size, offs, head, tail;
	uint8_t* base, *this, *next;
	event_t* ev;
	int err = 0;

	size = q->mem->data_size;
	offs = q->mem->data_offset;
	base = (uint8_t*)q->mem + offs;

	for (head = __get_head(q->mem); q->mem->data_tail != head; 
		__set_tail(q->mem, q->mem->data_tail+ev->hdr.size)) {
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
				ret = event_handle(ev, ev->hdr.size);
				break;
			case PERF_RECORD_LOST:
				lost = (void*) ev;
				verror("lost %"PRId64" events\n", lost->lost);
				ret.err = 1;
				ret.val = EOVERFLOW;
				break;
			default:
				verror("unknown perf event %#"PRIx32"\n", ev->hdr.type);
				ret.err = 1;
				ret.val = EINVAL;
				break;
		}

		if (ret.err || ret.exit)
			break;
	}

	return ret;
}

struct ret_value evpipe_loop(evpipe_t* evp, int* sig, int timeout) {
	struct ret_value ret;
	int cpu, ready;

	for (;!(*sig);) {
		ready = poll(evp->poll, evp->ncpus, timeout);
		
		if (ready < 0) {
			ret.err = 1;
			ret.val = errno;
			return ret;
		} 

		if (timeout == -1) {
			assert(ready);
		} else if (ready == 0) {
			return ret;
		}

		for (cpu = 0; ready && (cpu < evp->ncpus); cpu++) {
			if (!(evp->poll[cpu].revents & POLLIN))
				continue;
			ret = evqueue_drain(&evp->q[cpu]);
			
			if (ret.err | ret.exit) 
				return ret;

			ready--;
		}
	}
	return ret;
}

static void __key_workaround(int fd, void* key, size_t key_sz, void* val) {
	FILE* fp;
	int err;

	fp = fopen("/dev/urandom", "r");
	
	while (1) {
		err = bpf_map_lookup(fd, key, val);
		if (err)
			break;

		if (fread(key, key_sz, 1, fp) != 1)
			break;
	}
	fclose(fp);
}

void dump_str(FILE* fp, node_t* str, void* data) {
	int size = (int) str->annot.size;

	fprintf(fp, "%-*.*s", size, size, (const char*)data);
}

void dump_int(FILE* fp, node_t* integer, void* data) {
	int64_t num;

	memcpy(&num, data, sizeof(num));
	fprintf(fp, "%8" PRId64, num);
}


void dump(FILE* fp, node_t* n, void* data) {
	switch (n->annot.type) {
	case TYPE_STR:
	case TYPE_RSTR:
		dump_str(fp, n, data);
		break;
	case TYPE_INT:
		dump_int(fp, n, data);
		break;
	case TYPE_RINT:
		dump_int(fp, n, data);
		break;
	default:
		dump_int(fp, n, data);
		break;
	}
}

void map_dump(node_t* map) {
	node_t* arg;
	int err, c = 0;
	size_t fd, rsize, ksize, vsize;
	char* key, *val, *data;

	arg = map->map.args;
	fd = map->annot.mapid;
	ksize = arg->annot.size;
	vsize = map->annot.size;	
	rsize = ksize + vsize;

	data = vmalloc(rsize * 1024);
	key = data;
	val = data + ksize;
	
	__key_workaround(fd, key, ksize, val);
	
	for (err = bpf_map_next(fd, key, key); !err; 
		err = bpf_map_next(fd, key-rsize, key)) {
		
		err = bpf_map_lookup(fd, key, val);
		if (err) 
			goto out_free;
		c++;

		key += rsize;
		val += rsize;
	}
	printf("\n%s\n", map->name);
	for (key = data, val = data+ksize; c > 0; c--) {
		dump(stdout, arg, key);
		fputs("\t", stdout);
		dump(stdout, map, val);
		fputs("\n", stdout);
		
		key += rsize;
		val += rsize;
	}

out_free:
	free(data);
}
