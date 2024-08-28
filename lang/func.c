#include <stdint.h>
#include <stdio.h>

#include "func.h"
#include "buffer.h"
#include "ut.h"

static int annot_rint(node_t* n) {
    n->annot.type = ANNOT_RINT;
    n->annot.size = 8;
}

static int annot_rstr(node_t* n) {
    n->annot.type = ANNOT_RSTR;
	n->annot.size = _ALIGNED(16);
}

static int annot_probe_arg(node_t* n) {
	node_t* arg;
	intptr_t reg;

	arg = n->call.args;
	reg = arch_reg_arg(arg->integer);	

	n->integer = reg;
	n->annot.type = ANNOT_RINT;
	n->annot.size = sizeof(int64_t);
	n->annot.addr = -8;
}


static int annot_probe_str(node_t* n) {
	node_t* arg;

	n->annot.type = ANNOT_RSTR;
	n->annot.size = 64;
}


static void printf_spec(const char* spec, const char* term, void* data, node_t* arg) {
	int64_t num;
	size_t fmt_len;
	char* fmt;

	memcpy(&num, data, sizeof(num));
	fmt_len = term - spec + 1;
	fmt = strndup(spec, fmt_len);
	
	switch(*term) {
	case 's':
		printf(fmt, (char*)data);
		break;
	case 'd':
		printf(fmt, (int)num);
		break;
	}

	free(fmt);
}

static int event_output(event_t* ev, void* _call) {
	node_t* arg, *call = _call;
	char* fmt, *spec, *name, *str;
	void* data = ev->data;

	name = call->call.args->name;

	arg = call->call.args->next->rec.args->next; 
	str = call->call.args->name;	

	str_escape(str);	
	
	for (fmt = str; *fmt; fmt++) {
		if (*fmt == '%' && arg) {
			spec = fmt;
			fmt = strpbrk(spec, "scd");
			if (!fmt) 
				break;
			printf_spec(spec, fmt, data, arg);
			
			data += arg->annot.size;
			arg = arg->next;
		} else {
			fputc(*fmt, stdout);
		}
	}
	return 0;
}

static int annot_out(node_t* call) {
    evhandler_t* evh;
	node_t* meta, *head, *varg, *rec;
	size_t size; 
	ssize_t addr;

	varg = call->call.args;
	if (!varg) {
		_errmsg("should has a string fromat");
		return -1;
	}
    
	evh = vcalloc(1, sizeof(*evh));
    evh->priv = call;
	evh->handle = event_output;
	
	evhandler_register(evh);	
	
	meta = node_int_new(evh->type);
	meta->annot.type = ANNOT_INT;
	meta->annot.size = 8;
	meta->next = varg->next;
	
	rec = node_rec_new(meta);
	varg->next = rec;
}

static builtin_t global_builtins[] = {
    {
        .name = "pid",
        .annotate = annot_rint,
    },
    {
        .name = "cpu",
        .annotate = annot_rint,
    },
    {
        .name = "ns",
        .annotate = annot_rint,
    },
    {
        .name = "comm",
        .annotate = annot_rstr,
    },
	{
		.name = "arg",
		.annotate = annot_probe_str,
	},
    {
        .name = "out",
        .annotate = annot_out,
    },
};

int global_annot(node_t* n) {
    builtin_t* bi;

    for (bi = global_builtins; bi->name; bi++) {
        if (!strcmp(bi->name, n->name))
            return bi->annotate(n);
    }

    return -1;
}