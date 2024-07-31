#include <stdio.h>
#include <string.h>

#include "ast.h"
#include "symtable.h"
#include "buffer.h"
#include "dsl.h"
#include "ut.h"
#include "compiler.h"

ssize_t get_stack_addr(node_t* n, ebpf_t* e) {
	if (n->type == NODE_MAP) {
		e->st->sp -= n->annot.keysize;
	}
	
	e->st->sp -= n->annot.size;
	return e->st->sp;
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
	case 'c':
		printf(fmt, (char)num);
		break;
	case 'd':
		printf(fmt, (int)num);
		break;
	}

	free(fmt);
}

static int event_output(event_t* ev, void* _call) {
	node_t* arg, *call = _call;
	char* fmt, *spec;
	void* data = ev->data;
	
	arg = call->call.args->next->rec.args->next; 
	for (fmt = call->call.args->name; *fmt; fmt++) {
		if (*fmt == '%' && arg) {
			spec = fmt;
			fmt = strpbrk(spec, "scd");
			if (!fmt) 
				break;
			printf_spec(spec, fmt, data, arg);
			
			data += arg->annot.size;
			if (arg->next) {
				arg = arg->next;
			} else {
				arg = NULL;
			}
		} else {
			fputc(*fmt, stdout);
			//printf("%c", *fmt);
		}
	}
	return 0;
}

void annot_perf_output(node_t* call, ebpf_t* e) {
	evhandler_t* evh;
	node_t* meta, *head, *varg, *rec;
	size_t size; 
	ssize_t addr;

	varg = call->call.args;
	if (!varg) {
		_errno("should has a string fromat");
		return -1;
	}
    
	evh = checked_calloc(1, sizeof(*evh));
    evh->priv = call;
	evh->handle = event_output;
	
	evhandler_register(evh);	
	
	meta = node_int_new(evh->type);
	meta->annot.type = NODE_INT;
	meta->annot.size = 8;
	meta->next = varg->next;
	
	rec = node_rec_new(meta);
	varg->next = rec;
	
	size = meta->annot.size;	
	
	//get the function value and get the size
	//but we don't store format string
	for (head = meta->next; head != NULL; head = head->next) {
		get_annot(head, e);
		size += head->annot.size;
	}
	
	rec->annot.size = size;
	rec->annot.addr = get_stack_addr(rec, e);
}

void annot_map(node_t* n, ebpf_t* e) {
   	node_t* lval = n->assign.lval, *expr = n->assign.expr;

    if (expr->type == NODE_VAR) {
        symtable_transfer(e->st, expr);  
    } else {
        get_annot(expr, e);
    }
   
   lval->annot.type = expr->annot.type;
   lval->annot.size = expr->annot.size;
   
   if (lval->type == NODE_MAP) {
        node_t* head, *args = lval->map.args;
        ssize_t ksize = 0; 
        
        for (head = args; head != NULL; head = head->next) {
            get_annot(head, e);
            ksize += head->annot.size;
        }

        lval->annot.keysize = ksize;
		lval->annot.addr = get_stack_addr(lval, e);
        
		int fd = bpf_map_create(BPF_MAP_TYPE_HASH, ksize, lval->annot.size, 1024);
        lval->annot.mapid = fd;
   }
    
    symtable_add(e->st, n->assign.lval);     
}


void annot_comm(node_t* n, ebpf_t* e) {
    n->annot.type = NODE_STRING;
    n->annot.size = _ALIGNED(16);
    n->annot.addr = symtable_reserve(e->st, n->annot.size);
    n->annot.loc = LOC_STACK;
}

void call_annot(node_t* n, ebpf_t* e) {
	if (!strcmp("comm", n->name)) {
       annot_comm(n, e);
    } else if (!strcmp("out", n->name)) {
		annot_perf_output(n, e);
	} else {
	  n->annot.type = NODE_INT;
	  n->annot.size = 8;
	  n->annot.loc = LOC_REG;
    }
}

void get_annot(node_t* n, ebpf_t* e) {
     switch(n->type) {
        case NODE_INT:
            n->annot.type = NODE_INT;
            n->annot.size = sizeof(n->integer);
            break;
        case NODE_STRING:
            n->annot.type = NODE_STRING;
            n->annot.size = _ALIGNED(strlen(n->name) + 1);
            n->annot.addr = symtable_reserve(e->st, n->annot.size);
            n->annot.loc  = LOC_STACK; 
            break;
        case NODE_CALL:
            call_annot(n, e);
			break;
       case NODE_ASSIGN:
            annot_map(n, e);
            break;
        default:
            break;
    }
}

ebpf_t* ebpf_new() {
    ebpf_t* e = checked_calloc(1, sizeof(*e));
    e->st = symtable_new();     
	e->ip = e->prog;
    e->evp = checked_calloc(1, sizeof(*e->evp));
	return e;
}
