#ifndef DSL_H
#define DSL_H

#include "lexer.h"
#include "parser.h"
#include "ast.h"
#include "annot.h"
#include "ir.h"
#include "buffer.h"
#include "probe.h"

struct globals {
    char* name;
    int debug:1;
};

#endif