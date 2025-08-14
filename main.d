/+
 + Copyright (c) 2025 Brian Callahan <bcallah@openbsd.org>
 +
 + Permission to use, copy, modify, and distribute this software for any
 + purpose with or without fee is hereby granted, provided that the above
 + copyright notice and this permission notice appear in all copies.
 +
 + THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 + WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 + MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 + ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 + WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 + ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 + OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 +/

import std.algorithm;
import std.conv;
import std.file;
import std.process;
import std.stdio;
import std.string;
import std.uni;

struct Dictionary {
    string name;
    string code;
    int type;
}

struct Flags {
    bool Eflag, Qflag, Sflag, cflag, tflag, vflag;
    int Oflag;
    bool genlib;
}

enum word_type {
    func,
    var,
    any
}

enum block_type {
    sentinel,
    if_then,
    do_loop,
    begin_until
}

struct Block {
    ulong blockno;
    int type;
    bool have_else;
}

enum pass {
    collect,
    compile
}

class Forth {
    private Dictionary[] dictionary;
    private Flags flags;
    private Block[] blocks;
    private string[] globals, input_list, user_globals;
    private string av, current_file, current_function;
    private ulong blockno, depth, lineno, strno;
    private int p;
    private bool error, next_is_name;
    string last_data, last_func, outfile;
    bool in_func;

    this(string s, Dictionary[] dict) {
        auto i = lastIndexOf(s, '/') + 1;
        this.av = s[i .. $];
        this.flags.Oflag = 0;
        this.last_func = ".sentinel";
        foreach (d; dict) {
            d.code ~= "\n";
            this.dictionary ~= d;
        }
        this.blocks ~= Block(0, block_type.sentinel, false);
        ++this.blockno;
    }

    void set_genlib() {
        this.flags.genlib = true;
    }

    void set_Eflag() {
        this.flags.Eflag = true;
    }

    void set_Oflag(string flag) {
        switch (flag) {
        case "-O0":
            this.flags.Oflag = 0;
            break;
        case "-O":
        case "-O1":
            this.flags.Oflag = 1;
            break;
        case "-O2":
            this.flags.Oflag = 2;
            break;
        default:
            this.flags.Oflag = 2;
        }
    }

    void set_Qflag() {
        this.flags.Qflag = true;
    }

    void set_Sflag() {
        this.flags.Sflag = true;
    }

    void set_cflag() {
        this.flags.cflag = true;
    }

    void set_tflag() {
        this.flags.tflag = true;
    }

    void set_vflag() {
        this.flags.vflag = true;
    }

    bool genlib() {
        return this.flags.genlib;
    }

    bool Eflag() {
        return this.flags.Eflag;
    }

    int Oflag() {
        return this.flags.Oflag;
    }

    bool Qflag() {
        return this.flags.Qflag;
    }

    bool Sflag() {
        return this.flags.Sflag;
    }

    bool cflag() {
        return this.flags.cflag;
    }

    bool tflag() {
        return this.flags.tflag;
    }

    bool vflag() {
        return this.flags.vflag;
    }

    void global(string s) {
        this.globals ~= s;
    }

    void user_global(string s) {
        this.user_globals ~= s;
    }

    void write_code(string fn) {
        string s;
        bool print;

        if (this.flags.genlib)
            print = true;

        foreach (d; this.dictionary) {
            if (d.type == word_type.func) {
                if (d.name == this.last_func) {
                    print = true;
                    continue;
                }

                if (print) {
                    if (d.code != "\n")
                        s ~= d.code;
                }
            } else {
                s ~= "export data $" ~ d.name ~ " = align 8 { z 8 }\n";
            }
        }

        if (this.flags.genlib) {
            foreach (g; this.globals)
                s ~= g;
        }

        foreach (ug; this.user_globals)
            s ~= ug;

        std.file.write(fn, s);
    }

    void cg(string s) {
        ulong i;

        if (this.have_errors)
            return;

        if (!this.in_func) {
            this.fatal("code found outside word");
            return;
        }

        while (this.dictionary[i].name != this.current_function) {
            ++i;
            if (i == this.dictionary.length) {
                this.fatal("word \"" ~ this.current_function ~ "\" not found in dictionary");
                return;
            }
        }

        this.dictionary[i].code ~= s ~ "\n";
    }

    void next_is_function_name() {
        this.next_is_name = true;
    }

    bool function_is_main() {
        return (current_function == "main");
    }

    void function_name(string func) {
        Dictionary d = this.verify_word(func);
        this.current_function = d.name;

        if (func == "main") {
            this.cg("export function w $main(w %argc, l %argv) {\n@start\n@begin");
            this.cg("\tcall $.init(w %argc, l %argv)");
        } else {
            this.cg("export function $.4q." ~ this.current_function ~ "() {\n@start\n@begin");
        }
        this.next_is_name = false;
    }

    bool token_is_function_name() {
        return this.next_is_name;
    }

    string argv0() {
        return this.av;
    }

    ulong get_strno() {
        return this.strno;
    }

    void inc_strno() {
        ++this.strno;
    }

    bool have_errors() {
        return this.error;
    }

    void set_pass(int which) {
        this.p = which;
    }

    void fatal(string s) {
        stderr.writeln(argv0 ~ ": " ~ this.current_file ~ ":" ~ to!string(this.lineno) ~ ": error: " ~ s);
        this.error = true;
    }

    void fatal_hash() {
        this.fatal("invalid `#' line");
    }

    void fatal_string() {
        this.fatal("unterminated string");
    }

    void fatal_colon() {
        if (this.p == pass.collect)
            this.fatal("cannot nest functions");
    }

    void fatal_semicolon() {
        this.fatal("`;' without matching `:'");
    }

    void fatal_variable(string token) {
        this.fatal("invalid variable name: " ~ token);
    }

    void set_file_name(string s) {
        this.current_file = s.idup;
    }

    void next() {
        ++this.lineno;
    }

    void set_line(ulong l) {
        this.lineno = (l == 0) ? 0 : l - 1;
    }

    void reset_line() {
        this.lineno = 0;
    }

    string mangle(string func) {
        return func.replace(".", ".dot.").replace("-", ".dash.").replace("?", ".q.").replace("\\", ".b.");
    }

    Dictionary verify_word(string func) {
        string mangled = mangle(func);

        foreach (d; this.dictionary) {
            if (d.name == mangled) {
                return d;
            }
        }

        this.fatal("word \"" ~ func ~ "\" not found");

        Dictionary d = Dictionary("", "", word_type.any);

        return d;
    }

    void add_word(string func, int type) {
        string mangled = mangle(func);

        ulong i;
        foreach (d; this.dictionary) {
            if (d.name == mangled) {
                if (type != d.type) {
                    this.fatal("cannot redefine " ~ func ~ " between word and variable");
                    return;
                }
                this.dictionary[i].code = "\n";
                return;
            }
            ++i;
        }

        this.dictionary ~= Dictionary(mangled, "\n", type);
        this.next_is_name = false;
    }

    void add_input(string s) {
        this.input_list ~= s;
    }

    string[] inputs() {
        return this.input_list;
    }

    ulong get_depth() {
        return this.depth;
    }

    void create_block(int type) {
        this.blocks ~= Block(this.blockno, type, false);
        string no = to!string(this.blockno);

        ++this.depth;
        ++this.blockno;

        if (type == block_type.do_loop) {
            this.cg("\t%.i." ~ no ~ " =l call $.pop()");
            this.cg("\t%.bound." ~ no ~ " =l call $.pop()");
            this.cg("@.do." ~ no);
            this.cg("\t%.0 =l csltl %.i." ~ no ~ ", %.bound." ~ no);
            this.cg("\tjnz %.0, @.body." ~ no ~ ", @.loop." ~ no);
            this.cg("@.body." ~ no);
        } else if (type == block_type.begin_until) {
            this.cg("@.begin." ~ no);
        } else {
            this.cg("@.if." ~ no);
            this.cg("\t%.0 =l call $.pop()");
            this.cg("\t%.1 =l ceql %.0, 0");
            this.cg("\tjnz %.1, @.else." ~ no ~ ", @.body." ~ no);
            this.cg("@.body." ~ no);
        }
    }

    void else_block() {
        if (this.blocks[$ - 1].type != block_type.if_then) {
            this.fatal("no `if' to match this `else'");
            return;
        }

        this.blocks[$ - 1].have_else = true;

        string no = to!string(this.blocks[$ - 1].blockno);
        this.cg("\tjmp @.then." ~ no);
        this.cg("@.else." ~ no);
    }

    void reset_blocks() {
        while (this.blocks.length > 1)
            this.blocks = this.blocks.remove(this.blocks.length - 1);
        this.depth = 0;
    }

    void remove_block(int type) {
        if (this.depth == 0) {
            if (type == block_type.do_loop)
                this.fatal("no open do ... loop");
            else if (type == block_type.begin_until)
                this.fatal("no open begin ... until");
            else
                this.fatal("no open if ... then");
            return;
        }

        if (this.blocks[$ - 1].type != type) {
            if (type == block_type.do_loop)
                this.fatal("mismatch: expected `then'");
            else if (type == block_type.begin_until)
                this.fatal("mismatch: expected `until'");
            else
                this.fatal("mismatch: expected `loop'");

            return;
        }

        string no = to!string(this.blocks[$ - 1].blockno);
        if (type == block_type.do_loop) {
            this.cg("\t%.i." ~ no ~ " =l add %.i." ~ no ~ ", 1");
            this.cg("\tjmp @.do." ~ no);
            this.cg("@.loop." ~ no);
        } else if (type == block_type.begin_until) {
            this.cg("\t%.0 =l call $.pop()");
            this.cg("\t%.1 =l ceql %.0, 0");
            this.cg("\tjnz %.1, @.begin." ~ no ~ ", @.until." ~ no);
            this.cg("@.until." ~ no);
        } else {
            if (!this.blocks[$ - 1].have_else)
                this.cg("@.else." ~ no);
            this.cg("@.then." ~ no);
        }

        this.blocks = this.blocks.remove(this.blocks.length - 1);
        --this.depth;
    }

    bool loop_i() {
        ulong i;
        bool found;

        for (i = this.blocks.length - 1; i > 0; --i) {
            if (this.blocks[i].type == block_type.do_loop) {
                found = true;
                break;
            }
        }

        this.cg("\tcall $.push(l %.i." ~ to!string(this.blocks[i].blockno) ~ ")");

        return true;
    }
}

enum rm {
    i,
    ssa,
    s,
    o,
    all
}

void remove_all(Forth forth, string base, int target) {
    try {
        remove(base ~ ".i");
    } catch (FileException e) {
        // Do nothing
    }

    if (target > rm.i) {
        try {
            remove(base ~ ".ssa");
        } catch (FileException e) {
            // Do nothing
        }

        try {
            remove(base ~ ".qbe");
        } catch (FileException e) {
            // Do nothing
        }
    }

    if (target > rm.ssa) {
        try {
            remove(base ~ ".s");
        } catch (FileException e) {
            // Do nothing
        }
    }

    if (target > rm.s) {
        try {
            remove(base ~ ".o");
        } catch (FileException e) {
            // Do nothing
        }
    }

    if (target > rm.o) {
        try {
            remove(base);
        } catch (FileException e) {
            // Do nothing
        }

        if (!forth.outfile.empty) {
            try {
                remove(forth.outfile);
            } catch (FileException e) {
                // Do nothing
            }
        }
    }
}

string[] tokenize(Forth forth, string line) {
    string[] tokens;
    string token;
    ulong hash_counter, i, j;
    bool is_hash;

    forth.next;

    while (true) {
        if (i == line.length) {
            if (is_hash && (hash_counter < 2))
                forth.fatal_hash;
            return tokens;
        }

        while (isWhite(line[i])) {
            ++i;
            if (i == line.length) {
                if (is_hash && (hash_counter < 2))
                    forth.fatal_hash;
                return tokens;
            }
        }

        if (is_hash) {
            if (++hash_counter == 2) {
                if (line[i] != '"') {
                    forth.fatal_hash;
                    return tokens;
                }
                ++i;

                j = i;

                if (i == line.length) {
                    forth.fatal_string;
                    return tokens;
                }

                while (line[i] != '"') {
                    ++i;
                    if (i == line.length) {
                        forth.fatal_string;
                        return tokens;
                    }
                }

                if (i - j == 0)
                    forth.fatal("no file name");

                token = line[j .. i];
                tokens ~= token;

                ++i;

                continue;
            }
        }

        j = i;

        while (!isWhite(line[i])) {
            ++i;
            if (i == line.length)
                break;
        }

        token = line[j .. i];

        if (is_hash) {
            tokens ~= token;
            continue;
        }

        // Comments, special case, skipped without tokenizing
        if (token == "(") {
            while (line[i] != ')') {
                if (i == line.length) {
                    forth.fatal("unterminated comment");
                    return tokens;
                }
                ++i;
            }
            ++i;
            continue;
        }

        // To end-of-line comment, no more coming, return what we have
        if (token == "\\")
            return tokens;

        // Strings, special case, tokenize whole string as one token
        if (token == ".\"") {
            tokens ~= token;
            while (isWhite(line[i])) {
                ++i;
                if (i == line.length) {
                    forth.fatal_string;
                    return tokens;
                }
            }

            j = i;

            while (line[i] != '"') {
                ++i;
                if (i == line.length) {
                    forth.fatal_string;
                    return tokens;
                }
            }

            ++i;
            token = line[j .. i];
        }

        // Hash, special case, similar to strings
        if (token == "#")
            is_hash = true;

        tokens ~= token;
    }
}

bool collect_functions(Forth forth, string line) {
    string[] tokens = tokenize(forth, line);
    bool got_number, got_file, first = true, is_hash;
    bool next_is_variable_name;

    foreach (token; tokens) {
        if (!first) {
            if (token == "#")
                forth.fatal_hash;
        }
        first = false;

        if (is_hash) {
            if (!got_number) {
                if (!isNumeric(token))
                    forth.fatal_hash;
                forth.set_line(to!ulong(token));
                got_number = true;
                continue;
            }

            if (!got_file) {
                if (token.length < 3)
                    forth.fatal_hash;
                forth.set_file_name(token);
                got_file = true;
                continue;
            }

            if (got_number && got_file) {
                if (isNumeric(token))
                    continue;
            }

            forth.fatal_hash;
        }

        if (token == ":") {
            if (next_is_variable_name) {
                forth.fatal_variable(token);
                continue;
            }
            if (forth.in_func)
                forth.fatal_colon;
            forth.in_func = true;
            forth.next_is_function_name;
            continue;
        }

        if (token == ";") {
            if (next_is_variable_name) {
                forth.fatal_variable(token);
                continue;
            }
            if (!forth.in_func)
                forth.fatal_semicolon;
            forth.in_func = false;
            continue;
        }

        if (token == "variable") {
            if (next_is_variable_name) {
                forth.fatal_variable(token);
                next_is_variable_name = false;
                continue;
            }

            if (forth.token_is_function_name) {
                forth.fatal_variable(token);
            } else {
                next_is_variable_name = true;
            }

            continue;
        }

        if (forth.token_is_function_name) {
            forth.add_word(token, word_type.func);
            continue;
        }

        if (next_is_variable_name) {
            forth.add_word(token, word_type.var);
            next_is_variable_name = false;
            continue;
        }

        if (token == "#")
            is_hash = true;
    }

    if (is_hash && (!got_number || !got_file))
        forth.fatal_hash;

    return forth.in_func;
}

bool compile(Forth forth, string line) {
    string[] tokens = tokenize(forth, line);
    bool got_number, got_file, first = true, have_notab, is_hash, is_string;
    bool is_variable;

    foreach (token; tokens) {
        if (!first) {
            if (token == "#")
                forth.fatal_hash;
        }
        first = false;

        if (is_hash) {
            if (!got_number) {
                if (!isNumeric(token))
                    forth.fatal_hash;
                forth.set_line(to!ulong(token));
                got_number = true;
                continue;
            }

            if (!got_file) {
                if (token.length < 3)
                    forth.fatal_hash;
                forth.set_file_name(token);
                got_file = true;
                continue;
            }

            if (got_number && got_file) {
                if (isNumeric(token))
                    continue;
            }

            forth.fatal_hash;
        }

        if (is_string) {
            dstring dstr = to!dstring(token);
            string str;
            string strno = to!string(forth.get_strno);
            for (ulong i = 0; i < dstr.length - 1; ++i) {
                uint c = to!uint(dstr[i]);
                str ~= ("w " ~ to!string(c) ~ ", ");
            }
            forth.user_global("\nexport data $_.L.str" ~ strno ~ " = align 4 { " ~ str ~ "w 0 }");
            forth.cg("\tcall $.string(l $_.L.str" ~ strno ~ ")");
            forth.inc_strno;
            is_string = false;
            continue;
        }

        if (isNumeric(token)) {
            forth.cg("\tcall $.push(l " ~ token ~ ")");
            continue;
        }

        if (token == ":") {
            if (forth.in_func)
                forth.fatal_colon;
            forth.in_func = true;
            forth.next_is_function_name;
            continue;
        }

        if (token == ";") {
            if (!forth.in_func)
                forth.fatal_semicolon;

            if (forth.get_depth != 0) {
                if (forth.blocks[$ - 1].type == block_type.do_loop)
                    forth.fatal("unterminated do ... loop");
                else
                    forth.fatal("unterminated if ... then");

                forth.reset_blocks;
            }

            if (forth.function_is_main)
                forth.cg("\tcall $.destroy()\n\tret 0\n}\n");
            else
                forth.cg("\tret\n}");

            forth.in_func = false;

            continue;
        }

        if (forth.token_is_function_name) {
            forth.function_name(token);
            continue;
        }

        switch (token) {
        case "+":
            forth.cg("\tcall $.addition()");
            break;
        case "-":
            forth.cg("\tcall $.subtraction()");
            break;
        case "*":
            forth.cg("\tcall $.multiplication()");
            break;
        case "/":
            forth.cg("\tcall $.division()");
            break;
        case "mod":
            forth.cg("\tcall $.modulo()");
            break;
        case "=":
            forth.cg("\tcall $.equal()");
            break;
        case "<>":
            forth.cg("\tcall $.notequal()");
            break;
        case ".":
            forth.cg("\tcall $.dot()");
            break;
        case "<":
            forth.cg("\tcall $.lessthan()");
            break;
        case ">":
            forth.cg("\tcall $.greaterthan()");
            break;
        case "#":
            is_hash = true;
            break;
        case "!":
            forth.cg("\tcall $.bang()");
            break;
        case "@":
            forth.cg("\tcall $.at()");
            break;
        case "?":
            forth.cg("\tcall $.at()");
            forth.cg("\tcall $.dot()");
            break;
        case "+!":
            forth.cg("\tcall $.addbang()");
            break;
        case ".\"":
            is_string = true;
            break;
        case "dup":
            forth.cg("\tcall $dup()");
            break;
        case "cr":
            forth.cg("\tcall $cr()");
            break;
        case "and":
            forth.cg("\tcall $and()");
            break;
        case "or":
            forth.cg("\tcall $or()");
            break;
        case "invert":
            forth.cg("\tcall $invert()");
            break;
        case "xor":
            forth.cg("\tcall $xor()");
            break;
        case "emit":
            forth.cg("\tcall $emit()");
            break;
        case "swap":
            forth.cg("\tcall $swap()");
            break;
        case "drop":
            forth.cg("\tcall $drop()");
            break;
        case "over":
            forth.cg("\tcall $over()");
            break;
        case "rot":
            forth.cg("\tcall $rot()");
            break;
        case "if":
            forth.create_block(block_type.if_then);
            break;
        case "then":
            forth.remove_block(block_type.if_then);
            break;
        case "else":
            forth.else_block;
            break;
        case "do":
            forth.create_block(block_type.do_loop);
            break;
        case "loop":
            forth.remove_block(block_type.do_loop);
            break;
        case "begin":
            forth.create_block(block_type.begin_until);
            break;
        case "until":
            forth.remove_block(block_type.begin_until);
            break;
        case "variable":
            is_variable = true;
            break;
        default:
            if (token == "i") {
                if (forth.loop_i == true)
                    continue;
            }

            Dictionary word = forth.verify_word(token);

            if (is_variable) {
                is_variable = false;
            } else {
                if (word.type == word_type.func)
                    forth.cg("\tcall $.4q." ~ word.name ~ "()");
                else
                    forth.cg("\tcall $.push(l $" ~ word.name ~ ")");
            }
        }
    }

    if (is_hash && (!got_number || !got_file))
        forth.fatal_hash;

    if (is_string)
        forth.fatal_string;

    return forth.in_func;
}

string create_base(string s) {
    auto i = lastIndexOf(s, '.');

    return s[0 .. i];
}

int main(string[] args) {
    import config;

    // These are special as they are created at configure time.
    Dictionary init = Dictionary(".init", init_init, word_type.func);
    Dictionary writestderr = Dictionary(".writestderr", writestderr_init, word_type.func);
    Dictionary key = Dictionary("key", key_init, word_type.func);

    // Our initial words.
    Dictionary[] dict;
    dict ~= push;
    dict ~= pop;
    dict ~= dup;
    dict ~= addition;
    dict ~= subtraction;
    dict ~= multiplication;
    dict ~= division;
    dict ~= modulo;
    dict ~= and;
    dict ~= or;
    dict ~= invert;
    dict ~= xor;
    dict ~= dot;
    dict ~= cr;
    dict ~= equal;
    dict ~= notequal;
    dict ~= drop;
    dict ~= over;
    dict ~= swap;
    dict ~= rot;
    dict ~= dotstring;
    dict ~= lessthan;
    dict ~= greaterthan;
    dict ~= emit;
    dict ~= key;
    dict ~= at;
    dict ~= bang;
    dict ~= addbang;
    dict ~= xmalloc;
    dict ~= destroy;
    dict ~= fatal;
    dict ~= init;
    dict ~= writestderr;
    dict ~= resize;
    // sentinel must be last
    dict ~= sentinel;

    Forth forth = new Forth(args[0], dict);

    // Some globals that we need.
    forth.global("export data $.stack = align 8 { z 8 }\n");
    forth.global("export data $.sp = align 8 { z 8 }\n");
    forth.global("export data $.sz = align 8 { z 8 }\n\n");
    forth.global("export data $.str.wfmtc = align 4 { w 37, w 108, w 99, w 0 }\n"); // "%lc"
    forth.global("export data $.str.wfmtd = align 4 { w 37, w 108, w 108, w 100, w 32, w 0 }\n"); // "%lld "
    forth.global("export data $.str.wfmts = align 4 { w 37, w 108, w 115, w 0 }\n"); // "%ls"
    forth.global("export data $.str.wnewline = align 4 { w 10, w 0 }\n"); // "\n"
    // "Stack underflow"
    forth.global("export data $.str.underflow = align 4 { w 83, w 116, w 97, w 99, w 107, w 32, w 117, w 110, w 100, w 101, w 114, w 102, w 108, w 111, w 119, w 0 }\n");
    // "malloc failed"
    forth.global("export data $.str.xmalloc = align 4 { w 109, w 97, w 108, w 108, w 111, w 99, w 32, w 102, w 97, w 105, w 108, w 101, w 100, w 0 }\n");
    forth.global("export data $.str.locale = align 1 { b \"\", b 0 }\n");

    bool first_arg = true, set_output, set_target;
    string target = default_target;

    foreach (arg; args) {
        bool output_set;

        if (first_arg) {
            first_arg = false;
            continue;
        }

        if (set_output) {
            if (output_set) {
                stderr.writeln(forth.argv0 ~ ": error: multiple -o flags");
                return 1;
            }

            forth.outfile = arg;

            output_set = true;
            set_output = false;

            continue;
        }

        if (set_target) {
            switch (arg) {
            case "amd64_sysv":
            case "amd64_apple":
            case "arm64":
            case "arm64_apple":
            case "rv64":
                break;
            default:
                stderr.writeln(forth.argv0 ~ ": error: unknown target `" ~ arg ~ "'");
                return 1;
            }
            target = arg;
            set_target = false;
            continue;
        }

        /+
         + -O0 = disable optimizations
         + -O1 = turn on peephole optimizer
         + -O2 = -O1 plus turn on optimized assembly routines
         +
         + -O == -O1
         + -O<anything else> == -O2
         +/
        if (arg.startsWith("-O")) {
            forth.set_Oflag(arg);
            continue;
        }

        if (arg[0] == '-') {
            switch (arg) {
            case "-E":
                forth.set_Eflag();
                break;
            case "-Q":
                forth.set_Qflag();
                break;
            case "-S":
                forth.set_Sflag();
                break;
            case "-c":
                forth.set_cflag();
                break;
            case "-o":
                set_output = true;
                break;
            case "-t":
                forth.set_tflag();
                set_target = true;
                break;
            case "-v":
                forth.set_vflag();
                break;
            case "-gen_lib":
                forth.set_genlib();
                break;
            default:
                stderr.writeln(forth.argv0 ~ ": warning: unknown option: " ~ arg);
            }
        } else {
            forth.add_input(arg);
        }
    }

    if (set_target && target.empty) {
        stderr.writeln(forth.argv0 ~ ": error: missing target for -t");
        return 1;
    }

    if (forth.inputs.empty) {
        stderr.writeln(forth.argv0 ~ ": error: no input files");
        return 1;
    }

    foreach (input; forth.inputs) {
        auto i = lastIndexOf(input, '.');

        if (i == -1 || input[i .. $] != ".4th") {
            forth.fatal("input file " ~ input ~ " must end in `.4th'");
            return 1;
        }
    }

    string[] ld = create_linker_invocation(forth);

    foreach (input; forth.inputs) {
        forth.reset_line;

        string base = create_base(input);

        /+
         + -C is to retain comments, otherwise a word
         + named "/*" or "//" would get removed.
         + Both clang and GNU cpp understand this flag.
         +/
        string[] pp;
        pp ~= preprocessor;
        pp ~= "-C";
        pp ~= "-nostdinc";
        pp ~= "-isystem";
        pp ~= incdir;
        if (need_Eflag) {
            pp ~= "-E";
            pp ~= "-x";
            pp ~= "c";
        }
        if (forth.vflag)
            pp ~= "-v";
        pp ~= input;
        if (need_Eflag)
            pp ~= "-o";
        if (forth.Eflag && !forth.outfile.empty)
            pp ~= forth.outfile;
        else
            pp ~= (base ~ ".i");

        if (forth.vflag) {
            bool first_s = true;
            foreach (s; pp) {
                if (first_s) {
                    first_s = false;
                    stderr.write(s);
                    continue;
                }
                stderr.write(" " ~ s);
            }
            stderr.writeln;
        }

        if (spawnProcess(pp).wait != 0) {
            forth.fatal("preprocessor failed");
            remove_all(forth, base, rm.all);
            return 1;
        }

        if (forth.Eflag)
            continue;

        string[] lines;
        try {
            lines = splitLines(cast(string)read(base ~ ".i"));
        } catch (FileException e) {
            stderr.writeln(forth.argv0 ~ " error: could not open preprocessed source");
            remove_all(forth, base, rm.all);
            return 1;
        }

        if (forth.vflag) {
            if (forth.Qflag && !forth.outfile.empty)
                stderr.writeln("forth1 -o " ~ forth.outfile ~ " " ~ (base ~ ".i"));
            else
                stderr.writeln("forth1 -o " ~ (base ~ ".ssa") ~ " " ~ (base ~ ".i"));
        }

        forth.set_pass(pass.collect);

        foreach (line; lines)
            forth.in_func = collect_functions(forth, line);

        if (forth.have_errors) {
            remove_all(forth, base, rm.all);
            return 1;
        }

        forth.reset_line;
        forth.set_pass(pass.compile);

        foreach (line; lines)
            forth.in_func = compile(forth, line);

        if (forth.in_func)
            forth.fatal("unterminated function");

        if (!forth.have_errors) {
            if (forth.Qflag && !forth.outfile.empty)
                forth.write_code(forth.outfile);
            else
                forth.write_code(base ~ ".ssa");

            if (forth.Qflag) {
                remove_all(forth, base, rm.i);
                continue;
            }

            string[] qbe_invocation;
            qbe_invocation ~= qbe;
            qbe_invocation ~= "-t";
            qbe_invocation ~= target;
            qbe_invocation ~= "-o";
            qbe_invocation ~= (base ~ ".qbe");
            qbe_invocation ~= (base ~ ".ssa");

            if (forth.vflag) {
                bool first_s = true;
                foreach (s; qbe_invocation) {
                    if (first_s) {
                        first_s = false;
                        stderr.write(s);
                        continue;
                    }
                    stderr.write(" " ~ s);
                }
                stderr.writeln;
            }

            if (spawnProcess(qbe_invocation).wait != 0) {
                forth.fatal("qbe failed");
                remove_all(forth, base, rm.all);
                return 1;
            }

            if (forth.vflag) {
                if (forth.Sflag && !forth.outfile.empty)
                    stderr.writeln("opt -o " ~ forth.outfile ~ " " ~ (base ~ ".qbe"));
                else
                    stderr.writeln("opt -o " ~ (base ~ ".s") ~ " " ~ (base ~ ".qbe"));
            }

            if (!O(forth, base))
                return 1;

            if (forth.Sflag) {
                remove_all(forth, base, rm.ssa);
                continue;
            }

            string[] as;
            as ~= assembler;
            if (need_cflag)
                as ~= "-c";
            if (forth.vflag)
                as ~= "-v";
            as ~= "-o";
            if (forth.cflag && !forth.outfile.empty)
                as ~= forth.outfile;
            else
                as ~= (base ~ ".o");
            as ~= (base ~ ".s");

            if (forth.vflag) {
                bool first_s = true;
                foreach (s; as) {
                    if (first_s) {
                        first_s = false;
                        stderr.write(s);
                        continue;
                    }
                    stderr.write(" " ~ s);
                }
                stderr.writeln;
            }

            if (spawnProcess(as).wait != 0) {
                forth.fatal("assembler failed");
                remove_all(forth, base, rm.all);
                return 1;
            }

            if (forth.cflag) {
                remove_all(forth, base, rm.s);
                continue;
            }

            if (forth.genlib) {
                string[] ar_cmd;
                ar_cmd ~= ar;
                ar_cmd ~= "cru";
                ar_cmd ~= "lib4q.a";
                ar_cmd ~= (base ~ ".o");

                string[] ranlib_cmd;
                ranlib_cmd ~= ranlib;
                ranlib_cmd ~= "lib4q.a";

                if (forth.vflag) {
                    bool first_s = true;
                    foreach (s; ar_cmd) {
                        if (first_s) {
                            first_s = false;
                            stderr.writeln(s);
                            continue;
                        }
                        stderr.write(" " ~ s);
                    }
                    stderr.writeln;
                }

                if (spawnProcess(ar_cmd).wait != 0) {
                    forth.fatal("ar failed");
                    remove_all(forth, base, rm.all);
                    return 1;
                }

                if (forth.vflag) {
                    bool first_s = true;
                    foreach (s; ranlib_cmd) {
                        if (first_s) {
                            first_s = false;
                            stderr.writeln(s);
                            continue;
                        }
                        stderr.write(" " ~ s);
                    }
                    stderr.writeln;
                }

                if (spawnProcess(ranlib_cmd).wait != 0) {
                    forth.fatal("ranlib failed");
                    remove_all(forth, base, rm.all);
                    return 1;
                }

                remove_all(forth, base, rm.all);

                return 0;
            }

            if (forth.vflag) {
                bool first_s = true;
                foreach (s; ld) {
                    if (first_s) {
                        first_s = false;
                        stderr.write(s);
                        continue;
                    }
                    stderr.write(" " ~ s);
                }
                stderr.writeln;
            }

            if (spawnProcess(ld).wait != 0) {
                forth.fatal("linker failed");
                remove_all(forth, base, rm.all);
                return 1;
            }

            remove_all(forth, base, rm.o);
        } else {
            remove_all(forth, base, rm.all);
            return 1;
        }
    }

    return 0;
}

string[] create_linker_invocation(Forth forth) {
    import config;

    string[] ld;
    string outfile;

    ld ~= linker;
    if (forth.vflag)
        ld ~= "-v";

    if (forth.outfile.empty)
        outfile = create_base(forth.inputs[0]);
    else
        outfile = forth.outfile;

    final switch (os) {
    case system.darwin:
        ld ~= "-dead_strip";
        for (int i = 0; i < 15; ++i)
            ld ~= ld_args[i];
        ld ~= outfile;
        ld ~= ld_args[15];
        foreach (input; forth.inputs)
            ld ~= (create_base(input) ~ ".o");
        ld ~= stdlibpath;
        ld ~= ld_args[16];
        ld ~= ld_args[17];
        break;
    case system.linux:
        ld ~= "--gc-sections";
        for (int i = 0; i < 11; ++i)
            ld ~= ld_args[i];
        ld ~= outfile;
        for (int i = 11; i < 18; ++i)
            ld ~= ld_args[i];
        foreach (input; forth.inputs)
            ld ~= (create_base(input) ~ ".o");
        ld ~= stdlibpath;
        for (int i = 18; i < 23; ++i)
            ld ~= ld_args[i];
        break;
    case system.freebsd:
        ld ~= "--gc-sections";
        for (int i = 0; i < 6; ++i)
            ld ~= ld_args[i];
        ld ~= outfile;
        for (int i = 6; i < 10; ++i)
            ld ~= ld_args[i];
        foreach (input; forth.inputs)
            ld ~= (create_base(input) ~ ".o");
        ld ~= stdlibpath;
        for (int i = 10; i < 15; ++i)
            ld ~= ld_args[i];
    }

    return ld;
}

bool O(Forth forth, string base) {
    import config;

    string[3] peephole;
    string output;
    uint i;
    int counter;

    string[] lines;
    try {
        lines = splitLines(cast(string)read(base ~ ".qbe"));
    } catch (FileException e) {
        stderr.writeln(forth.argv0 ~ " error: could not open " ~ base ~ ".qbe");
        remove_all(forth, base, rm.all);
        return false;
    }

    while (i < lines.length) {
        while (counter < 3) {
            peephole[counter] = lines[i++];
            ++counter;
        }

        /+ This only runs at -O2.  +/
        if (ffunction_sections(forth, peephole[0])) {
            output ~= peephole[0] ~ "\n";
            output ~= ".section .text.";
            if (peephole[1].startsWith(".globl ")) {
                output ~= peephole[2][0 .. $ - 1];
                output ~= ",\"ax\",@progbits\n";
                output ~= peephole[1] ~ "\n";
                output ~= peephole[2] ~ "\n";
                counter -= 3;
            } else {
                output ~= peephole[1][0 .. $ - 1];
                output ~= ",\"ax\",@progbits\n";
                output ~= peephole[1] ~ "\n";
                peephole[0] = peephole[2];
                counter -= 2;
            }
        } else {
            output ~= one(forth, peephole[0]) ~ "\n";
            peephole[0] = peephole[1];
            peephole[1] = peephole[2];
            --counter;
        }
    }

    while (counter > 0) {
        output ~= one(forth, peephole[0]) ~ "\n";
        peephole[0] = peephole[1];
        peephole[1] = peephole[2];
        --counter;
    }

    // This allows -dead_strip to work.
    if (os == system.darwin)
        output ~= ".subsections_via_symbols\n";

    if (forth.Sflag && !forth.outfile.empty)
        std.file.write(forth.outfile, output);
    else
        std.file.write(base ~ ".s", output);

    return true;
}

bool ffunction_sections(Forth forth, string line) {
    import config;

    if (forth.Oflag != 2)
        return false;

    /+
     + Implement -ffunction-sections for qbe on ELF platforms
     + macOS doesn't need it; the linker does it with -dead_strip
     +/
    if (!(os == system.darwin)) {
        if (line == ".text")
            return true;
    }

    return false;
}

string one(Forth forth, string line) {
    import config;

    string s;

    /+
     + macOS and linux need a fixup pass for stdin, stdout, and stderr
     + This must always run.
     +/
    if (os == system.darwin || os == system.linux) {
        s = fixup(line, real_stdin);
        if (s != line)
            return s;

        s = fixup(line, real_stdout);
        if (s != line)
            return s;

        s = fixup(line, real_stderr);
        if (s != line)
            return s;
    }

    // Only run peephole optimizer at -O1 or higher.
    if (forth.Oflag == 0)
        return line;

    if (cpu == arch.x64) {
        s = xorl(line);
        if (s != line)
            return s;

        s = incq(line);
        if (s != line)
            return s;

        s = decq(line);
        if (s != line)
            return s;

        s = xorq(line);
        if (s != line)
            return s;

        s = incl(line);
        if (s != line)
            return s;

        s = decl(line);
        if (s != line)
            return s;
    }

    return line;
}

string fixup(string line, string stream) {
    import config;

    switch (os) {
    case system.darwin:
        return darwin_fixup(line, stream);
        break;
    case system.linux:
        return linux_fixup(line, stream);
        break;
    default:
        return line;
    }
}

string linux_fixup(string line, string stream) {
    import config;

    switch (cpu) {
    case arch.arm64:
        string full1 = ", " ~ stream;
        string s1 = line.replace(full1, ", :got:" ~ stream);

        if (s1 != line)
            return s1;

        string full2 = ", #:lo12:" ~ stream;
        string s2 = line.replace(full2, ", :got_lo12:" ~ stream);

        if (s2 == line)
            return s1;

        auto i = line.indexOf('x');
        auto j = i;
        while (line[j] != ',') {
            if (j == line.length - 1)
                return line;
            ++j;
        }

        string reg = line[i .. j];
        string s = "\tldr\t" ~ reg ~ ", [" ~ reg ~ ", :got_lo12:" ~ stream ~ "]";

        return s;
    case arch.rv64:
        string s = line.replace(", " ~ stream, ", %got_pcrel_hi(" ~ stream ~ ")");

        if (s == line)
            return line;

        auto i = line.lastIndexOf(',');
        if (i < 2)
            return line;

        string reg = line[i - 2 .. i];

        s = ".Lpcrel_hi" ~ to!string(rvpcrel) ~ ":\n";
        s ~= "\tauipc " ~ reg ~ ", %got_pcrel_hi(" ~ stream ~ ")\n";
        s ~= "\tld " ~ reg ~ ", %pcrel_lo(.Lpcrel_hi" ~ to!string(rvpcrel) ~ ")(" ~ reg ~ ")\n";
        s ~= "\tld " ~ reg ~ ", 0(" ~ reg ~ ")";

        ++rvpcrel;

        return s;
    default:
        return line;
    }
}

string darwin_fixup(string line, string stream) {
    import config;

    switch (cpu) {
    case arch.x64:
        string full = "_" ~ stream ~ "(%rip)";
        string s = line.replace(full, "_" ~ stream ~ "@GOTPCREL(%rip)");

        if (s == line)
            return line;

        auto i = line.lastIndexOf('%');
        string reg = line[i .. $];

        string fixed = "\tmovq _" ~ stream ~ "@GOTPCREL(%rip), " ~ reg ~ "\n";
        fixed ~= "\tmovq (" ~ reg ~ "), " ~ reg;

        return fixed;
    case arch.arm64:
        string full = "_" ~ stream ~ "@pageoff";
        string s = line.replace(full, "_" ~ stream ~ "@GOTPAGEOFF");

        if (s == line) {
            full = "_" ~ stream ~ "@page";
            s = line.replace(full, "_" ~ stream ~ "@GOTPAGE");

            if (s == line)
                return line;
        } else {
            auto i = line.indexOf('x');
            auto j = i;
            while (line[j] != ',') {
                if (j == line.length - 1)
                    return line;
                ++j;
            }
            string reg = line[i .. j];
            s = "\tldr\t" ~ reg ~ ", [" ~ reg ~ ", _" ~ stream ~ "@GOTPAGEOFF]";
        }

        return s;
    default:
        stderr.writeln("ICE: no matching darwin arch for fixup pass (continuing without fixup)");
    }

    return line;
}

string incl(string line) {
    string s;

    string match = "\taddl $1, %";
    bool does = line.startsWith(match);
    if (does == false) {
        return line;
    } else {
        string reg = line[match.length - 1 .. $];
        s ~= "\tincl " ~ reg;
    }

    return s;
}

string incq(string line) {
    string s;

    string match = "\taddq $1, %r";
    bool does = line.startsWith(match);
    if (does == false) {
        return line;
    } else {
        string reg = line[match.length - 2 .. $];
        s ~= "\tincq " ~ reg;
    }

    return s;
}

string decl(string line) {
    string s;

    string match = "\tsubl $1, %";
    bool does = line.startsWith(match);
    if (does == false) {
        return line;
    } else {
        string reg = line[match.length - 1 .. $];
        s ~= "\tdecl " ~ reg;
    }

    return s;
}

string decq(string line) {
    string s;

    string match = "\tsubq $1, %r";
    bool does = line.startsWith(match);
    if (does == false) {
        return line;
    } else {
        string reg = line[match.length - 2 .. $];
        s ~= "\tdecq " ~ reg;
    }

    return s;
}

string xorl(string line) {
    string s;

    string match = "\tmovl $0, %";
    bool does = line.startsWith(match);
    if (does == false) {
        return line;
    } else {
        string reg = line[match.length - 1 .. $];
        s ~= "\txorl " ~ reg ~ ", " ~ reg;
    }

    return s;
}

string xorq(string line) {
    string s;

    string match = "\tmovq $0, %r";
    bool does = line.startsWith(match);
    if (does == false) {
        return line;
    } else {
        s ~= "\txorl %";
        string reg = line[match.length - 2 .. $];
        switch (reg) {
        case "r8":
        case "r9":
        case "r10":
        case "r11":
        case "r12":
        case "r13":
        case "r14":
        case "r15":
            s ~= reg ~ "d, %" ~ reg ~ "d";
            break;
        default:
            string ereg = line[match.length - 1 .. $ - 1];
            s ~= "e" ~ ereg ~ ", %e" ~ ereg;
        }
    }

    return s;
}

/+
 + A whole lot of built-in words to get us started.
 +/

Dictionary addition = Dictionary("+",
"export function $.addition() {
@start
	%b =l call $.pop()
	%a =l call $.pop()
	%c =l add %a, %b
	call $.push(l %c)
	ret
}\n", word_type.func);

Dictionary subtraction = Dictionary("-",
"export function $.subtraction() {
@start
	%b =l call $.pop()
	%a =l call $.pop()
	%c =l sub %a, %b
	call $.push(l %c)
	ret
}\n", word_type.func);

Dictionary multiplication = Dictionary("*",
"export function $.multiplication() {
@start
	%b =l call $.pop()
	%a =l call $.pop()
	%c =l mul %a, %b
	call $.push(l %c)
	ret
}\n", word_type.func);

Dictionary division = Dictionary("/",
"export function $.division() {
@start
	%b =l call $.pop()
	%a =l call $.pop()
	%c =l div %a, %b
	call $.push(l %c)
	ret
}\n", word_type.func);

Dictionary modulo = Dictionary("mod",
"export function $.modulo() {
@start
	%b =l call $.pop()
	%a =l call $.pop()
	%c =l rem %a, %b
	call $.push(l %c)
	ret
}\n", word_type.func);

Dictionary equal = Dictionary("=",
"export function $.equal() {
@start
	%b =l call $.pop()
	%a =l call $.pop()
	%c =l ceql %a, %b
	jnz %c, @true, @false
@true
	call $.push(l -1)
	ret
@false
	call $.push(l 0)
	ret
}\n", word_type.func);

Dictionary notequal = Dictionary("<>",
"export function $.notequal() {
@start
	%b =l call $.pop()
	%a =l call $.pop()
	%c =l cnel %a, %b
        jnz %c, @true, @false
@true
	call $.push(l -1)
	ret
@false
	call $.push(l 0)
	ret
}\n", word_type.func);

Dictionary and = Dictionary("and",
"export function $and() {
@start
	%b =l call $.pop()
	%a =l call $.pop()
	%c =l and %a, %b
	call $.push(l %c)
	ret
}\n", word_type.func);

Dictionary or = Dictionary("or",
"export function $or() {
@start
	%b =l call $.pop()
	%a =l call $.pop()
	%c =l or %a, %b
	call $.push(l %c)
	ret
}\n", word_type.func);

Dictionary invert = Dictionary("invert",
"export function $invert() {
@start
	%a =l call $.pop()
	%b =l extsw -1
	%c =l xor %a, %b
	call $.push(l %c)
	ret
}\n", word_type.func);

Dictionary xor = Dictionary("xor",
"export function $xor() {
@start
	%b =l call $.pop()
	%a =l call $.pop()
	%c =l xor %a, %b
	call $.push(l %c)
	ret
}\n", word_type.func);

Dictionary lessthan = Dictionary("<",
"export function $.lessthan() {
@start
	%b =l call $.pop()
	%a =l call $.pop()
	%cmp =l csltl %a, %b
	jnz %cmp, @true, @false
@true
	call $.push(l -1)
	ret
@false
	call $.push(l 0)
	ret
}\n", word_type.func);

Dictionary greaterthan = Dictionary(">",
"export function $.greaterthan() {
@start
	%b =l call $.pop()
	%a =l call $.pop()
	%cmp =l csgtl %a, %b
	jnz %cmp, @true, @false
@true
	call $.push(l -1)
	ret
@false
	call $.push(l 0)
	ret
}\n", word_type.func);

Dictionary dot = Dictionary(".",
"export function $.dot() {
@start
	%buf =l alloc8 128
	%n =l call $.pop()
	%.0 =w call $swprintf(l %buf, l 32, l $.str.wfmtd, ..., l %n)
	call $.string(l %buf)
	ret
}\n", word_type.func);

Dictionary print_wide = Dictionary(".print_wide",
"export function $.print_wide(l %fmt, ...) {
@start
}\n", word_type.func);

Dictionary dotstring = Dictionary(".\"",
"export function $.string(l %s) {
@start
	%.0 =w call $wprintf(l $.str.wfmts, ..., l %s)
	ret
}\n", word_type.func);

Dictionary emit = Dictionary("emit",
"export function $emit() {
@start
	%c =w call $.pop()
	%.0 =w call $wprintf(l $.str.wfmtc, ..., w %c)
	ret
}\n", word_type.func);

Dictionary destroy = Dictionary(".destroy",
"export function $.destroy() {
@start
	%stack =l loadl $.stack
	%sz =l loadl $.sz
	%.0 =l call $memset(l %stack, w 0, l %sz)
	call $free(l %stack)
	storel 0, $.stack
	storel 0, $.sp
	storel 0, $.sz
	ret
}\n", word_type.func);

Dictionary fatal = Dictionary(".fatal",
"export function $.fatal(l %s) {
@start
	call $.writestderr(l %s)
	call $.writestderr(l $.str.wnewline)
	call $.destroy()
	call $exit(w 1)
	ret
}\n", word_type.func);

Dictionary pop = Dictionary(".pop",
"export function l $.pop() {
@start
	%sp =l loadl $.sp
	%cmp =l ceql %sp, 0
	jnz %cmp, @error, @valid
@error
	call $.fatal(l $.str.underflow)
@valid
	%stack =l loadl $.stack
	%sp =l sub %sp, 1
	storel %sp, $.sp
	%offset =l shl %sp, 3
	%addr =l add %stack, %offset
	%value =l loadl %addr
	ret %value
}\n", word_type.func);

Dictionary resize = Dictionary(".resize",
"export function $.resize(l %sz) {
@start
	%newsz =l shl %sz, 1
	storel %newsz, $.sz
	%pointer =l call $.xmalloc(l %newsz)
	%stack =l loadl $.stack
	%.0 =l call $memcpy(l %pointer, l %stack, l %sz)
	call $free(l %stack)
	storel %pointer, $.stack
	ret
}\n", word_type.func);

Dictionary push = Dictionary(".push",
"export function $.push(l %num) {
@start
	%sp =l loadl $.sp
	%sz =l loadl $.sz
	%offset =l shl %sp, 3
	%cmp =l ceql %offset, %sz
	jnz %cmp, @resize, @end
@resize
	call $.resize(l %sz)
@end
	%stack =l loadl $.stack
	%addr =l add %stack, %offset
	storel %num, %addr
	%sp =l add %sp, 1
	storel %sp, $.sp
	ret
}\n", word_type.func);

Dictionary xmalloc = Dictionary(".xmalloc",
"export function l $.xmalloc(l %num) {
@start
	%.0 =l ceql %num, 0
	jnz %.0, @error, @valid
@valid
	%size =l shl %num, 3
	%pointer =l call $malloc(l %size)
	%.0 =l ceql %pointer, 0
	jnz %.0, @error, @success
@error
	call $.fatal(l $.str.xmalloc)
@success
	%.0 =l call $memset(l %pointer, w 0, l %size)
	ret %pointer
}\n", word_type.func);

Dictionary cr = Dictionary("cr",
"export function $cr() {
@start
	call $wprintf(l $.str.wnewline, ...)
	ret
}\n", word_type.func);

Dictionary drop = Dictionary("drop",
"export function $drop() {
@start
	%.0 =l call $.pop()
	ret
}\n", word_type.func);

Dictionary dup = Dictionary("dup",
"export function $dup() {
@start
	%a =l call $.pop()
	call $.push(l %a)
	call $.push(l %a)
	ret
}\n", word_type.func);

Dictionary over = Dictionary("over",
"export function $over() {
@start
        %b =l call $.pop()
        %a =l call $.pop()
	call $.push(l %b)
	call $.push(l %a)
	call $.push(l %b)
	ret
}\n", word_type.func);

Dictionary rot = Dictionary("rot",
"export function $rot() {
@start
	%c =l call $.pop()
	%b =l call $.pop()
	%a =l call $.pop()
	call $.push(l %b)
	call $.push(l %c)
	call $.push(l %a)
	ret
}\n", word_type.func);

Dictionary swap = Dictionary("swap",
"export function $swap() {
@start
	%b =l call $.pop()
	%a =l call $.pop()
	call $.push(l %b)
	call $.push(l %a)
	ret
}\n", word_type.func);

Dictionary bang = Dictionary(".bang",
"export function $.bang() {
@start
	%.location =l call $.pop()
	%.value =l call $.pop()
	storel %.value, %.location
	ret
}\n", word_type.func);

Dictionary at = Dictionary(".at",
"export function $.at() {
@start
	%.location =l call $.pop()
	%.value =l loadl %.location
	call $.push(l %.value)
	ret
}\n", word_type.func);

Dictionary question = Dictionary("?",
"export function $.question() {
@start
	call $.at()
	call $.dot()
}\n", word_type.func);

Dictionary addbang = Dictionary("+!",
"export function $.addbang() {
@start
	%.location =l call $.pop()
	%.0 =l call $.pop()
	%.value =l loadl %.location
	%.value =l add %.value, %.0
	storel %.value, %.location
	ret
}\n", word_type.func);

Dictionary sentinel = Dictionary(".sentinel", "\n", word_type.func);
