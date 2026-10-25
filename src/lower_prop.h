// Goose compiler — property verification lowering to proptest harnesses
#pragma once

#include "ast.h"
#include "dump.h"
#include "utils.h"

namespace goose {

struct PropDumpWrittenGuard {
    bool prev;
    PropDumpWrittenGuard() : prev(dumpwritten) { dumpwritten = true; }
    ~PropDumpWrittenGuard() { dumpwritten = prev; }
};

// Compute human-readable test target name for a property declaration.
inline string ComputePropTargetName(const PropDecl *prop, int prop_index = 0) {
    if (prop->target_fn) {
        if (!prop->tag.empty()) {
            return cat(prop->target_fn->qname, "::", prop->tag);
        }
        return string(prop->target_fn->qname);
    }
    if (!prop->tag.empty()) {
        return string(prop->tag);
    }
    return cat("prop_", prop_index);
}

// Sanitize an arbitrary target name into a valid Goose identifier.
inline string SanitizePropIdentifier(const string &s) {
    string out;
    for (char c : s) {
        if (isalnum((unsigned char)c) || c == '_') {
            out += c;
        } else {
            out += '_';
        }
    }
    string clean;
    for (char c : out) {
        if (c == '_' && !clean.empty() && clean.back() == '_') continue;
        clean += c;
    }
    if (!clean.empty() && clean.back() == '_') clean.pop_back();
    if (!clean.empty() && clean.front() == '_') clean.erase(0, 1);
    if (clean.empty() || isdigit((unsigned char)clean[0])) {
        clean = "prop_" + clean;
    }
    return clean;
}

// Escape strings for embedding inside Goose string literals.
inline string EscapePropString(const string &s) {
    string out;
    for (char c : s) {
        if (c == '\\') out += "\\\\";
        else if (c == '"') out += "\\\"";
        else if (c == '\n') out += "\\n";
        else if (c == '\t') out += "\\t";
        else if (c == '\r') out += "\\r";
        else out += c;
    }
    return out;
}

// Match property against a target filter (exact, tag, fn name, or sanitized).
inline bool MatchesPropTarget(const PropDecl *prop, const string &target_name, const string &filter) {
    if (filter.empty()) return true;
    if (target_name == filter) return true;
    if (SanitizePropIdentifier(target_name) == SanitizePropIdentifier(filter)) return true;
    if (!prop->tag.empty()) {
        if (prop->tag == filter) return true;
        if (SanitizePropIdentifier(string(prop->tag)) == SanitizePropIdentifier(filter)) return true;
    }
    if (prop->target_fn) {
        if (prop->target_fn->name == filter || prop->target_fn->qname == filter) return true;
    }
    return false;
}

// List all discovered property verification target names in an AST.
inline vector<string> ListPropTargets(const Ast &ast) {
    vector<string> targets;
    int index = 0;
    for (auto prop : ast.props) {
        targets.push_back(ComputePropTargetName(prop, index++));
    }
    return targets;
}

// Options configuring property harness synthesis and CLI overrides.
struct PropHarnessOptions {
    string target_filter;
    uint64_t seed = 0;
    string replay;
    string corpus_dir;
    int timeout_sec = 0;
    int64_t max_len = 0;
    bool is_fuzz = false;
    bool verbose = false;
};

// Generate the companion test worker and execution code for a single PropDecl.
inline string GeneratePropCompanion(const PropDecl *prop, const string &source_file,
                                    const string &fn_name, const string &target_name,
                                    const PropHarnessOptions &opts = {}) {
    PropDumpWrittenGuard guard;
    string out;

    if (!prop->ns.empty()) {
        out += cat("fn ", prop->ns, "::", fn_name, "() {\n");
    } else {
        out += cat("fn ", fn_name, "() {\n");
    }

    out += "    var c = proptest::check();\n";
    if (opts.is_fuzz) {
        out += "    c = proptest::fuzz(c);\n";
        out += "    c = proptest::verbose(c);\n";
    }
    if (prop->target_fn || !prop->tag.empty()) {
        out += cat("    c = proptest::fuzz_target_name(c, \"", EscapePropString(target_name), "\");\n");
    }
    if (!source_file.empty()) {
        out += cat("    c = proptest::fuzz_source_file(c, \"", EscapePropString(source_file), "\");\n");
    }

    // Apply prop->configs (`with(...)` options)
    for (auto &[key, val] : prop->configs) {
        string vstr;
        if (auto lit = Is<IntLit>(val)) {
            vstr = to_string(lit->val);
        } else if (auto un = Is<Unary>(val); un && un->op == T_MINUS) {
            if (auto slit = Is<IntLit>(un->child)) vstr = to_string(-slit->val);
        }
        if (vstr.empty() && val) {
            val->Dump(vstr, 0);
        }
        if (vstr.empty()) continue;

        if (key == "iterations") {
            out += cat("    c = proptest::iterations(c, ", vstr, ");\n");
        } else if (key == "timeout_ms") {
            out += cat("    c = proptest::timeout_ms(c, ", vstr, ");\n");
        } else if (key == "max_len") {
            out += cat("    c = proptest::max_len(c, ", vstr, ");\n");
        } else if (key == "shrink_steps") {
            out += cat("    c = proptest::shrink_steps(c, ", vstr, ");\n");
        } else if (key == "max_discards") {
            out += cat("    c = proptest::max_discards(c, ", vstr, ");\n");
        }
    }

    // CLI overrides take precedence over with(...)
    if (opts.timeout_sec > 0) {
        out += cat("    c = proptest::timeout_ms(c, ", to_string((int64_t)opts.timeout_sec * 1000), ");\n");
    }
    if (opts.max_len > 0) {
        out += cat("    c = proptest::max_len(c, ", to_string(opts.max_len), ");\n");
    }
    if (opts.seed != 0) {
        out += cat("    c = proptest::seed(c, ", to_string(opts.seed), ");\n");
    }
    if (!opts.replay.empty()) {
        bool is_file = false;
        if (FILE *f = fopen(opts.replay.c_str(), "rb")) {
            fclose(f);
            is_file = true;
        }
        if (is_file) {
            out += cat("    c = proptest::replay(c, \"", EscapePropString(opts.replay), "\");\n");
        } else {
            string hex = opts.replay;
            if (hex.rfind("0x", 0) == 0 || hex.rfind("0X", 0) == 0) hex = hex.substr(2);
            string cleanhex;
            for (char ch : hex) {
                if (isxdigit((unsigned char)ch)) cleanhex += ch;
            }
            out += "    let _replay_arr: u8[] = [";
            for (size_t k = 0; k + 1 < cleanhex.size(); k += 2) {
                if (k > 0) out += ", ";
                auto byte_val = (unsigned)strtoul(cleanhex.substr(k, 2).c_str(), nullptr, 16);
                out += to_string(byte_val);
            }
            out += "];\n    c = proptest::replay_bytes(c, _replay_arr[..]);\n";
        }
    }
    if (!opts.corpus_dir.empty()) {
        out += cat("    c = proptest::crash_file(c, \"", EscapePropString(opts.corpus_dir), "/crash.bin\");\n");
        out += cat("    c = proptest::corpus_dir(c, \"", EscapePropString(opts.corpus_dir), "\");\n");
    }
    if (opts.verbose && !opts.is_fuzz) {
        out += "    c = proptest::verbose(c);\n";
    }

    bool has_tier3 = !prop->analysis.tier3_constraints.empty();
    if (has_tier3) {
        out += "    fn _worker(d: Driver&) -> bool {\n";
    } else {
        out += "    proptest::for_each(c) { d =>\n";
    }

    // Generate variables in topological generation order
    const auto &vars = prop->analysis.vars;
    const auto &gen_order = prop->analysis.gen_order;

    vector<int> order;
    set<int> seen;
    for (int idx : gen_order) {
        if (idx >= 0 && idx < (int)vars.size() && seen.insert(idx).second) {
            order.push_back(idx);
        }
    }
    for (int i = 0; i < (int)vars.size(); i++) {
        if (seen.insert(i).second) {
            order.push_back(i);
        }
    }

    for (int v_idx : order) {
        const auto &v = vars[v_idx];
        if (v.is_slice) {
            int64_t actual_max_len = v.max_len;
            if (opts.max_len > 0 && opts.max_len < actual_max_len) {
                actual_max_len = opts.max_len;
            }
            int64_t actual_min_len = v.min_len;
            if (actual_min_len > actual_max_len) actual_min_len = actual_max_len;

            bool is_u8_slice = false;
            if (v.slice_elem_type && v.slice_elem_type->kind == TY_INT && v.slice_elem_type->intstorage == IS_U8) {
                is_u8_slice = true;
            }
            if (is_u8_slice) {
                out += cat("        let _", v.name, "_buf = d.gen_bytes(", to_string(actual_min_len), ", ", to_string(actual_max_len), ");\n");
                out += cat("        let ", v.name, " = _", v.name, "_buf[..];\n");
            } else {
                string elem_gen;
                if (!v.slice_elem_type) {
                    elem_gen = "_d.gen_i64()";
                } else if (v.slice_elem_type->kind == TY_INT) {
                    if (v.slice_elem_type->intstorage == IS_I64) {
                        elem_gen = "_d.gen_i64()";
                    } else if (v.slice_elem_type->intstorage < IS_I64) {
                        string tname; v.slice_elem_type->Dump(tname);
                        elem_gen = cat("(_d.gen_i64() as ", tname, ")");
                    } else if (v.slice_elem_type->intstorage == IS_U64) {
                        elem_gen = "_d.gen_u64()";
                    } else {
                        string tname; v.slice_elem_type->Dump(tname);
                        elem_gen = cat("(_d.gen_u64() as ", tname, ")");
                    }
                } else if (v.slice_elem_type->kind == TY_BOOL) {
                    elem_gen = "_d.gen_bool()";
                } else if (v.slice_elem_type->kind == TY_FLT) {
                    if (v.slice_elem_type->fltstorage == FS_F32) elem_gen = "_d.gen_f32()";
                    else elem_gen = "_d.gen_f64()";
                } else {
                    string tname; v.slice_elem_type->Dump(tname);
                    elem_gen = cat(tname, "::generate(_d)");
                }
                out += cat("        let _", v.name, "_buf = d.gen_array(", to_string(actual_min_len), ", ", to_string(actual_max_len), ") { _d => ", elem_gen, " };\n");
                out += cat("        let ", v.name, " = _", v.name, "_buf[..];\n");
            }
        } else if (v.tier == 2 && !v.dep_var.empty()) {
            string dep_lo;
            if (v.dep_offset == 0) {
                dep_lo = string(v.dep_var);
            } else if (v.dep_offset > 0) {
                dep_lo = cat(v.dep_var, " + ", to_string(v.dep_offset));
            } else {
                dep_lo = cat(v.dep_var, " - ", to_string(-v.dep_offset));
            }
            int64_t hi = v.has_high ? v.high : 1000000;
            if (v.type && v.type->kind == TY_INT && v.type->intstorage != IS_I64 && v.type->intstorage <= IS_I32) {
                string tname; v.type->Dump(tname);
                out += cat("        let ", v.name, " = (d.gen_i64_range(", dep_lo, ", ", to_string(hi), ") as ", tname, ");\n");
            } else if (v.type && v.type->kind == TY_INT && v.type->intstorage >= IS_U8 && v.type->intstorage <= IS_U64) {
                if (v.type->intstorage == IS_U64) {
                    out += cat("        let ", v.name, " = d.gen_u64_range(", dep_lo, ", ", to_string(hi), ");\n");
                } else {
                    string tname; v.type->Dump(tname);
                    out += cat("        let ", v.name, " = (d.gen_u64_range(", dep_lo, ", ", to_string(hi), ") as ", tname, ");\n");
                }
            } else {
                out += cat("        let ", v.name, " = d.gen_i64_range(", dep_lo, ", ", to_string(hi), ");\n");
            }
        } else {
            // Tier 1 scalar
            if (v.type && v.type->kind == TY_BOOL) {
                out += cat("        let ", v.name, " = d.gen_bool();\n");
            } else if (v.type && v.type->kind == TY_FLT) {
                if (v.has_low && v.has_high) {
                    out += cat("        let ", v.name, " = d.gen_f64_range(", to_string(v.low), ".0, ", to_string(v.high), ".0);\n");
                } else {
                    out += cat("        let ", v.name, " = d.gen_f64();\n");
                }
            } else {
                bool is_unsigned = (v.type && v.type->kind == TY_INT && v.type->intstorage >= IS_U8 && v.type->intstorage <= IS_U64);
                if (is_unsigned) {
                    uint64_t lo = v.has_low ? (uint64_t)v.low : 0;
                    uint64_t hi = v.has_high ? (uint64_t)v.high : 0;
                    if (!v.has_low && !v.has_high) {
                        if (v.type->intstorage == IS_U8) { lo = 0; hi = 255; }
                        else if (v.type->intstorage == IS_U16) { lo = 0; hi = 65535; }
                        else if (v.type->intstorage == IS_U32) { lo = 0; hi = 0xFFFFFFFF; }
                        else { lo = 0; hi = 1000; }
                    } else if (!v.has_low) {
                        lo = 0;
                    } else if (!v.has_high) {
                        if (v.type->intstorage == IS_U8) hi = 255;
                        else if (v.type->intstorage == IS_U16) hi = 65535;
                        else if (v.type->intstorage == IS_U32) hi = 0xFFFFFFFF;
                        else hi = lo + 1000;
                    }
                    if (v.type->intstorage != IS_U64) {
                        string tname; v.type->Dump(tname);
                        out += cat("        let ", v.name, " = (d.gen_u64_range(", to_string(lo), ", ", to_string(hi), ") as ", tname, ");\n");
                    } else {
                        out += cat("        let ", v.name, " = d.gen_u64_range(", to_string(lo), ", ", to_string(hi), ");\n");
                    }
                } else {
                    int64_t lo = v.has_low ? v.low : 0;
                    int64_t hi = v.has_high ? v.high : 0;
                    if (!v.has_low && !v.has_high) {
                        if (v.type && v.type->intstorage == IS_I8) { lo = -128; hi = 127; }
                        else if (v.type && v.type->intstorage == IS_I16) { lo = -32768; hi = 32767; }
                        else if (v.type && v.type->intstorage == IS_I32) { lo = -2147483648LL; hi = 2147483647; }
                        else { lo = -1000; hi = 1000; }
                    } else if (!v.has_low) {
                        if (v.type && v.type->intstorage == IS_I8) lo = -128;
                        else if (v.type && v.type->intstorage == IS_I16) lo = -32768;
                        else if (v.type && v.type->intstorage == IS_I32) lo = -2147483648LL;
                        else lo = hi - 1000;
                    } else if (!v.has_high) {
                        if (v.type && v.type->intstorage == IS_I8) hi = 127;
                        else if (v.type && v.type->intstorage == IS_I16) hi = 32767;
                        else if (v.type && v.type->intstorage == IS_I32) hi = 2147483647;
                        else hi = lo + 1000;
                    }
                    if (v.type && v.type->intstorage != IS_I64) {
                        string tname; v.type->Dump(tname);
                        out += cat("        let ", v.name, " = (d.gen_i64_range(", to_string(lo), ", ", to_string(hi), ") as ", tname, ");\n");
                    } else {
                        out += cat("        let ", v.name, " = d.gen_i64_range(", to_string(lo), ", ", to_string(hi), ");\n");
                    }
                }
            }
        }
    }

    // Tier 3 assume constraints
    for (auto c : prop->analysis.tier3_constraints) {
        string c_str;
        c->Dump(c_str, 0);
        out += cat("        if !d.assume(", c_str, ") { return true; }\n");
    }

    // Property body block statements / return expression
    if (prop->body) {
        for (auto st : prop->body->stmts) {
            out += "        ";
            st->Dump(out, 2);
            if (!EndsInBlock(st)) out += ";";
            out += "\n";
        }
        if (prop->body->tail) {
            out += "        ";
            prop->body->tail->Dump(out, 2);
            out += "\n";
        } else {
            out += "        return true;\n";
        }
    } else {
        out += "        return true;\n";
    }

    if (has_tier3) {
        out += "    }\n";
        out += "    proptest::for_each(c) { d => _worker(d) };\n";
    } else {
        out += "    };\n";
    }
    if (!opts.is_fuzz) {
        out += cat("    print(\"[PASS] ", EscapePropString(target_name), "\");\n");
    }
    out += "}\n\n";
    return out;
}

// Generate complete standalone test harness for an AST containing properties.
inline bool GeneratePropHarness(const Ast &ast, const string &source_file,
                                const PropHarnessOptions &opts, string &out_harness) {
    if (ast.props.empty()) return false;

    vector<pair<PropDecl *, string>> matched;
    int index = 0;
    for (auto prop : ast.props) {
        string tname = ComputePropTargetName(prop, index++);
        if (MatchesPropTarget(prop, tname, opts.target_filter)) {
            matched.push_back({prop, tname});
        }
    }

    if (matched.empty()) return false;

    string target_stem = PathStem(source_file);
    string harness;
    harness += "/* Synthesized test harness for declarative property verification */\n";
    harness += "import proptest;\n";
    if (!target_stem.empty()) {
        bool is_valid_ident = !target_stem.empty() && (isalpha((unsigned char)target_stem[0]) || target_stem[0] == '_');
        if (is_valid_ident) {
            for (char c : target_stem) {
                if (!isalnum((unsigned char)c) && c != '_') { is_valid_ident = false; break; }
            }
        }
        if (is_valid_ident) {
            harness += cat("import .", target_stem, ";\n");
        } else {
            harness += cat("import .\"", EscapePropString(target_stem), "\";\n");
        }
    }
    harness += "\n";

    set<string> seen_fn_names;
    vector<pair<string, string>> calls; // {ns, fn_name}

    for (size_t i = 0; i < matched.size(); i++) {
        auto prop = matched[i].first;
        const auto &target_name = matched[i].second;

        string base_fn_name = cat("__prop_", SanitizePropIdentifier(target_name));
        string fn_name = base_fn_name;
        int disambig = 1;
        while (seen_fn_names.count(fn_name)) {
            fn_name = cat(base_fn_name, "_", disambig++);
        }
        seen_fn_names.insert(fn_name);

        harness += GeneratePropCompanion(prop, source_file, fn_name, target_name, opts);
        calls.push_back({string(prop->ns), fn_name});
    }

    harness += "fn main() {\n";
    for (auto &[ns, fn_name] : calls) {
        if (!ns.empty()) {
            harness += cat("    ", ns, "::", fn_name, "();\n");
        } else {
            harness += cat("    ", fn_name, "();\n");
        }
    }
    harness += "}\n";

    out_harness = std::move(harness);
    return true;
}

inline bool GeneratePropHarness(const Ast &ast, const string &source_file,
                                const string &target_filter, string &out_harness) {
    PropHarnessOptions opts;
    opts.target_filter = target_filter;
    return GeneratePropHarness(ast, source_file, opts, out_harness);
}

}  // namespace goose
