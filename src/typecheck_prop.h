// Goose compiler — property verification semantic analysis and 3-tier constraint solving
#pragma once

namespace goose {

inline void TypeCheck::CheckProperties() {
    for (auto prop : ast.props) {
        CheckRoot([&] { CheckPropDecl(prop); });
    }
}

inline void TypeCheck::CheckPropDecl(PropDecl *prop) {
    // 1. Parameter Inference:
    // For PropDecl adjacent to target_fn where quantifiers is empty,
    // implicitly populate quantifiers from target_fn->params (copying names and types).
    if (prop->target_fn && prop->quantifiers.empty()) {
        for (auto &p : prop->target_fn->params) {
            Param q;
            q.name = p.name;
            q.line = p.line.line ? p.line : prop->line;
            q.type = p.type;
            q.isvar = p.isvar;
            prop->quantifiers.push_back(q);
        }
    }

    // Check duplicate quantifier names
    set<string_view> seen_quantifiers;
    for (auto &q : prop->quantifiers) {
        if (!seen_quantifiers.insert(q.name).second) {
            Error(q.line.line ? q.line : prop->line, cat("duplicate property variable '", q.name, "'"));
        }
    }

    // 2. Shadowing Prevention (Spec Section 4.3):
    // For each quantifier in prop->quantifiers, check if its name collides with a
    // module-level constant, global variable, type, or function in scope.
    // If so, emit compile-time error:
    // error: property variable 'X' shadows a module-level symbol of the same name
    for (auto &q : prop->quantifiers) {
        bool collides = false;

        // Check module globals / constants
        if (ast.LookupGlobal(q.name, prop->ns) != nullptr) collides = true;
        if (!collides && !prop->ns.empty() && ast.LookupGlobal(q.name, "") != nullptr) collides = true;
        if (!collides) {
            for (auto g : ast.globals) {
                for (auto nm : g->names) {
                    if (nm == q.name) { collides = true; break; }
                }
                if (collides) break;
            }
        }

        // Check types: structs, enums, aliases
        if (!collides && ast.LookupStruct(q.name, prop->ns) != nullptr) collides = true;
        if (!collides && !prop->ns.empty() && ast.LookupStruct(q.name, "") != nullptr) collides = true;
        if (!collides && ast.LookupEnum(q.name, prop->ns) != nullptr) collides = true;
        if (!collides && !prop->ns.empty() && ast.LookupEnum(q.name, "") != nullptr) collides = true;
        if (!collides && ast.LookupAlias(q.name, prop->ns) != nullptr) collides = true;
        if (!collides && !prop->ns.empty() && ast.LookupAlias(q.name, "") != nullptr) collides = true;
        if (!collides) {
            for (auto s : ast.structs) if (s->name == q.name) { collides = true; break; }
            for (auto e : ast.enums) if (e->name == q.name) { collides = true; break; }
            for (auto a : ast.aliases) if (a->name == q.name) { collides = true; break; }
        }

        // Check functions in scope
        if (!collides && !ast.LookupFunctions(q.name, prop->ns).empty()) collides = true;
        if (!collides && !prop->ns.empty() && !ast.LookupFunctions(q.name, "").empty()) collides = true;
        if (!collides) {
            for (auto sf : ast.functions) {
                if (sf->name == q.name) { collides = true; break; }
            }
        }

        if (collides) {
            Error(q.line.line ? q.line : prop->line,
                  cat("property variable '", q.name, "' shadows a module-level symbol of the same name"));
        }
    }

    // 3. Campaign Configuration: with(...)
    int64_t max_len = 4096;
    int64_t iterations = 1000;
    for (auto &[key, val] : prop->configs) {
        if (key == "max_len") {
            int64_t v = 0;
            if (ConstInt(val, v)) max_len = v;
        } else if (key == "iterations") {
            int64_t v = 0;
            if (ConstInt(val, v)) iterations = v;
        }
    }
    prop->analysis.max_len = max_len;
    prop->analysis.iterations = iterations;

    // 4. Type Inference & Quantifier Resolution
    prop->analysis.vars.clear();
    for (size_t qi = 0; qi < prop->quantifiers.size(); qi++) {
        auto &q = prop->quantifiers[qi];
        PropVarBound b;
        b.name = q.name;

        if (q.type) {
            ValidateType(q.type, q.line.line ? q.line : prop->line, VT_PARAM);
            b.type = q.type;
        } else if (prop->target_fn) {
            Param *tp = nullptr;
            for (auto &p : prop->target_fn->params) {
                if (p.name == q.name) { tp = &p; break; }
            }
            if (!tp && prop->quantifiers.size() == prop->target_fn->params.size()) {
                tp = &prop->target_fn->params[qi];
            }
            if (tp && tp->type) {
                q.type = tp->type;
                ValidateType(q.type, q.line.line ? q.line : prop->line, VT_PARAM);
                b.type = q.type;
            }
        }

        if (!b.type) {
            // Check if constraints in where mention q.name.len (slice view)
            bool has_len = false;
            for (auto c : prop->constraints) {
                function<void(Node *)> find_len = [&](Node *n) {
                    if (!n || has_len) return;
                    if (auto dot = Is<Dot>(n); dot && dot->name == "len") {
                        if (auto id = Is<Ident>(dot->obj); id && id->name == q.name) {
                            has_len = true;
                            return;
                        }
                    }
                    n->Children(find_len);
                };
                find_len(c);
                if (has_len) break;
            }
            if (has_len) {
                q.type = ast.NewType(TY_SLICE, q.line.line ? q.line : prop->line);
                q.type->sub = ast.inttypes[IS_U8];
                b.type = q.type;
            }
        }

        if (!b.type) {
            // Check if constraints in where mention q.name (e.g. arithmetic, range, comparison)
            bool mentions_in_where = false;
            for (auto c : prop->constraints) {
                function<void(Node *)> find_ident = [&](Node *n) {
                    if (!n || mentions_in_where) return;
                    if (auto id = Is<Ident>(n)) {
                        if (id->name == q.name) { mentions_in_where = true; return; }
                    }
                    n->Children(find_ident);
                };
                find_ident(c);
                if (mentions_in_where) break;
            }
            if (mentions_in_where) {
                q.type = ast.inttypes[IS_I64];
                b.type = q.type;
            }
        }

        if (!b.type) {
            Error(q.line.line ? q.line : prop->line,
                  cat("cannot deduce type for property variable '", q.name,
                      "'; hint: provide an explicit type annotation, e.g. '(", q.name, ": i64)'"));
        }

        // Flag slice views
        if (b.type && b.type->kind == TY_SLICE) {
            b.is_slice = true;
            b.slice_elem_type = b.type->sub;
            b.min_len = 0;
            b.max_len = max_len;
        }

        prop->analysis.vars.push_back(b);
    }

    // 5. Pragmatic 3-Tier Constraint Engine
    auto &vars = prop->analysis.vars;
    map<string_view, int> var_idx;
    for (int i = 0; i < (int)vars.size(); i++) {
        var_idx[vars[i].name] = i;
    }

    int N = (int)vars.size();
    vector<vector<pair<int, int64_t>>> adj(N);
    vector<vector<pair<int, int64_t>>> rev_adj(N);

    auto add_edge = [&](int u, int v, int64_t C) {
        for (auto &e : adj[u]) {
            if (e.first == v) {
                e.second = std::max(e.second, C);
                for (auto &re : rev_adj[v]) {
                    if (re.first == u) { re.second = std::max(re.second, C); break; }
                }
                return;
            }
        }
        adj[u].push_back({v, C});
        rev_adj[v].push_back({u, C});
    };

    prop->analysis.tier3_constraints.clear();

    for (auto c : prop->constraints) {
        bool handled = false;
        if (auto bin = Is<Binary>(c)) {
            if (bin->op == T_IN) {
                if (auto re = Is<RangeExpr>(bin->right)) {
                    if (auto id = Is<Ident>(bin->left); id && var_idx.count(id->name)) {
                        int v_idx = var_idx[id->name];
                        int64_t lo_c = 0, hi_c = 0;
                        bool lo_const = ConstInt(re->lo, lo_c);
                        bool hi_const = ConstInt(re->hi, hi_c);

                        if (lo_const && hi_const) {
                            int64_t actual_hi = re->inclusive ? hi_c : hi_c - 1;
                            if (vars[v_idx].has_low) vars[v_idx].low = std::max(vars[v_idx].low, lo_c);
                            else { vars[v_idx].low = lo_c; vars[v_idx].has_low = true; }

                            if (vars[v_idx].has_high) vars[v_idx].high = std::min(vars[v_idx].high, actual_hi);
                            else { vars[v_idx].high = actual_hi; vars[v_idx].has_high = true; }

                            handled = true;
                        } else if (!lo_const && hi_const) {
                            int u_idx = -1;
                            int64_t C = 0;
                            if (auto u_id = Is<Ident>(re->lo); u_id && var_idx.count(u_id->name)) {
                                u_idx = var_idx[u_id->name];
                                C = 0;
                            } else if (auto b_add = Is<Binary>(re->lo)) {
                                if (b_add->op == T_PLUS) {
                                    if (auto u_id = Is<Ident>(b_add->left); u_id && var_idx.count(u_id->name) && ConstInt(b_add->right, C)) {
                                        u_idx = var_idx[u_id->name];
                                    } else if (auto u_id = Is<Ident>(b_add->right); u_id && var_idx.count(u_id->name) && ConstInt(b_add->left, C)) {
                                        u_idx = var_idx[u_id->name];
                                    }
                                } else if (b_add->op == T_MINUS) {
                                    if (auto u_id = Is<Ident>(b_add->left); u_id && var_idx.count(u_id->name) && ConstInt(b_add->right, C)) {
                                        u_idx = var_idx[u_id->name];
                                        C = -C;
                                    }
                                }
                            }

                            if (u_idx >= 0 && u_idx != v_idx) {
                                int64_t actual_hi = re->inclusive ? hi_c : hi_c - 1;
                                vars[v_idx].tier = 2;
                                vars[v_idx].dep_var = vars[u_idx].name;
                                vars[v_idx].dep_offset = C;

                                if (vars[v_idx].has_high) vars[v_idx].high = std::min(vars[v_idx].high, actual_hi);
                                else { vars[v_idx].high = actual_hi; vars[v_idx].has_high = true; }

                                add_edge(u_idx, v_idx, C);
                                handled = true;
                            }
                        }
                    } else if (auto dot = Is<Dot>(bin->left); dot && dot->name == "len") {
                        if (auto data_id = Is<Ident>(dot->obj); data_id && var_idx.count(data_id->name)) {
                            int d_idx = var_idx[data_id->name];
                            int64_t lo_c = 0, hi_c = 0;
                            if (ConstInt(re->lo, lo_c) && ConstInt(re->hi, hi_c)) {
                                int64_t actual_hi = re->inclusive ? hi_c : hi_c - 1;
                                vars[d_idx].is_len_bound = true;
                                vars[d_idx].min_len = std::max(vars[d_idx].min_len, lo_c);
                                vars[d_idx].max_len = std::min(vars[d_idx].max_len, actual_hi);
                                handled = true;
                            }
                        }
                    }
                }
            } else if (bin->op == T_GT || bin->op == T_GTEQ || bin->op == T_LT || bin->op == T_LTEQ || bin->op == T_EQ) {
                // data.len op C
                if (auto dot = Is<Dot>(bin->left); dot && dot->name == "len") {
                    if (auto data_id = Is<Ident>(dot->obj); data_id && var_idx.count(data_id->name)) {
                        int d_idx = var_idx[data_id->name];
                        int64_t C = 0;
                        if (ConstInt(bin->right, C)) {
                            vars[d_idx].is_len_bound = true;
                            if (bin->op == T_GT) vars[d_idx].min_len = std::max(vars[d_idx].min_len, C + 1);
                            else if (bin->op == T_GTEQ) vars[d_idx].min_len = std::max(vars[d_idx].min_len, C);
                            else if (bin->op == T_LT) vars[d_idx].max_len = std::min(vars[d_idx].max_len, C - 1);
                            else if (bin->op == T_LTEQ) vars[d_idx].max_len = std::min(vars[d_idx].max_len, C);
                            else if (bin->op == T_EQ) {
                                vars[d_idx].min_len = std::max(vars[d_idx].min_len, C);
                                vars[d_idx].max_len = std::min(vars[d_idx].max_len, C);
                            }
                            handled = true;
                        }
                    }
                } else if (auto dot = Is<Dot>(bin->right); dot && dot->name == "len") {
                    if (auto data_id = Is<Ident>(dot->obj); data_id && var_idx.count(data_id->name)) {
                        int d_idx = var_idx[data_id->name];
                        int64_t C = 0;
                        if (ConstInt(bin->left, C)) {
                            vars[d_idx].is_len_bound = true;
                            if (bin->op == T_LT) vars[d_idx].min_len = std::max(vars[d_idx].min_len, C + 1);
                            else if (bin->op == T_LTEQ) vars[d_idx].min_len = std::max(vars[d_idx].min_len, C);
                            else if (bin->op == T_GT) vars[d_idx].max_len = std::min(vars[d_idx].max_len, C - 1);
                            else if (bin->op == T_GTEQ) vars[d_idx].max_len = std::min(vars[d_idx].max_len, C);
                            else if (bin->op == T_EQ) {
                                vars[d_idx].min_len = std::max(vars[d_idx].min_len, C);
                                vars[d_idx].max_len = std::min(vars[d_idx].max_len, C);
                            }
                            handled = true;
                        }
                    }
                }
                // v op C
                else if (auto v_id = Is<Ident>(bin->left); v_id && var_idx.count(v_id->name)) {
                    int v_idx = var_idx[v_id->name];
                    int64_t C = 0;
                    if (ConstInt(bin->right, C)) {
                        if (bin->op == T_GT) {
                            int64_t lo = C + 1;
                            if (vars[v_idx].has_low) vars[v_idx].low = std::max(vars[v_idx].low, lo);
                            else { vars[v_idx].low = lo; vars[v_idx].has_low = true; }
                        } else if (bin->op == T_GTEQ) {
                            int64_t lo = C;
                            if (vars[v_idx].has_low) vars[v_idx].low = std::max(vars[v_idx].low, lo);
                            else { vars[v_idx].low = lo; vars[v_idx].has_low = true; }
                        } else if (bin->op == T_LT) {
                            int64_t hi = C - 1;
                            if (vars[v_idx].has_high) vars[v_idx].high = std::min(vars[v_idx].high, hi);
                            else { vars[v_idx].high = hi; vars[v_idx].has_high = true; }
                        } else if (bin->op == T_LTEQ) {
                            int64_t hi = C;
                            if (vars[v_idx].has_high) vars[v_idx].high = std::min(vars[v_idx].high, hi);
                            else { vars[v_idx].high = hi; vars[v_idx].has_high = true; }
                        } else if (bin->op == T_EQ) {
                            if (vars[v_idx].has_low) vars[v_idx].low = std::max(vars[v_idx].low, C);
                            else { vars[v_idx].low = C; vars[v_idx].has_low = true; }
                            if (vars[v_idx].has_high) vars[v_idx].high = std::min(vars[v_idx].high, C);
                            else { vars[v_idx].high = C; vars[v_idx].has_high = true; }
                        }
                        handled = true;
                    } else {
                        // v op (u + K)
                        int u_idx = -1;
                        int64_t K = 0;
                        if (auto u_id = Is<Ident>(bin->right); u_id && var_idx.count(u_id->name)) {
                            u_idx = var_idx[u_id->name];
                            K = 0;
                        } else if (auto b_right = Is<Binary>(bin->right)) {
                            if (b_right->op == T_PLUS) {
                                if (auto u_id = Is<Ident>(b_right->left); u_id && var_idx.count(u_id->name) && ConstInt(b_right->right, K)) {
                                    u_idx = var_idx[u_id->name];
                                } else if (auto u_id = Is<Ident>(b_right->right); u_id && var_idx.count(u_id->name) && ConstInt(b_right->left, K)) {
                                    u_idx = var_idx[u_id->name];
                                }
                            } else if (b_right->op == T_MINUS) {
                                if (auto u_id = Is<Ident>(b_right->left); u_id && var_idx.count(u_id->name) && ConstInt(b_right->right, K)) {
                                    u_idx = var_idx[u_id->name];
                                    K = -K;
                                }
                            }
                        }

                        if (u_idx >= 0 && u_idx != v_idx) {
                            if (bin->op == T_GT) {
                                add_edge(u_idx, v_idx, K + 1);
                                vars[v_idx].tier = 2;
                                vars[v_idx].dep_var = vars[u_idx].name;
                                vars[v_idx].dep_offset = K + 1;
                                handled = true;
                            } else if (bin->op == T_GTEQ) {
                                add_edge(u_idx, v_idx, K);
                                vars[v_idx].tier = 2;
                                vars[v_idx].dep_var = vars[u_idx].name;
                                vars[v_idx].dep_offset = K;
                                handled = true;
                            } else if (bin->op == T_LT) {
                                add_edge(v_idx, u_idx, 1 - K);
                                vars[u_idx].tier = 2;
                                vars[u_idx].dep_var = vars[v_idx].name;
                                vars[u_idx].dep_offset = 1 - K;
                                handled = true;
                            } else if (bin->op == T_LTEQ) {
                                add_edge(v_idx, u_idx, -K);
                                vars[u_idx].tier = 2;
                                vars[u_idx].dep_var = vars[v_idx].name;
                                vars[u_idx].dep_offset = -K;
                                handled = true;
                            }
                        }
                    }
                }
                // C op v
                else if (auto v_id = Is<Ident>(bin->right); v_id && var_idx.count(v_id->name)) {
                    int v_idx = var_idx[v_id->name];
                    int64_t C = 0;
                    if (ConstInt(bin->left, C)) {
                        if (bin->op == T_LT) {
                            int64_t lo = C + 1;
                            if (vars[v_idx].has_low) vars[v_idx].low = std::max(vars[v_idx].low, lo);
                            else { vars[v_idx].low = lo; vars[v_idx].has_low = true; }
                        } else if (bin->op == T_LTEQ) {
                            int64_t lo = C;
                            if (vars[v_idx].has_low) vars[v_idx].low = std::max(vars[v_idx].low, lo);
                            else { vars[v_idx].low = lo; vars[v_idx].has_low = true; }
                        } else if (bin->op == T_GT) {
                            int64_t hi = C - 1;
                            if (vars[v_idx].has_high) vars[v_idx].high = std::min(vars[v_idx].high, hi);
                            else { vars[v_idx].high = hi; vars[v_idx].has_high = true; }
                        } else if (bin->op == T_GTEQ) {
                            int64_t hi = C;
                            if (vars[v_idx].has_high) vars[v_idx].high = std::min(vars[v_idx].high, hi);
                            else { vars[v_idx].high = hi; vars[v_idx].has_high = true; }
                        } else if (bin->op == T_EQ) {
                            if (vars[v_idx].has_low) vars[v_idx].low = std::max(vars[v_idx].low, C);
                            else { vars[v_idx].low = C; vars[v_idx].has_low = true; }
                            if (vars[v_idx].has_high) vars[v_idx].high = std::min(vars[v_idx].high, C);
                            else { vars[v_idx].high = C; vars[v_idx].has_high = true; }
                        }
                        handled = true;
                    }
                }
                // (u + K) op v
                else if (auto b_left = Is<Binary>(bin->left)) {
                    int u_idx = -1;
                    int64_t K = 0;
                    if (b_left->op == T_PLUS) {
                        if (auto u_id = Is<Ident>(b_left->left); u_id && var_idx.count(u_id->name) && ConstInt(b_left->right, K)) {
                            u_idx = var_idx[u_id->name];
                        } else if (auto u_id = Is<Ident>(b_left->right); u_id && var_idx.count(u_id->name) && ConstInt(b_left->left, K)) {
                            u_idx = var_idx[u_id->name];
                        }
                    } else if (b_left->op == T_MINUS) {
                        if (auto u_id = Is<Ident>(b_left->left); u_id && var_idx.count(u_id->name) && ConstInt(b_left->right, K)) {
                            u_idx = var_idx[u_id->name];
                            K = -K;
                        }
                    }
                    if (auto v_id = Is<Ident>(bin->right); v_id && var_idx.count(v_id->name) && u_idx >= 0 && u_idx != var_idx[v_id->name]) {
                        int v_idx = var_idx[v_id->name];
                        // u + K < v <=> v > u + K
                        if (bin->op == T_LT) {
                            add_edge(u_idx, v_idx, K + 1);
                            vars[v_idx].tier = 2;
                            vars[v_idx].dep_var = vars[u_idx].name;
                            vars[v_idx].dep_offset = K + 1;
                            handled = true;
                        } else if (bin->op == T_LTEQ) {
                            add_edge(u_idx, v_idx, K);
                            vars[v_idx].tier = 2;
                            vars[v_idx].dep_var = vars[u_idx].name;
                            vars[v_idx].dep_offset = K;
                            handled = true;
                        } else if (bin->op == T_GT) {
                            add_edge(v_idx, u_idx, 1 - K);
                            vars[u_idx].tier = 2;
                            vars[u_idx].dep_var = vars[v_idx].name;
                            vars[u_idx].dep_offset = 1 - K;
                            handled = true;
                        } else if (bin->op == T_GTEQ) {
                            add_edge(v_idx, u_idx, -K);
                            vars[u_idx].tier = 2;
                            vars[u_idx].dep_var = vars[v_idx].name;
                            vars[u_idx].dep_offset = -K;
                            handled = true;
                        }
                    }
                }
            }
        }

        if (!handled) {
            prop->analysis.tier3_constraints.push_back(c);
        }
    }

    // Check 1: Static Unsatisfiability Check (Tier 1)
    for (auto &v : vars) {
        if (v.has_low && v.has_high && v.low > v.high) {
            Error(prop->line, cat("unsatisfiable constraint on '", v.name, "': interval is empty"));
        }
        if (v.is_len_bound && v.min_len > v.max_len) {
            Error(prop->line, cat("unsatisfiable constraint on '", v.name, "': interval is empty"));
        }
    }

    // Check 2: Cycle Detection (Tier 2)
    vector<int> state(N, 0);
    bool has_cycle = false;
    function<void(int)> dfs = [&](int u) {
        state[u] = 1;
        for (auto &edge : adj[u]) {
            int v = edge.first;
            if (state[v] == 1) {
                has_cycle = true;
                return;
            }
            if (state[v] == 0) dfs(v);
            if (has_cycle) return;
        }
        state[u] = 2;
    };

    for (int i = 0; i < N; i++) {
        if (state[i] == 0) dfs(i);
        if (has_cycle) break;
    }

    if (has_cycle) {
        Error(prop->line, "cyclic constraint between property variables");
    }

    // Check 3: Reverse-Topological Bound Tightening (Tier 2)
    vector<int> in_degree(N, 0);
    for (int u = 0; u < N; u++) {
        for (auto &edge : adj[u]) {
            in_degree[edge.first]++;
        }
    }

    vector<int> Q;
    for (int i = 0; i < N; i++) {
        if (in_degree[i] == 0) Q.push_back(i);
    }

    vector<int> topo;
    size_t qhead = 0;
    while (qhead < Q.size()) {
        int u = Q[qhead++];
        topo.push_back(u);
        for (auto &edge : adj[u]) {
            int v = edge.first;
            if (--in_degree[v] == 0) Q.push_back(v);
        }
    }
    prop->analysis.gen_order = topo;

    // Reverse-topological tightening: sinks back to roots
    for (int i = (int)topo.size() - 1; i >= 0; i--) {
        int v = topo[i];
        for (auto &edge : rev_adj[v]) {
            int u = edge.first;
            int64_t C = edge.second;
            if (vars[v].has_high) {
                int64_t tightened_upper = vars[v].high - C;
                if (vars[u].has_high) {
                    vars[u].high = std::min(vars[u].high, tightened_upper);
                } else {
                    vars[u].high = tightened_upper;
                    vars[u].has_high = true;
                }
                if (vars[u].has_low && vars[u].low > vars[u].high) {
                    Error(prop->line, cat("unsatisfiable constraint on '", vars[u].name, "': interval is empty"));
                }
            }
        }
    }

    // Forward propagation of lower bounds
    for (int u : topo) {
        if (vars[u].has_low) {
            for (auto &edge : adj[u]) {
                int v = edge.first;
                int64_t C = edge.second;
                int64_t implied_low = vars[u].low + C;
                if (vars[v].has_low) {
                    vars[v].low = std::max(vars[v].low, implied_low);
                } else {
                    vars[v].low = implied_low;
                    vars[v].has_low = true;
                }
                if (vars[v].has_high && vars[v].low > vars[v].high) {
                    Error(prop->line, cat("unsatisfiable constraint on '", vars[v].name, "': interval is empty"));
                }
            }
        }
    }

    // Check 4: Tier 3 Safety Check (Unbounded Variable Enforcement)
    for (auto pred : prop->analysis.tier3_constraints) {
        function<void(Node *)> check_var = [&](Node *n) {
            if (!n) return;
            if (auto id = Is<Ident>(n)) {
                if (var_idx.count(id->name)) {
                    int idx = var_idx[id->name];
                    auto &v = vars[idx];
                    if (!v.is_slice) {
                        if (!v.has_low || !v.has_high) {
                            Error(id->line.line ? id->line : prop->line,
                                  cat("variable '", v.name,
                                      "' in runtime constraint has an unbounded domain; hint: add an explicit interval bound in 'where', e.g., '",
                                      v.name, " in 1..=1000'"));
                        }
                    }
                }
            }
            n->Children(check_var);
        };
        check_var(pred);
    }
}

}  // namespace goose
