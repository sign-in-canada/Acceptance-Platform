/*!
 * Web Experience Toolkit (WET) / BoÃ®te Ã Â  outils de l'expÃ©rience Web (BOEW)
 * wet-boew.github.io/wet-boew/License-en.html / wet-boew.github.io/wet-boew/Licence-fr.html
 * v5.1.0-development - 2019-03-22
 * - gcweb-menu changed for gcweb-v2
 * - fix - Menu screen reader compatibility issue
 * - 2019-02-27 - Initial commit - Chat wizard
 * - 2019-02-28 - Binding wb5 table with URL mapping plugin
 * - 2019-03-09 - Added gcweb-menu to remove gcweb-v2 codename
 * - 2019-03-16 - Added Geomap filter in the action manager
 * - 2019-03-22 - Added Chat wizard and steps form plugins
 * - 2019-04-11 - Minor updates to the Chat wizard
 * - 2019-05-07 - Hotfix GCWeb menu V2
 * - 2019-05-14 - GCWeb responsive header and Experimental
 *
 */
! function(A, j) {
    "use strict";
    var e = j.doc,
        u = "wb-actionmng",
        l = "." + u,
        t = "[data-" + u + "]",
        C = u + "Rn",
        E = u + l,
        p = {},
        f = {},
        S = {},
        a = ["mapfilter", "patch", "ajax", "addClass", "removeClass", "tblfilter", "run"].join("." + E + " ") + "." + E,
        h = function(e, t, a) {
            t[e] || (t[e] = []), t[e].push(a)
        },
        b = function(e, t, a) {
            var r, n, i;
            for (r = a[t]; n = r.shift();)(i = n.action) && (e.trigger(i + "." + E, n), delete n.action)
        };
    e.on("do." + E, function(e) {
        var t, a, r, n, i, o, s, l = e.element || e.target,
            d = l.id,
            c = e.actions || [];
        if ((l === e.target || e.currentTarget === e.target) && -1 === l.className.indexOf(u)) {
            for (A.isArray(c) || (c = [c]), (r = c.length) && (t = A(l)).addClass(u), d && p[d] && b(t, d, p), a = 0; a !== r; a += 1)(i = (n = c[a]).action) && ((o = n.target) ? (n.trgbefore ? h(o, p, n) : h(o, f, n), (s = n.trggroup) && h(s, S, n)) : t.trigger(i + "." + E, n));
            d && f[d] && b(t, d, f), A(e.target).removeClass(u)
        }
    }), e.on("clean." + E, function(e) {
        var t, a, r = e.element || e.target,
            n = e.trggroup;
        if ((r === e.target || e.currentTarget === e.target) && n && S[n])
            for (t = S[n]; a = t.shift();) delete a.action
    }), e.on(a, l, function(e, t) {
        var a, r, n, i, o, s, l, d, c, u, p, f, h, b, g, m, v, w, y, x, k = e.type;
        if (E === e.namespace) switch (k) {
            case "run":
                ! function(e, t) {
                    var a, r, n, i, o = e.target,
                        s = A(o),
                        l = S[t.trggroup];
                    if (l && !s.hasClass(C)) {
                        for (s.addClass(C), r = l.length, a = 0; a !== r; a += 1)(i = (n = l[a]).action) && s.trigger(i + "." + E, n);
                        s.removeClass(C)
                    }
                }(e, t);
                break;
            case "tblfilter":
                ! function(e, t) {
                    var a = e.target,
                        r = A(t.source || a),
                        n = t.column,
                        i = parseInt(n, 10),
                        o = !!t.regex,
                        s = !t.smart || !!t.smart,
                        l = !t.caseinsen || !!t.caseinsen;
                    if ("TABLE" !== r.get(0).nodeName) throw "Table filtering can only applied on table";
                    n = !0 === i ? i : n, r.dataTable({
                        retrieve: !0
                    }).api().column(n).search(t.value, o, s, l).draw()
                }(e, t);
                break;
            case "addClass":
                w = e, x = A((y = t).source || w.target), y.class && x.addClass(y.class);
                break;
            case "removeClass":
                g = e, v = A((m = t).source || g.target), m.class && v.removeClass(m.class);
                break;
            case "ajax":
                u = e, (p = t).container ? f = A(p.container) : (h = j.getId(), f = A("<div id='" + h + "'></div>"), A(u.target).after(f)), p.trigger && f.attr("data-trigger-wet", "true"), b = p.type ? p.type : "replace", f.attr("data-ajax-" + b, p.url), f.one("wb-contentupdated", function(e, t) {
                    var a = e.currentTarget,
                        r = a.getAttribute("data-trigger-wet");
                    a.removeAttribute("data-ajax-" + t["ajax-type"]), r && (A(a).find(j.allSelectors).addClass("wb-init").filter(":not(#" + a.id + " .wb-init .wb-init)").trigger("timerpoke.wb"), a.removeAttribute("data-trigger-wet"))
                }), f.trigger("wb-update.wb-data-ajax");
                break;
            case "patch":
                l = (s = t).source, d = s.patches, c = !!s.cumulative, d && (A.isArray(d) || (d = [d]), A(l).trigger({
                    type: "patches.wb-jsonmanager",
                    patches: d,
                    fpath: s.fpath,
                    filter: s.filter || [],
                    filternot: s.filternot || [],
                    cumulative: c
                }));
                break;
            case "mapfilter":
                a = e, n = A((r = t).source || a.target).get(0).geomap, i = r.filter, o = r.value, "aoi" === i && n.zoomAOI(o), "layer" === i && n.showLayer(o, !0)
        }
    }), e.on("timerpoke.wb wb-init.wb-actionmng", t, function(e) {
        var t, a, r, n, i, o, s = j.init(e, u, l);
        if (s) {
            if (t = A(s), a = j.getData(t, u))
                for (A.isArray(a) || (a = [a]), n = a.length, r = 0; r !== n; r += 1)(o = (i = a[r]).trggroup) && i.action && h(o, S, i);
            j.ready(t, u)
        }
    }), j.add(t)
}(jQuery, wb),
function(a, r) {
    "use strict";
    var e = r.doc,
        n = "wb-bgimg",
        i = "[data-bgimg]";
    e.on("timerpoke.wb wb-init." + n, i, function(e) {
        var t = r.init(e, n, i);
        t && (t.style.backgroundImage = "url(" + t.dataset.bgimg + ")", r.ready(a(t), n))
    }), r.add(i)
}(jQuery, wb),
function(j, d, C) {
    "use strict";
    var e, p = "wb-data-json",
        u = "wb-json",
        t = ["[data-json-after]", "[data-json-append]", "[data-json-before]", "[data-json-prepend]", "[data-json-replace]", "[data-json-replacewith]", "[data-" + u + "]"],
        f = ["after", "append", "before", "prepend", "val"],
        h = /(href|src|data-*|pattern|min|max|step|low|high)/,
        b = /(checked|selected|disabled|required|readonly|multiple|hidden)/,
        a = t.length,
        g = t.join(","),
        m = p + "-queue",
        r = C.doc,
        v = function(e, t, a, r, n) {
            var i, o = j(e),
                s = {
                    url: t,
                    refId: a,
                    nocache: r,
                    nocachekey: n
                },
                l = d[p];
            !l || "http" !== t.substr(0, 4) && "//" !== t.substr(0, 2) || (i = C.getUrlParts(t), C.pageUrlParts.protocol === i.protocol && C.pageUrlParts.host === i.host || Modernizr.cors && !l.forceCorsFallback || "function" == typeof l.corsFallback && (s.dataType = "jsonp", s.jsonp = "callback", s = l.corsFallback(s))), o.trigger({
                type: "json-fetch.wb",
                fetch: s
            })
        },
        E = function(e, t, a) {
            var r, n, i, o, s, l, d, c, u, p, f, h, b, g = t.mapping || [{}],
                m = t.filter || [],
                v = t.filternot || [],
                w = t.queryall,
                y = t.tobeclone,
                x = e.className,
                k = e,
                A = t.source ? document.querySelector(t.source) : e.querySelector("template");
            if (j.isArray(a) || (a = "object" != typeof a ? [a] : j.map(a, function(e, t) {
                    return "object" != typeof e || j.isArray(e) ? e = {
                        "@id": t,
                        "@value": e
                    } : e["@id"] || (e["@id"] = t), [e]
                })), i = a.length, j.isArray(g) || (g = [g]), r = g.length, "TABLE" === e.tagName && g && -1 !== x.indexOf("wb-tables-inited") && "string" == typeof g[0]) {
                for (b = j(e).dataTable({
                        retrieve: !0
                    }).api(), n = 0; n < i; n += 1)
                    if (o = a[n], S(o, m, v)) {
                        for (c = "/" + n, h = [], s = 0; s < r; s += 1) h.push(jsonpointer.get(a, c + g[s]));
                        b.row.add(h)
                    }
                b.draw()
            } else if (A)
                for (A.content || C.tmplPolyfill(A), t.appendto && (k = j(t.appendto).get(0)), n = 0; n < i; n += 1)
                    if (o = a[n], S(o, m, v)) {
                        for (c = "/" + n, u = y ? A.content.querySelector(y).cloneNode(!0) : A.content.cloneNode(!0), w && (p = u.querySelectorAll(w)), s = 0; s < r || 0 === s; s += 1) l = g[s], f = p ? p[s] : l.selector ? u.querySelector(l.selector) : u, (d = l.attr) && (f.hasAttribute(d) || f.setAttribute(d, ""), f = f.getAttributeNode(d)), h = "string" == typeof o ? o : "string" == typeof l ? jsonpointer.get(a, c + l) : jsonpointer.get(a, c + l.value), l.placeholder && (h = (f.textContent || "").replace(l.placeholder, h)), j.isArray(h) ? E(f, l, h) : l.isHTML ? f.innerHTML = h : f.textContent = h;
                        k.appendChild(u)
                    }
        },
        S = function(e, t, a) {
            var r, n, i, o = t.length,
                s = a.length,
                l = !1;
            if (o || s) {
                for (r = 0; r < o; r += 1)
                    if (n = t[r], i = c(jsonpointer.get(e, n.path), n.value), n.optional) l = l || i;
                    else {
                        if (!i) return !1;
                        l = !0
                    }
                if (o && !l) return !1;
                for (r = 0; r < s; r += 1)
                    if (n = a[r], (i = c(jsonpointer.get(e, n.path), n.value)) && !n.optional || i && n.optional) return !1
            }
            return !0
        },
        c = function(e, t) {
            switch (typeof e) {
                case "undefined":
                    return !1;
                case "boolean":
                case "string":
                case "number":
                    return e === t;
                case "object":
                    if (null === e) return null === t;
                    if (j.isArray(e)) {
                        if (j.isArray(t) || e.length !== t.length) return !1;
                        for (var a = 0, r = e.length; a < r; a++)
                            if (!c(e[a], t[a])) return !1;
                        return !0
                    }
                    var n = i(t).length;
                    if (i(e).length !== n) return !1;
                    for (a = 0; a < n; a++)
                        if (!c(e[a], t[a])) return !1;
                    return !0;
                default:
                    return !1
            }
        },
        i = function(e) {
            if (j.isArray(e)) {
                for (var t = new Array(e.length), a = 0; a < t.length; a++) t[a] = "" + a;
                return t
            }
            if (Object.keys) return Object.keys(e);
            t = [];
            for (var r in e) e.hasOwnProperty(r) && t.push(r);
            return t
        };
    r.on("json-failed.wb", g, function() {
        throw "Bad JSON Fetched from url in " + p
    }), Modernizr.load({
        test: "content" in document.createElement("template"),
        nope: "site!deps/template" + C.getMode() + ".js"
    }), r.on("timerpoke.wb wb-init.wb-data-json wb-update.wb-data-json json-fetched.wb", g, function(e) {
        if (e.currentTarget === e.target) switch (e.type) {
            case "timerpoke":
            case "wb-init":
                ! function(e) {
                    var t, a = C.init(e, p, g);
                    if (a) {
                        var r, n, i, o, s, l = ["before", "replace", "replacewith", "after", "append", "prepend"],
                            d = l.length,
                            c = [];
                        for (t = j(a), i = 0; i !== d; i += 1) r = l[i], null !== (s = a.getAttribute("data-json-" + r)) && c.push({
                            type: r,
                            url: s
                        });
                        if (C.ready(t, p), (n = C.getData(t, u)) && n.url) c.push(n);
                        else if (n && j.isArray(n))
                            for (d = n.length, i = 0; i !== d; i += 1) c.push(n[i]);
                        for (t.data(m, c), d = c.length, i = 0; i !== d; i += 1) o = c[i], v(a, o.url, i, o.nocache, o.nocachekey)
                    }
                }(e);
                break;
            case "wb-update":
                ! function(e) {
                    var t = e.target,
                        a = j(t),
                        r = a.data(m),
                        n = r.length,
                        i = e["wb-json"];
                    if (!i.url || !i.type && !i.source) throw "Data JSON update not configured properly";
                    r.push(i), a.data(m, r), v(t, i.url, n)
                }(e);
                break;
            default:
                ! function(e) {
                    var t, a = e.target,
                        r = j(a),
                        n = r.data(m),
                        i = e.fetch,
                        o = n[i.refId],
                        s = o.type,
                        l = o.prop || o.attr,
                        d = o.showempty,
                        c = i.response,
                        u = typeof c;
                    if (d || "undefined" !== u) {
                        if (d && "undefined" === u && (c = ""), t = jQuery.ajaxSettings.cache, jQuery.ajaxSettings.cache = !0, s)
                            if ("replace" === s) r.html(c);
                            else if ("replacewith" === s) r.replaceWith(c);
                        else if ("addclass" === s) r.addClass(c);
                        else if ("removeclass" === s) r.removeClass(c);
                        else if ("prop" === s && l && b.test(l)) r.prop(l, c);
                        else if ("attr" === s && l && h.test(l)) r.attr(l, c);
                        else {
                            if ("function" != typeof r[s] || -1 === f.indexOf(s)) throw p + " do not support type: " + s;
                            r[s](c)
                        } else s = "template", E(a, o, c), o.trigger && r.find(C.allSelectors).addClass("wb-init").filter(":not(#" + a.id + " .wb-init .wb-init)").trigger("timerpoke.wb");
                        jQuery.ajaxSettings.cache = t, r.trigger("wb-contentupdated", {
                            "json-type": s,
                            content: c
                        })
                    }
                }(e)
        }
        return !0
    });
    for (e = 0; e !== a; e += 1) C.add(t[e])
}(jQuery, window, wb),
function(a, n, r) {
    "use strict";
    var i = "wb-template",
        o = "template",
        e = r.doc,
        s = function(e) {
            if (!e.content) {
                var t, a, r = e;
                for (t = r.childNodes, a = n.createDocumentFragment(); t[0];) a.appendChild(t[0]);
                r.content = a
            }
        };
    r.tmplPolyfill = s, e.on("timerpoke.wb wb-init.wb-template", o, function(e) {
        var t = r.init(e, i, o);
        t && (s(t), r.ready(a(t), i))
    }), r.add(o)
}(jQuery, document, wb),
function(r, e, n) {
    "use strict";
    var i = "wb-doaction",
        o = "a[data-" + i + "],button[data-" + i + "]",
        s = "do.wb-actionmng",
        l = n.doc;
    l.on("click", o, function(e) {
        var t = e.target,
            a = r(t);
        if (e.currentTarget !== e.target && (t = (a = a.parentsUntil("main", o))[0]), "BUTTON" === t.nodeName || "A" === t.nodeName) return n.isReady ? a.trigger({
            type: s,
            actions: n.getData(a, i)
        }) : l.one("wb-ready.wb", function() {
            a.trigger({
                type: s,
                actions: n.getData(a, i)
            })
        }), !1
    })
}(jQuery, document, wb),
function(f, h) {
    "use strict";
    var e = h.doc,
        b = {},
        g = {},
        m = function(e, t, a, r, n, i) {
            if (!window.jsonpointer) return setTimeout(function() {
                m(e, t, a, r, n, i)
            }, 100), !1;
            i && (a = jsonpointer.get(a, i)), f("#" + e).trigger({
                type: "json-fetched.wb",
                fetch: {
                    response: a,
                    status: r,
                    xhr: n,
                    refId: t
                }
            }, this)
        };
    e.on("json-fetch.wb", function(e) {
        var t, a, s, r, n = e.element || e.target,
            l = e.fetch,
            i = l.url.split("#"),
            d = i[0],
            o = l.nocache,
            c = l.nocachekey || h.cacheBustKey || "wbCacheBust",
            u = i[1] || !1,
            p = l.refId;
        if (n === e.target || e.currentTarget === e.target) {
            if (n.id || (n.id = h.getId()), s = n.id, u) {
                if (91 === (a = u.split("/")[0]).charCodeAt(0)) return void f("#" + s).trigger({
                    type: "postpone.wb-jsonmanager",
                    postpone: {
                        callerId: s,
                        refId: p,
                        dsname: a,
                        selector: u.substring(a.length)
                    }
                });
                l.url = d
            }
            o && (t = c + "=" + ("nocache" === o ? h.guid() : h.sessionGUID()), d = -1 !== d.indexOf("?") ? d + "&" + t : d + "?" + t, l.url = d), Modernizr.load({
                load: "site!deps/jsonpointer" + h.getMode() + ".js",
                complete: function() {
                    if (!l.nocache) {
                        if (r = b[d]) return void m(s, p, r, "success", void 0, u);
                        if (g[d]) return void g[d].push({
                            callerId: s,
                            refId: p,
                            selector: u
                        });
                        g[d] = []
                    }
                    f.ajax(l).done(function(e, t, a) {
                        var r, n, i, o;
                        if (!l.nocache) try {
                            b[d] = e
                        } catch (e) {
                            return
                        }
                        if (m(s, p, e, t, a, u), g[d])
                            for (n = (o = g[d]).length, r = 0; r !== n; r += 1) i = o[r], m(i.callerId, i.refId, e, t, a, i.selector)
                    }).fail(function(e, t, a) {
                        f("#" + s).trigger({
                            type: "json-failed.wb",
                            fetch: {
                                xhr: e,
                                status: t,
                                error: a,
                                refId: p
                            }
                        }, this)
                    }, this)
                }
            })
        }
    })
}(jQuery, wb),
function(m, p, v) {
    "use strict";
    var w = "wb-jsonmanager",
        f = "[data-" + w + "]",
        h = [],
        y = {},
        x = {},
        k = {},
        e = v.doc,
        b = {
            ops: [{
                name: "wb-count",
                fn: function(e, t, a) {
                    var r, n, i = e[t],
                        o = 0,
                        s = this.filter || [],
                        l = this.filternot || [];
                    if (m.isArray(s) || (s = [s]), m.isArray(l) || (l = [l]), (s.length || l.length) && m.isArray(i))
                        for (r = i.length, n = 0; n !== r; n += 1) d(i[n], s, l) && (o += 1);
                    else m.isArray(i) && (o = i.length);
                    jsonpatch.apply(a, [{
                        op: "add",
                        path: this.set,
                        value: o
                    }])
                }
            }, {
                name: "wb-first",
                fn: function(e, t, a) {
                    var r = e[t];
                    m.isArray(r) && 0 !== r.length && jsonpatch.apply(a, [{
                        op: "add",
                        path: this.set,
                        value: r[0]
                    }])
                }
            }, {
                name: "wb-last",
                fn: function(e, t, a) {
                    var r = e[t];
                    m.isArray(r) && 0 !== r.length && jsonpatch.apply(a, [{
                        op: "add",
                        path: this.set,
                        value: r[r.length - 1]
                    }])
                }
            }, {
                name: "wb-nbtolocal",
                fn: function(e, t, a) {
                    var r = e[t],
                        n = this.locale || p.wb.lang,
                        i = this.suffix || "",
                        o = this.prefix || "";
                    "string" == typeof r && (r = parseFloat(r), isNaN(r)) || jsonpatch.apply(a, [{
                        op: "replace",
                        path: this.path,
                        value: o + r.toLocaleString(n) + i
                    }])
                }
            }, {
                name: "wb-toDateISO",
                fn: function(e, t, a) {
                    this.set ? jsonpatch.apply(a, [{
                        op: "add",
                        path: this.set,
                        value: v.date.toDateISO(e[t])
                    }]) : jsonpatch.apply(a, [{
                        op: "replace",
                        path: this.path,
                        value: v.date.toDateISO(e[t])
                    }])
                }
            }, {
                name: "wb-toDateTimeISO",
                fn: function(e, t, a) {
                    this.set ? jsonpatch.apply(a, [{
                        op: "add",
                        path: this.set,
                        value: v.date.toDateISO(e[t], !0)
                    }]) : jsonpatch.apply(a, [{
                        op: "replace",
                        path: this.path,
                        value: v.date.toDateISO(e[t], !0)
                    }])
                }
            }],
            opsArray: [{
                name: "wb-toDateISO",
                fn: function(e) {
                    var t, a = this.set,
                        r = this.path,
                        n = e.length;
                    for (t = 0; t !== n; t += 1) a ? jsonpatch.apply(e, [{
                        op: "wb-toDateISO",
                        set: "/" + t + a,
                        path: "/" + t + r
                    }]) : jsonpatch.apply(e, [{
                        op: "wb-toDateISO",
                        path: "/" + t + r
                    }])
                }
            }, {
                name: "wb-toDateTimeISO",
                fn: function(e) {
                    var t, a = this.set,
                        r = this.path,
                        n = e.length;
                    for (t = 0; t !== n; t += 1) a ? jsonpatch.apply(e, [{
                        op: "wb-toDateTimeISO",
                        set: "/" + t + a,
                        path: "/" + t + r
                    }]) : jsonpatch.apply(e, [{
                        op: "wb-toDateTimeISO",
                        path: "/" + t + r
                    }])
                }
            }],
            opsRoot: [],
            settings: {}
        },
        A = function(e, t, a, r) {
            e.after('<p lang="en"><strong>JSON Manager Debug</strong> (' + t + ')</p><ul lang="en"><li>JSON: <pre><code>' + JSON.stringify(a) + "</code></pre></li><li>Patches: <pre><code>" + JSON.stringify(r) + "</code></pre>")
        },
        d = function(e, t, a) {
            var r, n, i, o = t.length,
                s = a.length,
                l = !1;
            if (o || s) {
                for (r = 0; r < o; r += 1)
                    if (n = t[r], i = c(jsonpointer.get(e, n.path), n.value), n.optional) l = l || i;
                    else {
                        if (!i) return !1;
                        l = !0
                    }
                if (o && !l) return !1;
                for (r = 0; r < s; r += 1)
                    if (n = a[r], (i = c(jsonpointer.get(e, n.path), n.value)) && !n.optional || i && n.optional) return !1
            }
            return !0
        },
        c = function(e, t) {
            switch (typeof e) {
                case "undefined":
                    return !1;
                case "boolean":
                case "string":
                case "number":
                    return e === t;
                case "object":
                    if (null === e) return null === t;
                    if (m.isArray(e)) {
                        if (m.isArray(t) || e.length !== t.length) return !1;
                        for (var a = 0, r = e.length; a < r; a++)
                            if (!c(e[a], t[a])) return !1;
                        return !0
                    }
                    var n = i(t).length;
                    if (i(e).length !== n) return !1;
                    for (a = 0; a < n; a++)
                        if (!c(e[a], t[a])) return !1;
                    return !0;
                default:
                    return !1
            }
        },
        i = function(e) {
            if (m.isArray(e)) {
                for (var t = new Array(e.length), a = 0; a < t.length; a++) t[a] = "" + a;
                return t
            }
            if (Object.keys) return Object.keys(e);
            t = [];
            for (var r in e) e.hasOwnProperty(r) && t.push(r);
            return t
        },
        j = function(e, t, a, r) {
            var n, i;
            if (m.isArray(a) || (a = [a]), m.isArray(r) || (r = [r]), n = jsonpointer.get(e, t), m.isArray(n))
                for (i = n.length - 1; - 1 !== i; i -= 1) d(n[i], a, r) || jsonpatch.apply(e, [{
                    op: "remove",
                    path: t + "/" + i
                }]);
            return e
        };
    v.ie && (Number.prototype.toLocaleString = function(e) {
        var t, a = this.toString().split("."),
            r = a[0],
            n = a[1],
            i = r.length,
            o = i % 3 || 3,
            s = r.substr(0, o),
            l = "fr" === e,
            d = l ? " " : ",";
        for (t = o; t < i; t += 3) s = s + d + r.substr(t, 3);
        return n.length && (s = l ? s + "," + n : s + "." + n), s
    }), e.on("json-failed.wb", f, function(e) {
        var t, a = e.target;
        a === e.currentTarget && ((t = m(a)).addClass("jsonfail"), v.ready(t, w))
    }), e.on("json-fetched.wb", f, function(e) {
        var t, a, r, n, i, o, s, l, d, c, u, p, f = e.target,
            h = m(f),
            b = e.fetch.response,
            g = m.isArray(b);
        if (f === e.currentTarget) {
            a = "[" + (t = v.getData(h, w)).name + "]", d = t.patches || [], p = t.fpath, c = t.filter || [], u = t.filternot || [], m.isArray(d) || (d = [d]), b = g ? m.extend([], b) : m.extend({}, b), p && (b = j(b, p, c, u)), d.length && (g && t.wraproot && ((o = {})[t.wraproot] = b, b = o), jsonpatch.apply(b, d)), t.debug && A(h, "initEvent", b, d);
            try {
                y[a] = b
            } catch (e) {
                return
            }
            if (!(x[a] = t).wait && k[a])
                for (i = (s = k[a]).length, n = 0; n !== i; n += 1) {
                    if ((l = (o = s[n]).selector).length) try {
                        r = jsonpointer.get(b, l)
                    } catch (e) {
                        throw a + " - JSON selector not found: " + l
                    } else r = b;
                    m("#" + o.callerId).trigger({
                        type: "json-fetched.wb",
                        fetch: {
                            response: r,
                            status: "200",
                            refId: o.refId,
                            xhr: null
                        }
                    }, this)
                }
            v.ready(h, w)
        }
    }), e.on("patches.wb-jsonmanager", f, function(e) {
        var t, a, r, n, i, o, s, l, d, c = e.target,
            u = m(c),
            p = e.patches,
            f = e.fpath,
            h = e.filter || [],
            b = e.filternot || [],
            g = !!e.cumulative;
        if (c === e.currentTarget && m.isArray(p)) {
            if (!(t = v.getData(u, w))) return !0;
            if (a = "[" + t.name + "]", !k[a]) throw "Applying patched on undefined dataset name: " + a;
            for (r = y[a], g || (r = m.extend(!0, m.isArray(r) ? [] : {}, r)), f && (r = j(r, f, h, b)), jsonpatch.apply(r, p), t.debug && A(u, "patchesEvent", r, p), s = (i = k[a]).length, o = 0; o !== s; o += 1) {
                if ((d = (l = i[o]).selector).length) try {
                    n = jsonpointer.get(r, d)
                } catch (e) {
                    throw a + " - JSON selector not found: " + d
                } else n = r;
                m("#" + l.callerId).trigger({
                    type: "json-fetched.wb",
                    fetch: {
                        response: n,
                        status: "200",
                        refId: l.refId,
                        xhr: null
                    }
                }, this)
            }
        }
    }), e.on("postpone.wb-jsonmanager", function(e) {
        var t, a = e.postpone,
            r = a.dsname,
            n = a.callerId,
            i = a.refId,
            o = a.selector;
        if (k[r] || (k[r] = []), k[r].push({
                callerId: n,
                refId: i,
                selector: o
            }), y[r] && !x[r].wait) {
            if (t = y[r], o.length) try {
                t = jsonpointer.get(t, o)
            } catch (e) {
                throw r + " - JSON selector not found: " + o
            }
            m("#" + n).trigger({
                type: "json-fetched.wb",
                fetch: {
                    response: t,
                    status: "200",
                    refId: i,
                    xhr: null
                }
            }, this)
        }
    }), e.on("op.action.wb-fieldflow", ".wb-fieldflow", function(e, t) {
        var a, r, n, i, o;
        t.op && (t.preventSubmit = !0, a = m(t.provEvt), r = "wb-fieldflow-submit", n = t, (o = a.data(r)) && !i || (o = []), o.push(n), a.data(r, o))
    }), e.on("op.submit.wb-fieldflow", ".wb-fieldflow", function(e, t) {
        var a, r = t.op,
            n = t.source;
        if (!r) return !0;
        m.isArray(r) ? a = r : (a = []).push(r), m(n).trigger({
            type: "patches.wb-jsonmanager",
            patches: a
        })
    }), e.on("timerpoke.wb wb-init.wb-jsonmanager", f, function(e) {
        var t, a, r, n, i, o, s, l, d, c = v.init(e, w, f),
            u = p[w] || {};
        c && (t = m(c), Modernizr.load({
            load: "site!deps/json-patch" + v.getMode() + ".js",
            testReady: function() {
                return p.jsonpatch
            },
            complete: function() {
                var e = v.getData(t, w);
                if (!b.registered) {
                    if (a = b.ops.concat(u.ops || []), r = b.opsArray.concat(u.opsArray || []), n = b.opsRoot.concat(u.opsRoot || []), a.length)
                        for (i = 0, o = a.length; i !== o; i++) s = a[i], jsonpatch.registerOps(s.name, s.fn);
                    if (r.length)
                        for (i = 0, o = r.length; i !== o; i++) s = r[i], jsonpatch.registerOpsArray(s.name, s.fn);
                    if (n.length)
                        for (i = 0, o = n.length; i !== o; i++) s = n[i], jsonpatch.registerOpsRoot(s.name, s.fn);
                    b.settings = m.extend({}, b.settings, u.settings || {}), b.registered = !0
                }
                if (!(d = e.name) || d in h) throw "Dataset name must be unique";
                h.push(d), (l = e.url) ? (t.trigger({
                    type: "json-fetch.wb",
                    fetch: {
                        url: l,
                        nocache: e.nocache,
                        nocachekey: e.nocachekey
                    }
                }), 35 === l.charCodeAt(0) && 91 === l.charCodeAt(1) && v.ready(t, w)) : v.ready(t, w)
            }
        }))
    }), v.add(f)
}(jQuery, window, wb),
function(r, n) {
    "use strict";
    var a, i, w, o, y, s = "gcweb-v2",
        x = "." + s,
        e = n.doc,
        l = x + " [data-ajax-replace]," + x + " [data-ajax-append]," + x + " [data-ajax-prepend]," + x + " [data-wb-ajax]",
        d = 350,
        c = {
            en: "Press the SPACEBAR to expand or the escape key to collapse this menu. Use the up and Down arrow keys to choose a submenu item. Press the Enter or Right arrow key to expand it, or the Left arrow or Escape key to collapse it. Use the up and Down arrow keys to choose an item on that level and the Enter key to access it.",
            fr: "Appuyez sur la barre d'espacement pour ouvrir ou sur la touche d'Ã©chappement pour fermer le menu. Utilisez les flÃ¨ches haut et bas pour choisir un Ã©lÃ©ment de sous-menu. Appuyez sur la touche EntrÃ©e ou sur la flÃ¨che vers la droite pour le dÃ©velopper, ou sur la flÃ¨che vers la gauche ou la touche Ã‰chap pour le rÃ©duire. Utilisez les flÃ¨ches haut et bas pour choisir un Ã©lÃ©ment de ce niveau et la touche EntrÃ©e pour y accÃ©der."
        },
        u = function(e) {
            var t = r(e).parentsUntil(x).parents(),
                a = document.querySelector("html").className;
            w = -1 !== a.indexOf("smallview"), o = -1 !== a.indexOf("mediumview"), (w || o) && p(!1, o), e.previousElementSibling.setAttribute("aria-label", c), n.ready(t, s)
        };

    function k(e) {
        if ("true" !== e.getAttribute("aria-expanded")) {
            var t = e.parentElement.parentElement.querySelector("[aria-haspopup][aria-expanded=true]:not([data-keep-expanded=md-min])");
            t && !w && A(t, !0), e.setAttribute("aria-expanded", "true"), i = e, setTimeout(function() {
                i = !1
            }, d)
        }
    }

    function A(e, t) {
        if (e.hasAttribute("aria-haspopup") || (e = e.previousElementSibling), !t) {
            var a = e.nextElementSibling.querySelector("[role=menuitem]:focus"),
                r = e.parentElement.parentElement.querySelector("[role=menuitem]:focus");
            if (a || r === e) return
        }
        e.setAttribute("aria-expanded", "false")
    }

    function p(e, t) {
        var a, r = document.querySelectorAll("[role=menu] [role=menu] [role=menuitem][aria-haspopup=true]"),
            n = r.length,
            i = t ? "true" : "false",
            o = e ? "vertical" : "horizontal",
            s = i;
        for (a = 0; a < n; a++) s = r[a].nextElementSibling.querySelector("[role=menuitem]:focus") ? "true" : i, r[a].setAttribute("aria-expanded", s), r[a].parentElement.previousElementSibling.setAttribute("aria-orientation", o)
    }
    e.on("mouseenter", x + " ul [aria-haspopup]", function(e) {
        var t;
        w || (clearTimeout(void 0), "md-min" !== (t = e.currentTarget).dataset.keepExpanded && (clearTimeout(a), a = setTimeout(function() {
            k(t)
        }, d)))
    }), e.on("focusin", x + " ul [aria-haspopup]", function(e) {
        w ? y = !1 : k(e.currentTarget)
    }), e.on("mouseenter focusin", x + " [aria-haspopup] + [role=menu]", function(e) {
        "md-min" !== e.currentTarget.previousElementSibling.dataset.keepExpanded && (w || i === e.currentTarget || clearTimeout(void 0))
    }), e.on("mouseleave", x + " [aria-haspopup]", function() {
        clearTimeout(a)
    }), e.on("click", x + " [aria-haspopup]", function(e) {
        var t, a = e.currentTarget;
        y ? y = !1 : ((w || "BUTTON" === a.nodeName) && ("true" === a.getAttribute("aria-expanded") ? i !== a && A(a, !0) : (k(a), (t = a.nextElementSibling.querySelector("[role=menuitem]")).focus(), t.setAttribute("tabindex", "0"))), e.stopImmediatePropagation(), e.preventDefault())
    }), e.on(n.resizeEvents, function(e) {
        switch (e.type) {
            case "xxsmallview":
            case "xsmallview":
            case "smallview":
                p(!(w = !0), !1);
                break;
            case "mediumview":
                p(w = !1, !0);
                break;
            case "largeview":
            case "xlargeview":
            default:
                p(!(w = !1), !0)
        }
    }), e.on("keydown", function(e) {
        27 === e.keyCode && A(document.querySelector(x + " button"))
    }), e.on("keydown", x + " button, " + x + " [role=menuitem]", function(e) {
        var t, a = e.currentTarget,
            r = 9 === (t = e.charCode || e.keyCode) ? "tab" : 13 === t || 32 === t ? "enter" : 27 === t ? "esc" : 39 === t ? "right" : 37 === t ? "left" : 40 === t ? "down" : 38 === t && "up",
            n = document.querySelector("[role=menuitem]:focus") || a,
            i = n.parentElement,
            o = i.parentElement,
            s = "BUTTON" === n.nodeName;
        if ("tab" !== r)
            if (s && "enter" === r && "true" === a.getAttribute("aria-expanded")) A(a, y = !0);
            else {
                var l, d;
                n.nextElementSibling && (l = n.nextElementSibling.querySelector("[role='menuitem']")), i.nextElementSibling ? (d = i.nextElementSibling.querySelector("[role=menuitem]")) || (d = i.nextElementSibling.nextElementSibling.querySelector("[role=menuitem]")) : d = !w && n.dataset.keepExpanded && l ? l : !w && o.previousElementSibling.dataset.keepExpanded ? o.parentElement.parentElement.querySelector("[role=menuitem]") : o.querySelector("[role=menuitem]");
                var c, u = o.previousElementSibling;
                i.previousElementSibling ? (c = i.previousElementSibling.querySelector("[role=menuitem]")) || (c = i.previousElementSibling.previousElementSibling.querySelector("[role=menuitem]")) : c = !w && o.lastElementChild.querySelector("[role=menuitem]").dataset.keepExpanded ? o.lastElementChild.querySelector("[role=menuitem]").nextElementSibling.lastElementChild.querySelector("[role=menuitem]") : !w && o.previousElementSibling.dataset.keepExpanded && u ? u : s ? n.nextElementSibling.lastElementChild.querySelector("[role=menuitem]") : o.lastElementChild.querySelector("[role=menuitem]");
                for (var p, f, h, b, g, m = i; m.nextElementSibling;)
                    if ("separator" === (m = m.nextElementSibling).getAttribute("role")) {
                        p = !(!m.hasAttribute("aria-orientation") || "vertical" !== m.getAttribute("aria-orientation")), f = m.nextElementSibling.querySelector("[role=menuitem]");
                        break
                    }
                for (m = i; m.previousElementSibling;) {
                    if ("separator" === (m = m.previousElementSibling).getAttribute("role")) {
                        if (b) break;
                        h = !(!m.hasAttribute("aria-orientation") || "vertical" !== m.getAttribute("aria-orientation")), b = m.previousElementSibling
                    }
                    b && (b = m)
                }
                if (b && (b = b.querySelector("[role=menuitem]")), s || n.setAttribute("tabindex", "-1"), "down" === r && d) g = d;
                else if ("up" === r && c) g = c;
                else if (!s && "right" === r && l || "enter" === r && l) g = l;
                else if (p && "right" === r) g = f;
                else if (h && "left" === r) g = b;
                else if (!s && "left" === r || !s && "esc" === r) g = u;
                else if ("tab" === r) return;
                if ("left" !== r && "esc" !== r || (!s && w && "true" === g.getAttribute("aria-expanded") ? g.setAttribute("aria-expanded", "false") : s && a.setAttribute("aria-expanded", "false")), g) {
                    if (w || s) {
                        var v = g.parentElement.parentElement.previousElementSibling;
                        "true" !== v.getAttribute("aria-expanded") && k(v)
                    }
                    g.setAttribute("tabindex", "0"), g.focus(), e.stopImmediatePropagation(), e.preventDefault()
                }
            } else A(document.querySelector(x + " button"), !0)
    }), e.on("ajax-fetched.wb ajax-failed.wb", l, function(e) {
        var t = e.target;
        e.currentTarget === t && u(t)
    }), e.on("timerpoke.wb wb-init.gcweb-v2", x, function(e) {
        var t = n.init(e, s, x);
        t && (c[n.lang] ? c = c[n.lang] : c.en && (c = c.en), t.querySelector(l) || u(t.querySelector("[role=menu]")))
    }), n.add(x)
}(jQuery, wb),
function(p, s, l) {
    "use strict";
    var f, d = "wb-urlmapping",
        r = "[data-" + d + "]",
        n = "domapping." + d,
        i = l.doc,
        h = {
            op: "move",
            path: "{base}",
            from: "{base}/{qval}"
        },
        c = function(e, t, a) {
            var r, n, i, o, s, l, d;
            for (n = (a = p.isArray(a) ? p.extend([], a) : [a]).length, r = 0; r !== n; r += 1)
                if (o = (i = a[r]).action) {
                    if (s = i.match, d = i.default, l = !1, s && !d) throw "'match' and 'default' property need to be set";
                    if (d && t.length && "string" == typeof s) try {
                        l = (l = new RegExp(s).exec(t)) || d
                    } catch (e) {}
                    switch (!i.qval && l && (i.qval = l), o) {
                        case "patch":
                            var c = i.patches,
                                u = i.base || "/";
                            c || (c = [h], i.cumulative = !0), p.isArray(c) || (c = [c]), c = b(c, i.qval, u), i.patches = c;
                            break;
                        case "ajax":
                            i.trigger && e[0] !== f && (i.trigger = !1), i.url = g(i.url, i.qval);
                            break;
                        case "tblfilter":
                            i.value = g(i.value, i.qval)
                    }
                }
            e.trigger({
                type: "do.wb-actionmng",
                actions: a
            })
        },
        b = function(e, t, a) {
            var r, n, i, o = e.length,
                s = [];
            for (a || (a = "/"), r = 0; r !== o; r += 1) n = e[r], i = p.extend({}, n), n.path && (i.path = g(n.path, t, a)), n.from && (i.from = g(n.from, t, a)), n.value && (i.value = g(n.value, t, a)), s.push(i);
            return s
        },
        g = function(e, t, a) {
            return t ? a ? e.replace(/\{qval\}/, t).replace(/\{base\}/, a) : e.replace(/\{qval\}/, t) : e
        };
    i.on(n, r, function(e) {
        var t, a, r, n = p(e.target),
            i = function() {
                for (var e = {}, t = /\+/g, a = /([^&=]+)=?([^&]*)/g, r = function(e) {
                        return decodeURIComponent(e.replace(t, " "))
                    }, n = s.location.search.substring(1), i = a.exec(n); i;) e[r(i[1])] = r(i[2]), i = a.exec(n);
                return e
            }(),
            o = p.extend({}, s[d] || {}, l.getData(n, d));
        for (t in i)
            if ("object" == typeof(r = o[t + "=" + (a = i[t])] || o[t]) && (c(n, a, r), !o.multiplequery)) break
    }), i.on("timerpoke.wb wb-init.wb-urlmapping", r, function(e) {
        var t, a = l.init(e, d, r);
        a && (t = p(a), f || (f = a), l.ready(t, d), l.isReady ? t.trigger(n) : i.one("wb-ready.wb", function() {
            t.trigger(n)
        }))
    }), l.add(r)
}(jQuery, window, wb),
function(a, e, o) {
    "use strict";
    var t = o.doc,
        r = "#wb-srch-q",
        s = a(r),
        l = a("#" + s.attr("list")),
        n = function(e) {
            0 < e.length && a(this).trigger({
                type: "ajax-fetch.wb",
                fetch: {
                    url: o.pageUrlParts.protocol + "//clients1.google.com/complete/search?client=partner&sugexp=gsnos%2Cn%3D13&gs_rn=25&gs_ri=partner&partnerid=" + window.encodeURIComponent("008724028898028201144:knjjdikrhq0+lang:" + o.lang) + "&types=t&ds=cse&cp=3&gs_id=b&hl=" + o.lang + "&q=" + encodeURI(e),
                    dataType: "jsonp",
                    jsonp: "callback"
                }
            })
        };
    t.on("change keyup", r, function(e) {
        var t = e.target,
            a = e.target.value,
            r = e.which;
        switch (e.type) {
            case "change":
                n.call(t, a);
                break;
            case "keyup":
                e.ctrlKey || e.altKey || e.metaKey || (32 === r || 47 < r && r < 91 || 95 < r && r < 112 || 159 < r && r < 177 || 187 < r && r < 223) && n.call(t, a)
        }
    }), t.on("ajax-fetched.wb", r, function(e) {
        var t, a, r = e.fetch.response[1],
            n = r.length,
            i = "";
        for (l.empty(), t = 0; t < n; t += 1) i += '<option label="' + (a = r[t])[0] + '" value="' + a[0] + '"></option>';
        o.ielt10 && (i = "<select>" + i + "</select>"), l.append(i), s.trigger("wb-update.wb-datalist")
    }), window["wb-data-ajax"] = {
        corsFallback: function(e) {
            return e.url = e.url.replace(".html", ".htmlp"), e
        }
    }, a("[data-reveal]").change(function() {
        var e = a(this),
            t = e.attr("data-reveal");
        return e.is(":checked") ? a(t).removeClass("hide") : a(t).addClass("hide")
    })
}(jQuery, document, wb),
function(b, u, l) {
    "use strict";

    function o(e) {
        if ("click" === e.type) return !0;
        if ("keypress" !== e.type) return !1;
        var t = e.charCode || e.keyCode;
        return 32 === t || 13 === t || void 0
    }
    var t, d = (t = new RegExp("{{\\s*([a-z0-9_$][\\.a-z0-9_]*)\\s*}}", "gi"), function(e, d, c) {
        return e.replace(t, function(e, t) {
            for (var a, r, n, i = t.split("."), o = i.length, s = d, l = 0; l < o; l += 1) {
                if (void 0 === (s = s[i[l]])) throw "tim: '" + i[l] + "' not found in " + e;
                if (l === o - 1) return b.isNumeric(s) && c ? (a = s, r = c, n = Math.pow(10, r || 0), Math.round(a * n) / n).toLocaleString(u.documentElement.lang) : b.isNumeric(s) ? s.toLocaleString(u.documentElement.lang) : s
            }
        })
    });

    function s(e, r, t, n) {
        var a = b('[data-wbtbl-search$="@' + t + "@" + n + '"],[data-wbtbl-highlight$="@' + t + "@" + n + '"]');
        r ? a.removeClass("pick") : a.addClass("pick"), b('form[data-wb5-bind="#' + e.table().node().id + '"]').find('[value^="' + t + "@" + n + '"],[data-wbtbl-bind^="' + t + "@" + n + '"]').each(function(e, t) {
            var a = b(t);
            return a.is("[type=checkbox],[type=radio]") ? a.prop("checked", r) : a.is("[type=text],[type=textarea]") ? a.val(r ? n : "") : a.get(0).selected = r, !0
        })
    }
    b.fn.extend({
        relatives: function() {
            var a = b();
            return this.each(function(e, t) {
                t.wb5 && t.wb5.relatives && t.wb5.relatives.each(function() {
                    a = a.add(this)
                })
            }), a
        },
        related: function(a, r) {
            return this.each(function(e, t) {
                r && t.wb5 && t.wb5.relatives && t.wb5.relatives.each(function() {
                    a = a.add(this)
                }), b.extend(t, {
                    wb5: {
                        relatives: a
                    }
                })
            }), this
        }
    }), b.fn.extend({
        shuffle: function() {
            var a = this.get(),
                t = b.map(a, function() {
                    var e = Math.floor(Math.random() * a.length),
                        t = b(a[e]).clone(!0)[0];
                    return a.splice(e, 1), t
                });
            return this.each(function(e) {
                b(this).replaceWith(b(t[e]))
            }), b(t)
        }
    }), b.fn.extend({
        rand: function(e) {
            var t = this,
                a = t.size();
            if (a < (e = e ? parseInt(e) : 1)) return t.pushStack(t);
            if (1 == e) return t.filter(":eq(" + Math.floor(Math.random() * a) + ")");
            r = t.get();
            for (var n = 0; n < a - 1; n++) {
                var i = Math.floor(Math.random() * (a - n)) + n;
                r[i] = r.splice(n, 1, r[i])[0]
            }
            return r = r.slice(0, e), t.filter(function(e) {
                return -1 < b.inArray(t.get(e), r)
            })
        }
    }), b.fn.extend({
        notEmpty: function() {
            return 0 !== this.length
        }
    }), b.fn.extend({
        command: function(e) {
            if (e.length) {
                var t = e.split("@");
                return {
                    command: t[0],
                    selector: t[1],
                    options: t[2]
                }
            }
            return {
                command: !1,
                selector: !1
            }
        }
    }), b("[data-wb5-bind]").each(function(e, t) {
        var a, r = b(t);
        r.parents().is("template") || (a = b(r.attr("data-wb5-bind"))).notEmpty() && r.related(a)
    }), b(u).on("keypress click", "[data-wb5-debug]", function(e) {
        if (!o(e)) return !0;
        for (var t = b(this), a = t.attr("data-wb5-debug").split(","), r = a.length - 1; 0 <= r; r--) console.log(t[a[r]]())
    }), b(u).on("draw.dt", ".wb-tables", function(e) {
        var t = b(this),
            a = t.DataTable();
        t.relatives().trigger({
            type: e.type,
            table: a,
            displayed: a.page.info().recordsDisplay,
            total: a.page.info().recordsTotal
        })
    }), Modernizr.details || b(u).on("draw.dt", ".wb-tables", function(e) {
        b(this).find("summary").removeClass("wb-init").removeClass("wb-details-inited").trigger("wb-init.wb-details")
    }), b(u).on("draw.dt", "[data-wbtbl-draw]", function(e) {
        var t, a, r = b(this),
            n = r.command(r.attr("data-wbtbl-draw")),
            i = e.table,
            o = b(i.table().node()),
            s = e.displayed !== e.total,
            l = 0,
            d = e.total;
        e.displayed;
        switch (n.command) {
            case "display":
                return t = r, a = i.page.info()[n.options], t.is(":input") ? t.val(a) : t.text(a), !0;
            case "count":
                if ((s ? i.rows({
                        search: "applied"
                    }) : i.rows({
                        page: "all"
                    })).iterator("row", function(e, t) {
                        -1 < b(this.row(t).node()).text().indexOf(n.options) && l++
                    }), r.is("progress")) {
                    if (r.attr({
                            max: d,
                            value: l
                        }), o.hasClass("wbtbl-silent")) return !0;
                    r.trigger("updated.wb5")
                }
                return r.text(l)
        }
    }), b("[data-wbtbl-reset]").on("click", function(e) {
        var t = this.getAttribute("data-wbtbl-reset").split("@"),
            a = b(t[0]).DataTable();
        return a.search("").columns().search(""), "all" === t[1] ? a.search("").columns().search("").draw() : a.column(t[1]).search("").draw()
    }), b(u).on("wb-ready.wb-tables", "[data-wbtbl-tag=enable]", function() {
        var e = b(this),
            t = e.closest(".dataTables_wrapper");
        t.addClass("tagcloud").find(".top").append('<div data-wbtbl-tagcloud="active" aria-live="polite"></div>'), e.related(t.find("[data-wbtbl-tagcloud]").eq(0), !0), t.find("[data-wbtbl-tagcloud]").eq(0).trigger({
            type: "draw.dt",
            table: e.eq(0).dataTable().api()
        })
    }), b(u).on("draw.dt", "[data-wbtbl-tagcloud]", function(e) {
        var t = e.table,
            r = -1,
            n = b(this),
            a = function() {
                var e = this.search();
                if (e) {
                    var t = e.split("|"),
                        a = '<li><span class="tagitem" data-wbtbl-col-idx="' + r + '"><span class="content">' + t.map(function(e) {
                            return e.replace(/[{()}]/g, "")
                        }).join(" &amp; ") + '</span> <button type="button" class="close" tabindex="0" aria-label="' + l.i18n("geo-aoi-btnclear") + '"><span aria-hidden="true">&times;</span></button></span></li>';
                    n.find("ul").append(a)
                }
                r++
            };
        n.html('<ul class="list-inline tags" aria-live="polite"></ul><div class="clearfix"></div>'), a.call(t), t.columns().every(a)
    }), b(u).on("updated.wb5", "[data-wb5-update]", function(e) {
        var t = b(this).relatives(),
            a = this.getAttribute("max"),
            r = this.getAttribute("value"),
            n = (this.getAttribute("data-percentage"), Math.ceil(r / a * 100) || 0);
        t.find(".meter").text(r), t.removeClass(function(e, t) {
            return (t.match(/(^|\s)p\d+/g) || []).join(" ")
        }).attr("data-percentage", "p" + n), t.addClass("p" + n)
    }), b(u).on("keypress click", "[data-wbtbl-highlight]", function(e) {
        if (!o(e)) return !0;
        var t = b(this),
            a = t.command(this.getAttribute("data-wbtbl-highlight")),
            r = t.relatives().DataTable();
        t.relatives().removeClass("wbtbl-silent").addClass("wbtbl-silent"), r.column(a.selector).search(a.options, !1, !1, !0).draw()
    }), b(u).on("keypress click", "[data-wbtbl-search]", function(e) {
        if (!o(e)) return !0;
        var t = b(this),
            a = t.command(this.getAttribute("data-wbtbl-search")),
            r = t.relatives().DataTable();
        t.relatives().removeClass("wbtbl-silent"), r.search("").columns().search(""), r.column(a.selector).search(a.options, !1, !1, !0).draw()
    }), b(u).on("submit", "[data-wbtbl-submit]", function(e) {
        var t = b(this),
            a = t.command(this.getAttribute("data-wbtbl-submit")),
            r = t.relatives().DataTable(),
            n = a.selector;
        return t.relatives(), r.search("").columns().search(""), n && (r = r.column(n)), r.search(t.find("input").val(), !1, !1, !0).draw(), !1
    }), b(u).on("keypress click", "[data-wb5-ajax]", function(e) {
        if (!o(e)) return !0;
        var t = b(this),
            a = t.command(this.getAttribute("data-wb5-ajax")),
            r = t.relatives();
        switch (r.attr("aria-live", "polite"), a.command) {
            case "replace":
                b.get(a.options, function(e) {
                    r.html(e)
                })
        }
    }), b(u).on("keypress click", "[data-wb5-load]", function(e) {
        if (!o(e)) return !0;
        var t = b(this),
            a = t.command(this.getAttribute("data-wb5-load")),
            r = t.relatives();
        switch (r.attr({
            "aria-relevant": "all",
            "aria-live": "polite",
            "aria-atomic": "true"
        }), a.command) {
            case "replace":
                r.load(a.options)
        }
    }), b(u).on("keypress click", "[data-wb5-trigger]", function(e) {
        if (!o(e)) return !0;
        var t = b(this),
            a = t.command(this.getAttribute("data-wb5-trigger"));
        t.relatives().trigger(a.command)
    }), b(u).on("keypress click", "[data-wb5-profile]", function(e) {
        if (!o(e)) return !0;
        var t = b(this),
            a = t.command(this.getAttribute("data-wb5-profile"));
        "single" === a.command && (t.relatives().removeClass(a.options).filter("[role=button]").attr("aria-pressed", "false"), b(e.target).closest(t.relatives()).addClass(a.options).filter("[role=button]").attr("aria-pressed", "true"))
    }), b(u).on("keypress click", "[data-wbtbl-tagcloud] li button", function(e) {
        if (!o(e)) return !0;
        var t = b(this),
            a = t.closest("li"),
            r = a.find(".content").text(),
            n = parseInt(t.closest("[data-wbtbl-col-idx]").attr("data-wbtbl-col-idx")),
            i = t.closest(".dataTables_wrapper").find(".wb-tables").removeClass("wbtbl-silent").DataTable(); - 1 !== n && (i = i.column(n)), i.search("", !1, !1, !0).draw(), a.remove(), s(i, !1, n, r)
    }), b(u).on("refreshCtrl.wbtbl", "table", function(e) {
        var t, a, r, n;
        t = b(e.currentTarget).DataTable(), a = void 0 === e.isSelected || e.isSelected, r && n ? s(t, a, r, n) : t.columns().every(function(e) {
            n = t.column(e).search(), s(t, a && n, e, n)
        })
    }), b(u).on("submit", "[data-wbtbl-post]", function(e) {
        var t = b(this),
            a = !!t.is("[action]"),
            r = [],
            n = t.relatives().DataTable(),
            i = t.command(this.getAttribute("data-wbtbl-post")),
            o = [];
        if (t.find(i.selector).each(function(e, t) {
                var a = b(t);
                if (a.is("[type=checkbox]")) {
                    if (a.is(":checked")) {
                        if (a.is("[data-xor]")) return o.push(a.val()), !0;
                        r.push(a.val())
                    }
                    return !0
                }
                r.push(a.val())
            }), 1 < o.length) {
            for (var s = {}, l = !1, d = o.length - 1; 0 <= d; d--) {
                var c = o[d].split("@");
                s.hasOwnProperty(c[0]) || (s[c[0]] = []), s[c[0]].push("(" + c[1] + ")")
            }
            for (var l in s) r.push(l + "@" + s[l].join("|"))
        } else 1 === o.length && r.push(o[0]);
        for (var u = r.length - 1; 0 <= u; u--) {
            var p = r[u].split("@"),
                f = p[0],
                h = p[1]; - 1 === h.indexOf("|") ? (h = h.replace(/^\(/, "").replace(/\)$/, ""), n.column(f).search(h)) : n.column(f).search(h, !0)
        }
        return n.draw(), a
    }), b(u).on("reset", "[data-wbtbl-post]", function(e) {
        var n = this,
            t = b(n).relatives().DataTable();
        t.search(""), t.columns().every(function() {
            this.search("")
        }), t.draw(), setTimeout(function() {
            var e, t, a = n.querySelectorAll("[data-wb5-default-checked]"),
                r = a.length;
            for (e = 0; e < r; e++)(t = a[e]).checked = "false" !== t.dataset.wb5DefaultChecked
        }, 1)
    }), b("[data-wb5-click]").on("click", function() {
        var e = b(this).data("wb5-click").split("@"),
            t = e[0],
            a = (e[1], e[2]);
        if ("postback" === t) {
            var r = b(e[1]);
            return b.ajax({
                type: r.attr("method"),
                url: r.attr("action"),
                data: r.serialize()
            }), !a.block
        }
    }), b("[data-wb5-randomize]").each(function() {
        var e, t = b(this),
            a = t.data("wb5-randomize").split("@"),
            r = a[0],
            n = a[1],
            i = 2 < a.length ? JSON.parse(a[2]) : {};
        return "self!" === n.substring(0, 5) && (n = n.substr(5), e = t), "shuffle" === r && b(n, e).shuffle(), "toggle" === r && b(n, e).rand(i.number).toggleClass(i.classes), !0
    }), b(u).on("wb-ready.wb-charts", "[data-wb-charts-interactive]", function() {
        var e = b(this),
            t = e.command(this.getAttribute("data-wb-charts-interactive")),
            i = l.getId().replace(/-/g, ""),
            o = b(t.selector).html(),
            s = t.options ? t.options : 1,
            a = e.prev();
        b("<div id='" + i + "' class='wbchrt-tpl'></div>").css({
            position: "absolute",
            display: "none"
        }).appendTo("body"), b("canvas:eq(1)", a).css("position", "relative"), a.on("plothover", function(e, t, a) {
            if (a) {
                var r = b("#" + i),
                    n = {
                        x: a.datapoint[0],
                        y: a.datapoint[1],
                        label: a.series.label,
                        formatted: {}
                    };
                r.html(d(o, n, s)), r.css({
                    top: a.pageY + 7,
                    left: a.pageX + 7
                }).show()
            } else b("#" + i).hide()
        })
    })
}(jQuery, document, wb),
function(x, k, A) {
    "use strict";
    var j, o = A.doc,
        s = "wb-suggest",
        l = "[data-" + s + "]",
        C = 5,
        E = function(e) {
            return e.normalize("NFD").replace(/[\u0300-\u036f]/g, "")
        },
        S = function(e, t, a) {
            var r, n, i, o, s, l, d, c, u, p = a || JSON.parse(this.dataset.wbSuggestions || []),
                f = this.dataset.wbFilterType || "any",
                h = p.length,
                b = [],
                g = this.childNodes,
                m = g.length - 1,
                v = x("[list=" + this.id + "]"),
                w = v.get(0);
            if (!p.length && C && (C -= 1, j && clearTimeout(j), j = setTimeout(S(e, t, a), 250)), t || (t = parseInt(this.dataset.wbLimit || h)), e) {
                switch (f) {
                    case "startWith":
                        e = "^" + e;
                        break;
                    case "word":
                        e = "^" + e + "|\\s" + e
                }
                r = new RegExp(e, "i")
            }
            if (!e || e.length < 2)(function() {
                var e, t, a = this.children;
                for (t = a.length - 1; 0 < t; t -= 1) 1 === (e = a[t]).nodeType && "TEMPLATE" !== e.nodeName && this.removeChild(e)
            }).call(this), g = [];
            else
                for (d = m; 0 !== d; d -= 1) 1 === (c = g[d]).nodeType && "OPTION" === c.nodeName && ((u = c.getAttribute("value")) && u.match(r) ? b.push(E(u)) : this.removeChild(c));
            var y = this.querySelector("template");
            for (y && !y.content && A.tmplPolyfill(y), n = 0; n < h && b.length < t; n += 1) i = p[n], o = E(i), -1 !== b.indexOf(o) || e && !i.match(r) || (b.push(o), y ? l = (s = y.content.cloneNode(!0)).querySelector("option") : (s = k.createDocumentFragment(), l = k.createElement("OPTION"), s.appendChild(l)), l.setAttribute("label", i), l.setAttribute("value", i), this.appendChild(s));
            v.trigger("wb-update.wb-datalist"), w.value = w.value
        },
        d = function(e) {
            var t = e.target,
                a = k.getElementById(t.getAttribute("list"));
            Modernizr.load({
                test: Modernizr.stringnormalize,
                nope: ["site!deps/unorm" + A.getMode() + ".js"]
            }), x(a).trigger({
                type: "json-fetch.wb",
                fetch: {
                    url: a.dataset.wbSuggest
                }
            })
        },
        c = function(e) {
            var t = e.target,
                a = k.getElementById(t.getAttribute("list")),
                r = e.target.value,
                n = e.which;
            switch (j && clearTimeout(j), e.type) {
                case "change":
                    j = setTimeout(S.bind(a, r), 250);
                    break;
                case "keyup":
                    e.ctrlKey || e.altKey || e.metaKey || (8 === n || 32 === n || 47 < n && n < 91 || 95 < n && n < 112 || 159 < n && n < 177 || 187 < n && n < 223) && (j = setTimeout(S.bind(a, r), 250))
            }
        };
    o.on("timerpoke.wb wb-init.wb-suggest json-fetched.wb", l, function(e) {
        var t, a, r, n = e.type,
            i = e.target;
        if (e.currentTarget === i) switch (n) {
            case "timerpoke":
            case "wb-init":
                t = e, a = A.init(t, s, l), r = "[list=" + t.target.id + "]", a && (Modernizr.addTest("stringnormalize", "normalize" in String), o.one("focus", r, d), (a.dataset.wbLimit || a.dataset.wbFilterType) && o.on("change keyup", r, c), A.ready(x(a), s));
                break;
            case "json-fetched":
                (function(e) {
                    this.dataset.wbSuggestions = JSON.stringify(e), delete this.dataset.wbSuggest, S.call(this, k.querySelector("[list=" + this.id + "]").value)
                }).call(i, e.fetch.response)
        }
        return !0
    }), A.add(l)
}(jQuery, document, wb),
function(I, g, m, T) {
    "use strict";
    var v, d, c, w = "wb-combobox",
        y = "." + w,
        e = T.doc,
        x = {
            template: '<div class="combobox-wrapper"><div role="combobox" aria-expanded="false" aria-haspopup="listbox" data-wb5-bind="aria-owns@popupId"><input autocomplete="off" data-rule-fromListbox="true" data-wb5-bind="id@fieldId, aria-controls@popupId, value@filter" aria-autocomplete="list" aria-activedescendant="" /></div><div data-wb5-bind="id@popupId" role="listbox" class="hidden"><template data-slot-elm="" data-wb5-template="sub-template-listbox"><ul class="list-unstyled mrgn-bttm-0">\x3c!-- <li class="brdr-bttm" role="option" data-wb5-for="option in wbLoad" data-wb5-if="!parent.filter.length || parent.config.compareLowerCase(option,parent.filter)" data-wb5-on="select@select(option); live@parent.nbdispItem(wb-nbNode)" >{{ option }}</li> --\x3e<li class="" role="option" data-wb5-for="option in options" data-wb5-if="!parent.filter.length || parent.config.compareLowerCase(option.value,parent.filter)" data-wb5-on="select@select(option.value); live@parent.nbdispItem(wb-nbNode)" >{{ option.textContent }}</li></ul></template></div></div>',
            i18n: {
                en: {
                    errValid: "You need to choose a valid options."
                },
                fr: {
                    errValid: "Veuillez choisir une option valide."
                }
            },
            compareLowerCase: function(e, t) {
                return -1 !== e.toLowerCase().indexOf(t.toLowerCase())
            },
            similarText: function(e, t, a) {
                function h(e, t) {
                    for (var a = [], r = 0; r <= e.length; r++) {
                        for (var n = r, i = 0; i <= t.length; i++)
                            if (0 === r) a[i] = i;
                            else if (0 < i) {
                            var o = a[i - 1];
                            e.charAt(r - 1) !== t.charAt(i - 1) && (o = Math.min(Math.min(o, n), a[i]) + 1), a[i - 1] = n, n = o
                        }
                        0 < r && (a[t.length] = n)
                    }
                    return a[t.length]
                }
                var r = function(e, t) {
                    e = e.replace(/[\-\/]|_/g, " ").replace(/[^\w\s]|_/g, "").trim().toLowerCase(), t = t.replace(/[\-\/]|_/g, " ").replace(/[^\w\s]|_/g, "").trim().toLowerCase();
                    var a = e.split(" "),
                        r = t.split(" ");
                    if (e.length > t.length && (a = t.split(" "), r = e.split(" ")), !r.length || !a.length) return 100;
                    for (var n = 0, i = 0, o = "", s = "", l = 0; l < a.length; l++) {
                        for (var d = 0, c = 0, u = !1, p = 0; p < r.length; p++)
                            if (s = a[l], 0 <= (o = r[p]).indexOf(s)) {
                                var f = o.length;
                                (!u || f < d) && (d = o.length, c = o.length), u = !0
                            } else u || d < (f = o.length - h(s, o)) && (d = f, c = o.length);
                        n += d, i += c
                    }
                    return 0 === n ? 0 : n / i * 100
                }(e, t);
                return (a = parseInt(a)) <= r
            }
        },
        u = 9,
        p = 13,
        f = 27,
        h = 35,
        b = 36,
        k = 38,
        A = 40,
        j = {},
        C = m.createDocumentFragment(),
        q = [],
        N = function(t, a, e) {
            var r, n = t.childNodes,
                i = n.length,
                o = [];
            for (m = 0; m < i; m++) {
                if (3 === (r = n[m]).nodeType && -1 != r.textContent.indexOf("{{")) {
                    r.textContent = r.textContent.replace(/{{\s?([^}]*)\s?}}/g, function(e, t) {
                        return B(a.data, t.trim())
                    })
                }
                if ("TEMPLATE" !== r.nodeName) {
                    if (1 === r.nodeType)
                        if (r.hasAttribute("data-wb5-for")) {
                            var s = z(r, "data-wb5-for"),
                                l = M(s),
                                d = B(a.data, l.for);
                            if (!d) throw "Iterator not found";
                            var c = d.length,
                                u = 0;
                            for (d.wbLen = parseInt(c), I.isArray(d) && (d.active = u), m = 0; m < c; m++) {
                                var p = r.cloneNode(!0),
                                    f = L(p),
                                    h = {
                                        "wb-idx": m,
                                        "wb-nbNode": u,
                                        parent: a.data
                                    };
                                h[l.alias] = d[m], h = F(h), e && (a.data[e] = h), f.if && !D(f.if, h.data, a.data) || (u += 1, N(p, h, e), t.appendChild(p))
                            }
                            d.wbActive = u, o.push(r)
                        } else r.hasAttribute("data-wb5-if") || r.hasAttribute("data-wb5-else") || r.hasAttribute("data-wb5-ifelse"), N(r, a, e)
                } else {
                    R(r);
                    var b = z(r, "data-wb5-template");
                    b || (b = T.getId()), r.parentNode.hasAttribute("data-wb5-template") || r.parentNode.setAttribute("data-wb5-template", b), a.tmplDefault(b, r)
                }
            }
            for (i = o.length, m = 0; m !== i; m += 1) t.removeChild(o[m]);
            if (1 === t.nodeType && t.hasAttribute("data-wb5-bind"))
                for (var g = z(t, "data-wb5-bind").split(", "), m = 0; m < g.length; m++) {
                    var v = g[m].split("@");
                    t[v[0]] ? (t[v[0]] = B(a.data, v[1]), a.observe(v[1], function(e) {
                        return t[v[0]] = B(a.data, v[1]) || ""
                    })) : (t.setAttribute(v[0], B(a.data, v[1])), a.observe(v[1], function(e) {
                        return void 0 !== t[v[0]] ? t[v[0]] = B(a.data, v[1]) || "" : t.setAttribute(v[0], B(a.data, v[1])) || ""
                    }))
                }
            if (1 === t.nodeType && t.hasAttribute("data-wb5-text")) {
                var w = z(t, "data-wb5-text");
                t.textContent = B(a.data, w), a.observe(w, function(e) {
                    return t.textContent = B(a.data, w) || ""
                })
            }
            if (1 === t.nodeType && t.hasAttribute("data-wb5-on")) {
                var y = z(t, "data-wb5-on").split("; ");
                i = y.length;
                for (m = 0; m < i; m++) {
                    var x, k, A = y[m].split("@"),
                        j = A[0],
                        C = A[1],
                        E = C.indexOf("("),
                        S = C.lastIndexOf(")");
                    if (E && S && (x = C.substring(0, E).trim(), k = C.substring(E + 1, S).trim()), !x) throw "Error, an event handler need to call a function";
                    k && (k = O(k, a.data)), "live" === j ? B(a.data, x).call(a.data, k) : q.push({
                        nd: t,
                        evt: j,
                        trigger: x,
                        attr: k
                    })
                }
            }
        },
        z = function(e, t) {
            var a = e.getAttribute(t);
            return e.removeAttribute(t), a
        },
        D = function(e, t, a) {
            return !!O(e, t, a)
        },
        O = function(e, n, i) {
            var o = /{{-\s?([^}]*)\s?-}}/g,
                s = [];
            return e = (e = (e = e.replace(/"([^"\\]*(\\.[^"\\]*)*)"|\'([^\'\\]*(\\.[^\'\\]*)*)\'/g, function(e, t) {
                var a = "{{-" + s.length + "-}}";
                return s.push(e), a
            })).replace(/[a-zA-Z]([^\s]+)/g, function(e, t) {
                var a, r = e.trim();
                r = r.replace(o, function(e, t) {
                    return s[t]
                });
                try {
                    a = B(n, r)
                } catch (e) {
                    try {
                        a = B(i, r)
                    } catch (e) {
                        throw "Information in the DATA obj not found"
                    }
                }
                return "object" == typeof a && (a = JSON.stringify(a)), "string" == typeof a ? '"' + a + '"' : a
            })).replace(o, function(e, t) {
                return s[t]
            }), new Function("return " + e)()
        },
        L = function(e) {
            var t = {},
                a = z(e, "data-wb5-if");
            if (a) t.if = a, n(t, {
                exp: a,
                block: e
            });
            else {
                null != z(e, "data-wb5-else") && (t.else = !0);
                var r = z(e, "data-wb5-elseif");
                r && (t.elseif = r)
            }
            return t
        },
        n = function(e, t) {
            e.ifConditions || (e.ifConditions = []), e.ifConditions.push(t)
        },
        E = function(e, t) {
            var a, r, n = e.options,
                i = n.length;
            for (a = 0; a < i; a++) r = n[a], t.data.options.push({
                value: r.value,
                textContent: r.textContent
            });
            t.data.fieldId = e.id || T.getId(), t.data.fieldName = e.name, t.data.mustExist = !0
        },
        S = function(e, t) {
            var a, r = node.childNodes,
                n = r.length;
            for (a = 0; a < n; a++) r[a]
        },
        M = function(e) {
            var t = /,([^,\}\]]*)(?:,([^,\}\]]*))?$/,
                a = e.match(/([^]*?)\s+(?:in|of)\s+([^]*)/);
            if (a) {
                var r = {};
                r.for = a[2].trim();
                var n = a[1].trim().replace(/^\(|\)$/g, ""),
                    i = n.match(t);
                return i ? (r.alias = n.replace(t, ""), r.iterator1 = i[1].trim(), i[2] && (r.iterator2 = i[2].trim())) : r.alias = n, r
            }
        },
        B = function(e, t) {
            var a = (t = t.trim()).substring(0, 1),
                r = t.substring(-1);
            if ("'" === a || '"' === a || "'" === r || '"' === r) return t.substring(1, t.length - 1);
            var n = t.indexOf("("),
                i = t.lastIndexOf(")"),
                o = [];
            if (-1 !== n && -1 !== i && n + 1 !== i) {
                var s, l, d, c = t.substring(0, n);
                for (d = (o = t.substring(n + 1, i).split(",")).length, s = 0; s < d; s += 1) {
                    l = o[s];
                    var u = B(e, l);
                    o[s] = u
                }
                t = c + "()"
            }
            var p, f, h, b = t.split("."),
                g = b.length;
            for (p = 0; p < g; p += 1) {
                if (f = b[p], !e) return;
                e = -1 !== f.lastIndexOf("()") ? (h = f.substring(0, f.length - 2), "string" == typeof e ? String.prototype[h].apply(e, o) : e[h].apply(e, o)) : e[f]
            }
            return e
        },
        R = function(e) {
            if (!e.content) {
                var t, a, r = e;
                for (t = r.childNodes, a = m.createDocumentFragment(); t[0];) a.appendChild(t[0]);
                r.content = a
            }
        },
        U = function(e, t) {
            for (var a = m.getElementById(e.getAttribute("aria-controls")), r = I(e).parent(), n = I(e); !n.hasClass("wb5React");) n = n.parent();
            var i, o, s = j[n.get(0).id],
                l = a.getAttribute("data-wb5-template");
            if (l && (i = s.template(l) || m.getElementById(l) || s.tmplDefault(l)), !i || !l) throw "No template defined to show listbox options";
            s.template(l, i), R(i), o = i.content.cloneNode(!0), s.data.filter = e.value, q = [], N(o, s, l), o.querySelectorAll("[role=option]").length ? (a.innerHTML = "", a.appendChild(o), I(a).removeClass("hidden"), d = r.get(0)) : d && P()
        },
        P = function() {
            if (d) {
                var e = d.getAttribute("aria-owns");
                I("#" + e).addClass("hidden"), d = null
            }
        },
        r = function(e) {
            if (l(e), document.activeElement !== e) {
                for (var t = I(e).parent(), a = I(e); !a.hasClass("wb5React");) a = a.parent();
                for (var r = j[a.get(0).id], n = e.value, i = {}, o = r.data.options, s = 0; s < o.length; s++)
                    if (n === o[s].value) {
                        i = o[s];
                        break
                    }
                t.trigger("wb.change", {
                    value: e.value,
                    item: i
                })
            }
        },
        l = function(e) {
            var t = e.form && e.form.parentNode.classList.contains("wb-frmvld");
            if (null === e.getAttribute("required") && "" === e.value || null === e.getAttribute("data-rule-mustExist")) return e.setCustomValidity(""), t && I(e).valid(), !0;
            for (var a = I(e); !a.hasClass("wb5React");) a = a.parent();
            var r, n, i = j[a.get(0).id],
                o = e.getAttribute("aria-controls"),
                s = (m.getElementById(o), i.data.options),
                l = e.value,
                d = s.length;
            for (r = 0; r < d; r += 1)
                if (l === s[r].value) {
                    n = !0;
                    break
                }
            return n ? (e.setCustomValidity(""), t && I(e).valid(), !0) : (e.setCustomValidity(v.errValid), t && I(e).valid(), !1)
        };

    function F(e) {
        var a = {},
            r = {},
            n = {};
        return function(e) {
            for (var t in e) e.hasOwnProperty(t) && o(e, t)
        }(e), {
            data: e,
            observe: t,
            notify: i,
            template: function(e, t) {
                {
                    if (!t) return r[e] || !1;
                    r[e] = t
                }
            },
            tmplDefault: function(e, t) {
                {
                    if (!t) return n[e] || !1;
                    n[e] = t
                }
            },
            debug_signals: a
        };

        function t(e, t) {
            a[e] || (a[e] = []), a[e].push(t)
        }

        function i(e) {
            !a[e] || a[e].length < 1 || a[e].forEach(function(e) {
                return e()
            })
        }

        function o(e, t, a) {
            var r = e[t];
            if (Array.isArray(r)) return r.wbLen = parseInt(r.length), r.wbActive = 0, o(r, "wbLen", t), void o(r, "wbActive", t);
            Object.defineProperty(e, t, {
                get: function() {
                    return r
                },
                set: function(e) {
                    r = e, i(a ? a + "." + t : t)
                }
            })
        }
    }
    e.on("wb-ready.wb", function(e) {
        I.validator && I.validator.addMethod("fromListbox", function(e, t) {
            return t.checkValidity()
        }, "You need to choose a valid options")
    }), e.on("json-fetched.wb", "[role=combobox]", function(e) {
        for (var t = e.target, a = e.fetch.response, r = I(t); !r.hasClass("wb5React");) r = r.parent();
        j[r.get(0).id].data.wbLoad = a
    }), e.on("click vclick touchstart focusin", "body", function(e) {
        d && !d.parentElement.contains(e.target) && setTimeout(function() {
            P()
        }, 1)
    }), e.on("focus", "[role=combobox] input", function(e, t) {
        d || setTimeout(function() {
            U(e.target)
        }, 1)
    }), e.on("blur", "[role=combobox] input", function(e, t) {
        r(e.target)
    }), e.on("keyup", "[role=combobox] input", function(e) {
        var t = e.which || e.keyCode,
            a = e.target.classList.contains("error");
        switch (t) {
            case k:
            case A:
            case f:
            case p:
            case b:
            case h:
                e.preventDefault();
            case u:
                return void(a && setTimeout(function() {
                    r(e.target)
                }, 100));
            default:
                setTimeout(function() {
                    U(e.target), a && r(e.target)
                }, 100)
        }
    }), e.on("keydown", "[role=combobox] input", function(e) {
        var t = e.which || e.keyCode,
            a = e.target;
        if (t !== f) {
            var r;
            d || U(a);
            var n = a.getAttribute("aria-activedescendant"),
                i = n ? m.getElementById(n) : null,
                o = m.getElementById(a.getAttribute("aria-controls")).querySelectorAll("[role=option]"),
                s = o.length,
                l = -1;
            if (i) {
                for (l = 0; l < s && o[l].id !== i.id; l++);
                s <= l && (l = -1)
            }
            switch (t) {
                case k:
                    -1 === l ? l = s - 1 : 0 !== l ? l-- : l = s - 1;
                    break;
                case A:
                    -1 === l ? l = 0 : l < s && l++;
                    break;
                case b:
                    l = 0;
                    break;
                case h:
                    l = s - 1;
                    break;
                case p:
                    return I(o[l]).trigger("wb.select"), P(), void e.preventDefault();
                case u:
                    return c && I(o[l]).trigger("wb.select"), void P();
                default:
                    return
            }
            e.preventDefault(), r = o[l], i && i.setAttribute("aria-selected", "false"), r ? (r.id || (r.id = T.getId()), a.setAttribute("aria-activedescendant", r.id), r.setAttribute("aria-selected", "true"), c = !0) : a.setAttribute("aria-activedescendant", "")
        } else P()
    }), e.on("mouseover", "[role=listbox] [role=option]", function(e, t) {
        var a = d.querySelector("input"),
            r = e.target,
            n = a.getAttribute("aria-activedescendant"),
            i = n ? m.getElementById(n) : null;
        i && i.setAttribute("aria-selected", "false"), r.id || (r.id = T.getId()), i && i.id !== r.id && (c = !1), r.setAttribute("aria-selected", "true"), a.setAttribute("aria-activedescendant", r.id)
    }), e.on("click", "[role=listbox] [role=option]", function(e, t) {
        var a = I(d.querySelector("input"));
        I(e.target).trigger("mouseover").trigger("wb.select"), a.trigger("focus"), P()
    }), e.on("wb.select", "[role=listbox] [role=option]", function(e, t) {
        for (var a = e.target, r = m.querySelector("[aria-activedescendant=" + a.id + "]"), n = I(r); !n.hasClass("wb5React");) n = n.parent();
        var i, o, s = j[n.get(0).id];
        for (i = 0; i < q.length; i++)
            if ((o = q[i]).nd.isEqualNode(a)) {
                s.data[o.trigger].call(s.data, o.attr);
                break
            }
    }), e.on("timerpoke.wb wb-init.wb-combobox", y, function(e, t) {
        var a, r, n, i, o, s = T.init(e, w, y);
        if (s) {
            a = I(s), r = I.extend(!0, {}, x, g[w], T.getData(a, w)), v || (v = r.i18n[T.lang]);
            var l = F(t || (o = r, {
                popupId: T.getId(),
                fieldId: !1,
                fieldName: "",
                mustExist: !1,
                filter: "",
                cntdisplayeditem: 0,
                options: [],
                config: o,
                i18n: {},
                horay: "testMe",
                select: function(e) {
                    this.filter = e
                },
                nbdispItem: function(e) {
                    this.cntdisplayeditem = e
                }
            }));
            s.id || (s.id = T.getId()), r.parserUI && "function" == typeof r.parserUI ? r.parserUI(s, l) : r.parserUI && I.isArray(r.parserUI) && r.parserUI[s.id] ? r.parserUI[s.id].call(this, s, l) : (i = l, "SELECT" === (n = s).nodeName ? E(n, i) : "INPUT" === n.nodeName && S(n, i)), l.data.fieldId || (l.data.fieldId = T.getId());
            var d, c = function(e, t) {
                    var a, r, n = t.templateID;
                    if (n && (a = m.getElementById(n)), a) R(a), r = a.content.cloneNode(!0);
                    else {
                        var i = m.createElement("div");
                        i.innerHTML = t.template, (r = m.createDocumentFragment()).appendChild(i)
                    }
                    return q = [], N(r, e), r
                }(l, r),
                u = c.childNodes,
                p = u.length;
            for (b = 0; b < p; b++)
                if (1 === (d = u[b]).nodeType) {
                    var f = d.id;
                    f || (f = T.getId(), d.id = f), j[f] = l, d.classList.add("wb5React")
                }
            var h = c.querySelector("[role=combobox]");
            l.data.mustExist && c.querySelector("[role=combobox] input").setAttribute("data-rule-mustExist", "true"), s.parentNode.insertBefore(c, s), r.hideSourceUI ? a.addClass("hidden") : (s.id = T.getId(), C.appendChild(s));
            for (var b = 0; b < q.length; b++) q[b];
            a = I(c), s.dataset.wbLoad && I(h).trigger({
                type: "json-fetch.wb",
                fetch: {
                    url: s.dataset.wbLoad
                }
            }), "function" != typeof C.getElementById && (C.getElementById = function(e) {
                var t, a, r = this.childNodes,
                    n = r.length;
                for (t = 0; t < n; t += 1)
                    if ((a = r[t]).id === e) return a;
                return !1
            }), Modernizr.addTest("stringnormalize", "normalize" in String), Modernizr.load({
                test: Modernizr.stringnormalize,
                nope: ["site!deps/unorm" + T.getMode() + ".js"]
            }), T.ready(a, w)
        }
    }), T.add(y)
}(jQuery, window, document, wb),
function(c, a, e, u) {
    "use strict";
    var t = u.doc,
        i = {},
        r = (c.expr[":"].checked, function(e, t) {
            e.id || (e.id = u.getId());
            for (var a = 0; a < i.items.length; a++) {
                var r = i.items[a],
                    n = c.extend({}, r, {
                        value: r.label,
                        textContent: r.label
                    });
                n.source || (n.source = e.id), t.data.options.push(n)
            }
        });
    t.on("combobox.createctrl.wb-fieldflow", ".wb-fieldflow", function(e, t) {
        i = t, a["wb-combobox"] || (a["wb-combobox"] = {}), a["wb-combobox"].parserUI = [], a["wb-combobox"].parserUI[e.target.id] = r, a["wb-combobox"].hideSourceUI = !0, e.target.classList.add("wb-combobox"), c(e.target).trigger("wb-init.wb-combobox"), c(e.target).data().wbFieldflowRegister = [c(e.target).before().get(0).id], c(e.target).attr("data-wb-fieldflow-origin", c(e.target).before().get(0).id)
    }), t.on("wb.change", "[role=combobox]:not(.wb-fieldflow-init)", function(e, t) {
        var a = e.currentTarget,
            r = (c(a), t.item);
        a.id || (a.id = u.getId());
        var n, i = c("#" + r.bind).parentsUntil(".wb-fieldflow").parent();
        if (i.length) {
            n = i.get(0).id, r.source || n;
            var o = c("#" + r.bind).data().wbFieldflow;
            c.isArray(o) || (o = [o]);
            for (var s = 0; s < o.length; s++) {
                var l = o[s],
                    d = l.action + ".action.wb-fieldflow";
                l.provEvt = "#" + n, c("#" + n).trigger(d, l)
            }
        }
    })
}(jQuery, window, document, wb),
function(f, e, i, h) {
    "use strict";
    var b, g, m, v, w, y = "wb-steps",
        x = "." + y,
        t = h.doc,
        k = function(e, t, a, r) {
            var n = i.createElement(e);
            return n.className = ("prev" === t ? "btn btn-md btn-default" : "btn btn-md btn-primary") + " " + a, n.href = "#", n.setAttribute("aria-labelby", r), n.setAttribute("rel", t), n.setAttribute("role", "button"), n.innerHTML = r, n
        },
        A = function(e) {
            e.addEventListener("click", function(e) {
                e.preventDefault();
                var t = !!this.className && this.className,
                    a = t && -1 < t.indexOf("btn-primary"),
                    r = !0;
                a && jQuery.validator && "undefined" !== jQuery.validator && (r = f("#" + this.parentElement.parentElement.parentElement.id).valid()), r ? (n(this.parentElement, a), a && this.parentElement.previousElementSibling.classList.remove("wb-steps-error")) : a && !r && this.parentElement.previousElementSibling.classList.add("wb-steps-error")
            })
        },
        n = function(e, t) {
            var a, r;
            e && (e.classList.add("hidden"), (r = !!e.previousElementSibling && e.previousElementSibling) && r.classList.remove("wb-steps-active"), (a = t ? e.parentElement.nextElementSibling : e.parentElement.previousElementSibling) && (r = a.getElementsByTagName("LEGEND")[0], e = a.getElementsByTagName("DIV")[0], r && r.classList.add("wb-steps-active"), e && e.classList.remove("hidden")))
        };
    t.on("timerpoke.wb wb-init.wb-steps", x, function(e) {
        var t = h.init(e, y, x);
        if (t) {
            t.id || (t.id = h.getId()), g || (b = h.i18n, g = {
                prv: b("prv"),
                nxt: b("nxt")
            });
            var a, r = t.getElementsByTagName("FORM")[0],
                n = r ? f(r).children("fieldset") : 0;
            m && v && w || (m = k("A", "prev", "mrgn-rght-sm mrgn-bttm-md", g.prv), v = k("A", "next", "mrgn-bttm-md", g.nxt), (w = r.querySelector("input[type=submit], button[type=submit]")).classList.add("mrgn-bttm-md"));
            for (var i = 0, o = n.length; i < o; i++) {
                var s, l = n[i],
                    d = 0 === i,
                    c = i === o - 1,
                    u = l.firstElementChild,
                    p = !(!u || "LEGEND" !== u.tagName) && u.nextElementSibling;
                p && "DIV" === p.tagName && (a = !0, d || (s = m.cloneNode(!0), A(s), p.appendChild(s)), c ? p.appendChild(w) : (s = v.cloneNode(!0), A(s), p.appendChild(s)), l.classList.add("wb-tggle-fildst"), p.classList.add("hidden"), d && (u.classList.add("wb-steps-active"), p.classList.remove("hidden")))
            }
            r && a && f(r).children("input").hide()
        }
    }), h.add(x)
}(jQuery, window, document, wb),
function(u, n, o) {
    "use strict";
    var p, f, h, b, g, m, c, v, i, w = "wb-chtwzrd",
        y = "." + w,
        s = w + "-replace",
        x = o.doc,
        k = {},
        A = {},
        j = {
            en: {
                "chtwzrd-send": "Send<span class='wb-inv'> reply and continue</span>",
                "chtwzrd-toggle": "Switch to wizard",
                "chtwzrd-notification": "Close chat notification",
                "chtwzrd-open": "Open chat wizard",
                "chtwzrd-minimize": "Minimize chat wizard",
                "chtwzrd-history": "Conversation history",
                "chtwzrd-reply": "Reply",
                "chtwzrd-controls": "Controls",
                "chtwzrd-toggle-basic": "Switch to basic form",
                "chtwzrd-waiting": "Waiting for message",
                "chtwzrd-answer": "You have answered:"
            },
            fr: {
                "chtwzrd-send": "Envoyer<span class='wb-inv'> la rÃ©ponse et continuer</span>",
                "chtwzrd-toggle": "Basculer vers l&apos;assistant",
                "chtwzrd-notification": "Fermer la notification de discussion",
                "chtwzrd-open": "Ouvrir l&apos;assistant de discussion",
                "chtwzrd-minimize": "RÃ©duire l&apos;assistant de discussion",
                "chtwzrd-history": "Historique de discussion",
                "chtwzrd-reply": "RÃ©pondre",
                "chtwzrd-controls": "ContrÃ´les",
                "chtwzrd-toggle-basic": "Basculer vers le formulaire",
                "chtwzrd-waiting": "En attente d&apos;un message",
                "chtwzrd-answer": "Vous avez rÃ©pondu&nbsp;:"
            }
        },
        r = function(t) {
            if (void 0 !== typeof t.data(w + "-src") && t.data(w + "-src")) {
                var e = t.data(w + "-src");
                u.getJSON(e, function(e) {
                    d(t, k = e), a(t)
                })
            } else k = l(t), a(t)
        },
        a = function(e) {
            e.removeClass("hidden wb-inv").addClass(w + "-basic"), p = !(A = {
                shortDelay: 500,
                mediumDelay: 750,
                longDelay: 1250
            }), b = k.header.first, g = k.header.instructions ? k.header.instructions : "", h = k.header.defaultDestination, m = k.questions[b], f = k.header.formType ? k.header.formType : "dynamic", j = {
                send: (j = j[u("html").attr("lang") || "en"])["chtwzrd-send"],
                toggle: j["chtwzrd-toggle"],
                notification: j["chtwzrd-notification"],
                trigger: j["chtwzrd-open"],
                minimize: j["chtwzrd-minimize"],
                conversation: j["chtwzrd-history"],
                reply: j["chtwzrd-reply"],
                controls: j["chtwzrd-controls"],
                toggleBasic: j["chtwzrd-toggle-basic"],
                waiting: j["chtwzrd-waiting"],
                answer: j["chtwzrd-answer"]
            }, S(e, k.header.title);
            var t, a = u(y + "-basic"),
                r = u(y + "-bubble-wrap"),
                n = u(y + "-container"),
                i = u(".body", n),
                o = u(".history", n),
                s = u(".minimize", n),
                l = u(".basic-link", n),
                d = s,
                c = l;
            C(a), E(r), l.on("click", function(e) {
                e.preventDefault();
                var t = u("legend:first", a);
                t.attr("tabindex", "0"), o.attr("aria-live", ""), I(a, "form"), n.stop().hide(), a.stop().show(function() {
                    t.focus(), t.removeAttr("tabindex")
                }), u("body").removeClass(w + "-noscroll")
            }), u(y + "-link").on("click", function(e) {
                e.preventDefault(), a.stop().hide(), t = u(":focus"), u(this).hasClass(w + "-bubble") || I(n, "wizard"), u(".bubble", r).removeClass("trans-pulse"), u("p", r).hide().removeClass("trans-left"), n.stop().show(), r.stop().hide(), u("body").addClass(w + "-noscroll"), o.length && u(".conversation", n).scrollTop(o[0].scrollHeight), p || T(i)
            }), n.on("keydown", function(e) {
                9 === e.keyCode && (e.shiftKey ? d.is(":focus") && (e.preventDefault(), c.focus()) : c.is(":focus") && (e.preventDefault(), d.focus())), 27 === e.keyCode && s.click()
            }), x.on("click", y + "-container .btn-send", function(e) {
                if ("submit" != u(this).attr("type")) {
                    e.preventDefault();
                    var t = u("input:checked", i);
                    t.length || (t = u("input:first", i)).attr("checked", !0), q(i, z(t), !1)
                }
            }), s.on("click", function(e) {
                e.preventDefault(), n.stop().hide(), r.stop().show(), u("body").removeClass(w + "-noscroll"), t.focus()
            })
        },
        C = function(e) {
            var r = u("form", e),
                t = u("fieldset", e),
                a = t.first();
            "dynamic" == f && (a.addClass(w + "-first-q"), t.not(y + "-first-q").hide()), e.hide(), u("input", r).prop("checked", !1), r.append('<button class="btn btn-sm btn-link ' + w + '-link mrgn-rght-sm">' + j.toggle + "</button>"), u("input", r).on("change", function() {
                var e = z(u(this)),
                    t = u("#" + e.qNext, r);
                if ("dynamic" == f) {
                    var a = u(this).closest("fieldset");
                    (t.is(":hidden") || a.next().attr("id") != t.attr("id") || "none" == e.qNext) && a.nextAll("fieldset").hide().find("input").prop("checked", !1), "none" != e.qNext && u("#" + e.qNext).show(), "" != e.url && r.attr("action", e.url)
                }
            })
        },
        E = function(t) {
            var a = u("#wb-info");
            if (t.fadeIn("slow"), a.addClass(w + "-mrgn"), a.length) {
                var e = function(e) {
                    u(n).scrollTop() >= u(document).outerHeight() - u(n).outerHeight() - a.outerHeight() ? e.css({
                        bottom: a.outerHeight() - (u(document).outerHeight() - u(n).outerHeight() - u(n).scrollTop()) + 30
                    }) : e.css({
                        bottom: 30
                    })
                };
                e(t), u(n).on("resize scroll", function() {
                    e(t)
                })
            }
            u(".notif", t).on("click", function() {
                u(y + "-link", t).click()
            }), u(".notif-close", t).on("click", function(e) {
                e.preventDefault(), u(this).parent().hide(), t.focus()
            })
        },
        l = function(e) {
            var t = u("form", e),
                a = u("h2", e).first(),
                r = u("p:not(" + y + "-greetings):not(" + y + "-farewell)", t).first(),
                n = "btn-former-send",
                i = {};
            i.header = void 0 !== typeof e.data(w) && e.data(w) ? e.data(w) : {}, i.header.defaultDestination = t.attr("action"), i.header.name = t.attr("name"), i.header.method = t.attr("method"), i.header.form = {}, i.header.form.title = a.html(), i.header.title = N(a, i.header.form.title), i.header.greetings = u("p" + y + "-greetings", t).html(), i.header.farewell = u("p" + y + "-farewell", t).html(), i.header.form.sendBtn = u("input[type=submit]", t).length ? u("input[type=submit]", t).addClass(n).val() : u("button[type=submit]", t).addClass(n).html(), i.header.sendBtn = N(u("." + n, t), i.header.form.sendBtn), r.length && (i.header.form.instructions = r.html(), i.header.instructions = N(r, i.header.form.instructions));
            var o = u("fieldset", e);
            return i.questions = {}, void 0 !== i.header.first && i.header.first || (i.header.first = o.first().attr("id")), o.each(function() {
                var e = u("legend", u(this)),
                    t = u("label", u(this)),
                    a = u(this).attr("id"),
                    r = u("input[type=radio]", u(this)).length ? "radio" : "checkbox",
                    o = [],
                    s = "";
                t.each(function(e) {
                    var t = u("input", u(this)),
                        a = {},
                        r = t.attr("name"),
                        n = t.data(w + "-url"),
                        i = t.siblings("span:not(.no-" + w + ")").html();
                    e || (s = r), a.content = i, a.value = t.val(), a.next = t.data(w + "-next"), void 0 !== typeof n && n && (a.url = n), o.push(a)
                }), i.questions[a] = {}, i.questions[a].name = s, i.questions[a].input = r, i.questions[a].formLabel = e.html(), i.questions[a].label = N(e, i.questions[a].formLabel), i.questions[a].choices = o
            }), i
        },
        S = function(e, t) {
            e.after('<div class="' + w + '-bubble-wrap"><p class="trans-left"><span class="notif">' + t + '</span> <a href="#" class="notif-close" title="' + j.notification + '" aria-label="' + j.notification + '" role="button">Ã—</a></p><a href="#' + w + '-container" aria-controls="' + w + '-container" class="' + w + '-link bubble trans-pulse" role="button">' + j.trigger + "</a></div>"), e.next(y + "-bubble-wrap").after('<aside id="' + w + '-container" class="modal-content overlay-def ' + w + '-container"></aside>');
            var a = u(y + "-container");
            a.append('<header class="modal-header header"><h2 class="modal-title title">' + t + '</h2><button type="button" class="minimize" title="' + j.minimize + '"><span class="glyphicon glyphicon-chevron-down"></span></button></header>'), a.append('<form class="modal-body body" method="GET"></form>');
            var r = u(".body", a);
            r.append('<div class="conversation"><section class="history" aria-live="assertive"><h3 class="wb-inv">' + j.conversation + '</h3></section><section class="reply"><h3 class="wb-inv">' + j.reply + '</h3><div class="inputs-zone"></div></section><div class="form-params"></div></div>'), r.append('<section class="controls"><h3 class="wb-inv">' + j.controls + '</h3><div class="row"><div class="col-xs-12"><button class="btn btn-primary btn-block btn-send" type="button">' + j.send + '</button></div></div><div class="row"><div class="col-xs-12 text-center mrgn-tp-sm"><a href="#' + w + '-basic" class="btn btn-sm btn-link basic-link" role="button">' + j.toggleBasic + "</a></div></div></section>"), r.attr("name", k.header.name + "-chat"), r.attr("method", k.header.method), i = u(".btn-send ", r).html()
        },
        d = function(e, t) {
            e.html("");
            var a = "<h2>" + t.header.title + "</h2>",
                r = "<p>" + t.header.instructions + "</p>",
                n = ">" + t.header.sendBtn + "</button>";
            void 0 !== typeof t.header.form.title && (a = "<h2 data-" + s + '="' + t.header.title + '">' + t.header.form.title + "</h2>"), e.append(a + '<form class="mrgn-bttm-xl" action="' + t.header.defaultDestination + '" name="' + t.header.name + '" method="' + (t.header.method ? t.header.method : "GET") + '"></form>');
            var i = u("form", e);
            void 0 !== typeof t.header.form.instructions && (r = "<p data-" + s + '="' + t.header.instructions + '">' + t.header.form.instructions + "</p>"), i.append('<p class="wb-chtwzrd-greetings wb-inv">' + t.header.greetings + "</p>" + r), u.each(t.questions, function(e, a) {
                var r = o.getId(),
                    t = "<legend>" + a.label + "</legend>";
                void 0 !== typeof a.formLabel && a.formLabel && (t = "<legend data-" + s + '="' + a.label + '">' + a.formLabel + "</legend>"), i.append('<fieldset id="' + e + '" class="' + r + '">' + t + '<ul class="list-unstyled mrgn-tp-md"></ul></fieldset>');
                var n = u("." + r, i);
                u.each(a.choices, function(e, t) {
                    r = o.getId(), u("ul", n).append('<li><label><input type="' + a.input + '" value="' + t.value + '" id ="' + r + '" name="' + a.name + '" data-value="' + t.content + '" /> <span>' + t.content + "</span>"), u("#" + r, n).attr("data-" + w + "-next", t.next), void 0 !== typeof t.url && t.url && u("#" + r, n).attr("data-" + w + "-url", t.url)
                })
            }), void 0 !== typeof t.header.form.sendBtn && (n = " data-" + s + '="' + t.header.sendBtn + '">' + t.header.form.sendBtn + "</button>"), i.append('<p class="wb-chtwzrd-farewell wb-inv">' + t.header.farewell + '</p><br/><button type="submit" class="btn btn-sm btn-primary"' + n), void 0 !== k.header.first && k.header.first || (k.header.first = u("fieldset", i).first().attr("id"))
        },
        I = function(e, t) {
            if ("wizard" == t) {
                var a = u(".conversation", e);
                n.clearTimeout(c), n.clearTimeout(v), p = !1, h = k.header.defaultDestination, b = k.header.first, g = k.header.instructions ? k.header.instructions : "", m = k.questions[b], u(".history, .form-params", a).html(""), u(".btn-send", e).attr("type", "button").html(i), u(".history", a).attr("aria-live", "assertive"), T(u(".body", e))
            } else {
                var r = u("fieldset", e);
                "dynamic" == f && (r.not(":first").hide(), u("input", r).prop("checked", !1))
            }
        },
        T = function(n) {
            var i = u(".history", n),
                o = u(".inputs-zone", n),
                s = u(".conversation", n),
                l = u(".btn-send", n),
                e = "" != b || "" != g || "last" == m ? "p" : "h4";
            p = !0, l.prop("disabled", !0), o.html(""), i.append('<div class="row mrgn-bttm-md"><div class="col-xs-9"><' + e + ' class="mrgn-tp-0 mrgn-bttm-0"><span class="avatar"></span><span class="question"></span></' + e + "></div></div>");
            var d = u(".question:last", i);
            t(d), c = setTimeout(function() {
                "" != b ? (d.html(k.header.greetings), b = "", T(n)) : "" != g ? (d.html(g), g = "", T(n)) : "last" == m ? (d.html(k.header.farewell), l.attr("type", "submit").prop("disabled", !1).html(k.header.sendBtn + '&nbsp;<span class="glyphicon glyphicon-chevron-right small"></span>'), n.attr("action", h)) : (d.html(m.label), m.input = "radio", v = setTimeout(function() {
                    o.append('<fieldset><legend class="wb-inv">' + m.label + '</legend><div class="row"><div class="col-xs-12"><ul class="' + ("inline" == k.header.displayForm ? "list-inline" : "list-unstyled") + ' mrgn-tp-sm choices"></ul></div></div></fieldset>');
                    for (var e = 0; e < m.choices.length; e++) {
                        var t = m.choices[e];
                        u(".choices", o).append('<li><label><input type="' + m.input + '" value="' + t.value + '" name="' + m.name + '" data-' + w + '-next="' + t.next + '"' + (void 0 === t.url ? "" : " data-" + w + '-url="' + t.url + '"') + (e ? "" : "checked ") + "/> <span>" + t.content + "</span></label></li>")
                    }
                    l.prop("disabled", !1);
                    var a = s[0].scrollHeight,
                        r = u(".reply", n);
                    r.length && r.outerHeight() + d.outerHeight() > s.innerHeight() && (a = i[0].scrollHeight - d.outerHeight() - 42), s.scrollTop(a)
                }, A.mediumDelay)), s.scrollTop(s[0].scrollHeight)
            }, A.longDelay)
        },
        q = function(e, t) {
            var a = o.getId(),
                r = u(".history", e);
            r.append('<div class="row mrgn-bttm-md"><div class="col-xs-9 col-xs-offset-3"><div class="message text-right pull-right" id="' + a + '"><p class="mrgn-bttm-0"><span class="wb-inv">' + j.answer + " </span>" + t.value + "</p></div></div></div>"), u(".form-params", e).append('<input type="hidden" name="' + t.name + '" value="' + t.val + '" data-value="' + t.value + '" />'), p = !1, "" != t.url && (h = t.url);
            var n = t.qNext,
                i = u("#" + a, r);
            m = "none" == n ? "last" : k.questions[n], u(".btn-send", e).prop("disabled", !0), i.attr("tabindex", "0"), c = setTimeout(function() {
                u(".inputs-zone", e).remove("fieldset"), i.focus(), i.removeAttr("tabindex"), T(e)
            }, A.shortDelay)
        },
        t = function(e) {
            e.html('<span class="loader-typing" aria-label="' + j.waiting + '"><span class="loader-dot dot1"></span><span class="loader-dot dot2"></span><span class="loader-dot dot3"></span></span>')
        },
        N = function(e, t) {
            var a = e.data(s);
            return void 0 !== typeof a && a ? a : t
        },
        z = function(e) {
            var t = e.data(w + "-next"),
                a = e.data(w + "-url");
            return {
                qNext: t,
                name: e.attr("name"),
                val: e.val(),
                url: void 0 !== typeof a && a ? a : "",
                value: e.next().html()
            }
        };
    x.on("timerpoke.wb wb-init.wb-chtwzrd", y, function(e) {
        var t, a = o.init(e, w, y);
        a && (t = u(a), r(t), o.ready(t, w))
    }), o.add(y)
}(jQuery, window, wb), $(document).on("do.wb-actionmng", "table[data-wb-urlmapping][data-wb5-bind]", function(e) {
    var t = $(e.currentTarget);
    t.one("draw.dt", function() {
        t.trigger("refreshCtrl.wbtbl")
    })
});

