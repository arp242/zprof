zprof displays runtime profiling data over HTTP.

This is based on [net/http/pprof][httppprof]; but has been rewritten quite a bit
and is much nicer. You can display the callgraphs directly without downloading
the file first, and a bunch of other changes. It doesn't give you the full power
of the CLI, but overall it's fairly useful.

Import as `zgo.at/zprof`; you need Go 1.16.

Current status: fairly functional, still some things left to do. API may break.

[httppprof]: https://godocs.io/net/http/pprof

Usage
-----

Unlike `net/http/pprof` endpoints are not registered automatically; use
`zprof.NewHandler()` to create a new handler to mount with your router, for
example using net/http's default mux:

    http.Handle("/profile*", zprof.NewHandler(zprof.Prefix("/profile")))

Or with chi:

    r := chi.NewRouter()
    r.Handle("/profile*", zprof.NewHandler(zprof.Prefix("/profile")))

Because you may not want to expose this to everyone you can add HTTP Basic auth
with `Auth()`:

    http.Handle("/profile*", zprof.NewHandler(zprof.Prefix("/profile"),
        zprof.Auth("user", "passwd")))

Or handle auth in your regular app middleware.

You can use the `zprof.Profile()` shortcut if your application doesn't have a
HTTP server:

    zprof.Profile("")

This will set up a HTTP server on `localhost:6060`; use the first parameter to
configure the address.

Like with net/http/pprof, you can still use the commandline tool if you prefer:

	$ go tool pprof http://localhost:6060/debug/pprof/heap

	$ wget -O trace.out http://localhost:6060/debug/pprof/trace?seconds=5
	$ go tool trace trace.out
