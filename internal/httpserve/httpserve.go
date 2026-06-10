// Package httpserve runs an HTTPS server with graceful shutdown. It serves in a
// goroutine and, on SIGINT/SIGTERM, drains in-flight requests via
// http.Server.Shutdown so the caller's deferred cleanup (e.g. flushing and
// closing the audit log) actually runs — which it does not when main exits via
// log.Fatal on a raw ListenAndServeTLS.
package httpserve

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// RunTLS serves srv over TLS (the certificate is taken from srv.TLSConfig, so
// the empty cert/key arguments are intentional) and blocks until a termination
// signal arrives or the server fails. On a signal it shuts down gracefully
// within shutdownTimeout and returns, allowing the caller's defers to run. A
// serve error before shutdown is fatal. name labels the log lines.
func RunTLS(srv *http.Server, name string, shutdownTimeout time.Duration) {
	errc := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errc <- err
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-errc:
		log.Fatalf("%s: serve: %v", name, err)
	case sig := <-stop:
		log.Printf("%s: received %s, shutting down...", name, sig)
	}

	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("%s: graceful shutdown error: %v", name, err)
	}
}
