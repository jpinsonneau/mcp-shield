package tokenstore

import (
	"io"
	"log/slog"
	"testing"
	"time"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestTokenStore_StoreGet(t *testing.T) {
	ts := NewTokenStore(discardLogger(), time.Hour)
	defer ts.Stop()

	ts.Store("proxy-a", "real-a")
	got, ok := ts.Get("proxy-a")
	if !ok || got != "real-a" {
		t.Fatalf("Get(proxy-a) = %q, %v; want real-a, true", got, ok)
	}
	if ts.Size() != 1 {
		t.Fatalf("Size() = %d; want 1", ts.Size())
	}
}

func TestTokenStore_GetMissing(t *testing.T) {
	ts := NewTokenStore(discardLogger(), time.Hour)
	defer ts.Stop()

	_, ok := ts.Get("nope")
	if ok {
		t.Fatal("expected miss")
	}
}

func TestTokenStore_Expired(t *testing.T) {
	ts := NewTokenStore(discardLogger(), time.Millisecond)
	defer ts.Stop()

	ts.Store("p", "r")
	time.Sleep(5 * time.Millisecond)
	_, ok := ts.Get("p")
	if ok {
		t.Fatal("expected expired token to miss")
	}
}

func TestTokenStore_Delete(t *testing.T) {
	ts := NewTokenStore(discardLogger(), time.Hour)
	defer ts.Stop()

	ts.Store("p", "r")
	ts.Delete("p")
	if ts.Size() != 0 {
		t.Fatalf("Size after delete = %d", ts.Size())
	}
	_, ok := ts.Get("p")
	if ok {
		t.Fatal("expected miss after delete")
	}
}

func TestGenerateProxyToken(t *testing.T) {
	ts := NewTokenStore(discardLogger(), time.Hour)
	defer ts.Stop()

	a, err := ts.GenerateProxyToken()
	if err != nil || a == "" {
		t.Fatalf("GenerateProxyToken() = %q, %v", a, err)
	}
	b, err := ts.GenerateProxyToken()
	if err != nil || a == b {
		t.Fatalf("expected two distinct tokens: %q vs %q", a, b)
	}
}
