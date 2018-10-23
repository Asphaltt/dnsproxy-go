# A simple library for DNS proxy

This is a completed DNS proxy.

## Usage

Like example as `cmd/dnsproxy`

> go get github.com/Asphaltt/dnsproxy-go

and use the library in your project.

```go
	cfg := &dnsproxy.Config{
		Addr:          ":53",
		UpServers:     []string{"8.8.8.8"},
		WithCache:     true,
		CacheFile:     "cache.json",
		WorkerPoolMin: 100,
		WorkerPoolMax: 1000,
	}

	if err := dnsproxy.Start(cfg); err != nil {
		return
	}
	defer dnsproxy.Close()
```

Or you can compile `cmd/dnsproxy` to run as a dns proxy server.

## License

[MIT License](https://github.com/Asphaltt/dnsproxy-go/blob/master/LICENSE)