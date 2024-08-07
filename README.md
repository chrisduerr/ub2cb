# uBlock => Content Blocker

This tool is a utility to convert [uBlock's filters] to [WebKit Content
Blockers].

## Usage

```sh
cargo run -p ub2cb_bin --release -- ublock.txt > content_blocker.json
```

[uBlock's filters]: https://github.com/uBlockOrigin/uAssets
[WebKit Content Blockers]: https://developer.apple.com/documentation/safariservices/creating-a-content-blocker
