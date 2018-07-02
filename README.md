# bcash_network_test_tool_01
A low and mid-level test toolkit for the Bcash p2p network.

1. Download and run ./build_linux.sh or build_mac.sh respectively.
2. Acess the RPC interface using CURL or equivalent.
	Example:
	curl --data-binary '{"jsonrpc":"1.0","id":"curltext","method":"getinfo","params":[]}' -H 'content-type:text/plain;' http://127.0.0.1:8332/
