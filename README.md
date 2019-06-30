# Cash:web Keyserver

This repository hosts a reference implementation of the Cash:web Keyserver protocol.  The goal of this is to provide a simple-to-use and cryptographically verifiable way to look up xpubkeys from their hashes.  This allows for BCH/ETH/BTC keys to be provided.

# Why not existing systems?

Traditional keyservers are subject to certificate spamming attacks. By being a first-class citizen in the cryptocurrency ecosystem, we are able to charge for key updates.  This prevents an explosion of advertised certificates, and provides some funding for node operators.  Other systems like OpenAlias, require you to trust that the service provider is providing the correct addresses, while this keyserver cannot forge such updates as they are died to a keyid which has been provided via another channel.  At most, a keyserver can censor a particular key, but other keyservers may provide that information.
