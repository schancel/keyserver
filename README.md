# Cash:web Keyserver

This repository hosts a reference implementation of the Cash:web Keyserver protocol.  The goal of this is to provide a simple-to-use and cryptographically verifiable way to look up xpubkeys, and other metadata, from their hashes.  The hashes are commonly available within Bitcoin Cash Addresses such as `bitcoincash:pqkh9ahfj069qv8l6eysyufazpe4fdjq3u4hna323j`.  This enables wallets to query a distributed network of metadata nodes to find out various information for contacting or paying the owners in a secure and private manner.  Additionally, wallets managing a key can advertise special capabilities they support.

# Why not existing systems?

Traditional keyservers are subject to certificate spamming attacks. By being a first-class citizen in the cryptocurrency ecosystem, we are able to charge for key updates.  This prevents an explosion of advertised certificates, and provides some funding for node operators.  Other systems like OpenAlias, require you to trust that the service provider is providing the correct addresses, while this keyserver cannot forge such updates as they are died to a keyid which has been provided via another channel.  At most, a keyserver can censor a particular key, but other keyservers may provide that information.

# Special Thanks

Special thanks goes out to Chris Pacia, Tyler Smith, and Josh Ellithorpe for writing and maintaining `bchd` and the `bchutil` library.  This services makes substantial use of them, and without their work this service would have been significantlly more difficult to write.