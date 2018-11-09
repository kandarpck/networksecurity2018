# Johns Hopkins University - Network Security 2018

This project contains documents and code to design an overlay network over the simulated wire protocol defined by the Playground project from Seth Neilson.

The overlay network is defines and implements a reliable transport layer mechanism to add features which are similar to TCP.

# Description
 * The Playground RFC to specify the reliable transport layer can be found inside `docs/prfc/drafts/reliable.{txt,xml}`
 * The Playground RFC to specify a protocol that provides confidentiality, message integrity, and mutual authentication. over the reliable transport layer can be found inside `docs/prfc/drafts/secure_transport.{txt,xml}`
 * These documents are taken as the spec for implementing the RIPP and the SITH protocol inside the `labs/` folder.
 
# Future work
 * ~Draft the TLS protocol~ [Done]
 * Implement the TLS protocol
 
