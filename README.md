# Johns Hopkins University - Network Security 2018

This project contains documents and code to design an overlay network over the simulated wire protocol defined by the Playground project from Seth Neilson.

The overlay network defines and implements a reliable transport layer mechanism to add features which take inspiration from TCP and TLS 1.3.

# Description
 * The Playground RFC for the Reliable Internetwork Playground Protocol (RIPP) to specify the reliable transport layer can be found inside `docs/prfc/drafts/reliable.{txt,xml}`
 * The Playground RFC for the Secure Internetwork Transport Handshake (SITH) used to specify a protocol that provides confidentiality, message integrity, and mutual authentication over the reliable transport layer RIPP can be found inside `docs/prfc/drafts/secure_transport.{txt,xml}`
 * These documents are used as the spec for implementing the RIPP and the SITH protocols inside the `labs/` folder.
 
# Future work
 * ~Draft the TLS protocol~ [Done]
 * Implement the TLS protocol
 
