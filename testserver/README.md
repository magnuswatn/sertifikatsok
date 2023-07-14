testserver
=====

This is a test server that is used to emulate Buypass and Commfides,
so that we can run API tests against a well-known set of test data, and without
bothering Buypass or Commfides. It clones our trusted CAs, creates some test
certificates and exposes them over LDAP as similar to Buypass+Commfides as
possible.
