
# About

`bounce_back` is a simple network throughput benchmark.

# Features

 * Test network throughput using a client/server pair.
 * Configurable message size.
 * Support ssl/tls

# Quick example: testing throughput

    bounce_back 0 256 1024 &
    bounce_back 1 256 1024

# Install

## From sources

Install the following packages first:

 * automake
 * gcc-c++
 * openssl

**Build and install:**

    make prepare
    make install


# Usage (Short version)

    Usage: bounce_back [RANK] [REPEAT] [MESSAGE_SIZE]
    RANK:
        0:                  server
        1:                  client
        2:                  server with ssl
        3:                  client with ssl
    REPEAT: an integer implying how many messages (k) send in total
    MESSAGE_SIZE: an integer implying the size (B) of a single message

# Usage Examples
<details>
<summary>A few command line examples</summary>

## TCP Examples

Start the server. The server will listen on port 8090 until the client connects:

    bounce_back 0 256 1024

Start the client (recommend in another terminal):

    bounce_back 1 256 1024

## TCP_SSL examples

Make sure there are certificates and keys in current directory './myCA':

    make prepare
    %or%
    ./key_generator.sh

In './myCA', you should see (bounce_back uses the following files by default):

    * client-cert.pem
    * client-key.pem
    * server-cert.pem
    * server-key.pem

Start the server. The server will listen on port 8090 until the client connects:

    bounce_back 2 256 1024

Start the client (recommend in another terminal):

    bounce_back 3 256 1024

</details>
