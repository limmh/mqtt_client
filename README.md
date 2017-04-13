A sample MQTT client using Mosquitto client library
===================================================

## Introduction

This is an MQTT client that is implemented using the Mosquitto client library.
For more information about the Mosquitto library , please visit its [official page](http://mosquitto.org) or its [Github page](https://github.com/eclipse/mosquitto).

## Software Libraries

The following are the required libraries.

- Mosquitto MQTT client library
- POSIX threads (pthreads)
- OpenSSL

The Mosquitto client library should be built with the Transport Layer Security (TLS) feature.
OpenSSL is needed for TLS support.

On Windows, pthreads for Windows is required.
Its source code is available on this [link](https://sourceforge.net/projects/pthreads4w/).

## Description

The sample MQTT client is a command line program.
MQTT protocol configuration, such as server name, port number, keep alive, clean session, etc. are specified on the command line parameters.

If a client ID is not provided, it is generated randomly.
After a TCP connection is established successfully, an MQTT connection will be established.
After the MQTT connection is successful, the client can be used to publishing messages and to subscribe to topics of interest.

Messages can be published in text or binary format.
The messages for subscribed topics are written to a file with the same name as the client ID in the program folder.

## Building the client

A Makefile for GNU/Linux is available.
The Mosquitto library is not included.
For successful compilation, place the mosquitto.h header file and the mosquitto library file in the same folder as the client source files.
OpenSSL, which can be obtained from the package manager of your distro, should be installed prior to compilation.
The client has been compiled successfully and tested on Debian 8, Ubuntu 16.10 and CentOS 7.

The distribution includes the library binary files and the necessary header files (including mosquitto.h) for Windows.
A Visual Studio 2015 solution is available and all of the library DLLs are built to link to VC++ 2015 runtime.

The MQTT client has not been compiled and tested on POSIX platforms such as FreeBSD and MacOS.
It may be tested on those platforms in the future.

## Testing the client

An MQTT broker (server) is needed to test the client.
You can install the Mosquitto broker on your computer or use some public MQTT brokers, such as those in this [link](https://github.com/mqtt/mqtt.github.io/wiki/public_brokers).
