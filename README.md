> *Metadata absolutely tells you everything about somebody's life*
>
> — [Stewart Baker](http://www.nybooks.com/articles/archives/2013/nov/21/snowden-leaks-and-public/), former General Counsel of the NSA

|

> *We kill people based on metadata*
>
> — [Michael Hayden](https://www.youtube.com/watch?v=kV2HDM86XgI&t=17m53s), former Director of the NSA

# Vuvuzela

Vuvuzela is a messaging system that protects the privacy of message contents
and message metadata.  Users communicating through Vuvuzela do not reveal who
they are talking to, even in the presence of powerful nation-state adversaries.
Our [SOSP 2015 paper](https://davidlazar.org/papers/vuvuzela.pdf) explains
the system, its threat model, performance, limitations, and more.  Our
[SOSP 2015 slides](https://davidlazar.org/slides/vuvuzela-sosp2015.pdf) give
a more graphical overview of the system.

Vuvuzela is the first system that provides strong metadata privacy while
scaling to millions of users.  Previous systems that hide metadata using
Tor (such as [Pond](https://pond.imperialviolet.org/)) are prone to traffic
analysis attacks.  Systems that encrypt metadata using techniques like
DC-nets and PIR don't scale beyond thousands of users.

Vuvuzela uses efficient cryptography ([NaCl](http://nacl.cr.yp.to)) to hide as
much metadata as possible and adds noise to metadata that can't be encrypted
efficiently.  This approach provides less privacy than encrypting all of the
metadata, but it enables Vuvuzela to support millions of users.  Nonetheless,
Vuvuzela adds enough noise to thwart adversaries like the NSA and guarantees
[differential privacy](https://en.wikipedia.org/wiki/Differential_privacy) for
users' metadata.


## Screenshots

**A conversation in the Vuvuzela client**

![client](https://github.com/vuvuzela/vuvuzela/blob/master/screenshots/client.gif)

In practice, the message latency would be around 20s to 40s, depending
on security parameters and the number of users connected to the system.

**Noise generated by the Vuvuzela servers**

![server](https://github.com/vuvuzela/vuvuzela/blob/master/screenshots/server.gif)

Vuvuzela is unable to encrypt two kinds of metadata: the number of idle users
(connected users without a conversation partner) and the number of active users
(users engaged in a conversation).  Without noise, a sophisticated adversary
could use this metadata to learn who is talking to who.  However, the Vuvuzela
servers generate noise that perturbs this metadata so that it is difficult to
exploit.


## Usage

Follow these steps to run the Vuvuzela system locally using the provided
sample configs.

1. Install Vuvuzela (assuming `GOPATH=~/go`, requires Go 1.4 or later):

        $ git clone https://github.com/XianmingLuo/CPS512-Vuvuzela.git
        $ cd CPS512-Vuvuzela
        $ go mod tidy

  The remaining steps assume `PATH` contains `~/go/bin` and that the
  current working directory is `~/go/src/vuvuzela.io/vuvuzela`.

2. Start the last Vuvuzela server:

        $ cd vuvuzela-server
        $ go run . -conf ../confs/local-last.conf

3. Start the middle server (in a new shell):

        $ cd vuvuzela-server
        $ go run . -conf ../confs/local-middle.conf

4. Start the first server (in a new shell):

        $ cd vuvuzela-server
        $ go run . -conf ../confs/local-first.conf

5. Start the entry server (in a new shell):

        $ cd vuvuzela-entry-server
        $ go run . -wait 1s

6. Run the Vuvuzela client:

        $ cd vuvuzela-client
        $ go run . -conf ../confs/alice.conf

7. Run another Vuvuzela client:
    
        $ cd vuvuzela-client
        $ go run . -conf ../confs/bob.conf
The client supports these commands:

* `/dial <user>` to dial another user
* `/talk <user>` to start a conversation
* `/talk <yourself>` to end a conversation


## Deployment considerations

This Vuvuzela implementation is not ready for wide-use deployment.
In particular, we haven't yet implemented these crucial components:

* **Public Key Infrastructure**:
Vuvuzela assumes the existence of a PKI in which users can privately
learn each others public keys.  This implementation uses `pki.conf`
as a placeholder until we integrate a real PKI.

* **CDN to distribute dialing dead drops**:
Vuvuzela's dialing protocol (used to initiate conversations) uses a
lot of server bandwidth.  To make dialing practical, Vuvuzela should
use a CDN or BitTorrent to distribute the dialing dead drops.

There is a lot more interesting work to do.  See the
[issue tracker](https://github.com/vuvuzela/vuvuzela/issues)
for more information.


## Acknowledgements

This code is written by David Lazar with contributions from
Jelle van den Hooff, Nickolai Zeldovich, and Matei Zaharia.


## See also

[Vuvuzela web client](https://github.com/jlmart88/vuvuzela-web-client)
