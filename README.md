ParaZMQ
-------

ParaZMQ is a pure-Go implementation of ZeroMQ 4.0's ZMTP/3.0.

ParaZMQ supports NULL and PLAIN authentication as well as the CurveZMQ authentication and encryption protocol.

ParaZMQ is NOT an implementation of ZeroMQ; it is an implementation only of the ZMTP protocol. The advanced fan-in/fan-out patterns and behind-the-scenes concurrency used by ZeroMQ are not present. In fact, this library launches no goroutines at all. You call Send, a ZMTP message is synchronously sent. You call Receive, a ZMTP message is synchronously received. Use of concurrency is completely up to the caller.

Each ParaZMQ session corresponds to an underlying (TCP) stream. If the stream is closed for whatever reason, so is the session. So this library is much lower level than ZeroMQ.

Since ParaZMQ is built on net.Conn, you can actually run ZMTP across anything supporting that interface, so unlike ZeroMQ you could use ZMTP with whatever exotic transport you desire.

ParaZMQ is internally structured as a layering of frame stream interfaces. A RawSession implements the base ZMTP protocol, and handshaking, authentication and CurveZMQ are then built upon that as further layers. Finally, this is all tied together as a Session. In the majority of cases you will just want to use the Session frontend interface.

Documentation
-------------

[See godoc.org.](http://godoc.org/github.com/hlandau/parazmq)

Licence
-------
© 2014 Hugo Landau <hlandau@devever.net> — GPLv3 or later
