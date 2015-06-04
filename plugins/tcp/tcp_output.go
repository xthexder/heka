/***** BEGIN LICENSE BLOCK *****
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
#
# The Initial Developer of the Original Code is the Mozilla Foundation.
# Portions created by the Initial Developer are Copyright (C) 2012-2015
# the Initial Developer. All Rights Reserved.
#
# Contributor(s):
#   Rob Miller (rmiller@mozilla.com)
#   Mike Trinkala (trink@mozilla.com)
#   Carlos Diaz-Padron (cpadron@mozilla.com,carlos@carlosdp.io)
#
# ***** END LICENSE BLOCK *****/

package tcp

import (
	"crypto/tls"
	"fmt"
	"net"
	"regexp"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mozilla-services/heka/message"
	. "github.com/mozilla-services/heka/pipeline"
)

// Output plugin that sends messages via TCP using the Heka protocol.
type TcpOutput struct {
	processMessageCount int64
	dropMessageCount    int64
	activeServer        int64
	serverTimeout       []time.Time
	keepAliveDuration   time.Duration
	conf                *TcpOutputConfig
	addresses           []string
	localAddress        net.Addr
	connections         []net.Conn
	name                string
	reportLock          sync.Mutex
	or                  OutputRunner
	pConfig             *PipelineConfig
}

// ConfigStruct for TcpOutput plugin.
type TcpOutputConfig struct {
	// String representation of the TCP address to which this output should be
	// sending data.
	Addresses    []string
	LocalAddress string `toml:"local_address"`
	UseTls       bool   `toml:"use_tls"`
	Tls          TlsConfig
	// Interval at which the output queue logs will roll, in seconds. Defaults
	// to 300.
	TickerInterval uint `toml:"ticker_interval"`
	// Allows for a default encoder.
	Encoder string
	// Set to true if TCP Keep Alive should be used.
	KeepAlive bool `toml:"keep_alive"`
	// Integer indicating seconds between keep alives.
	KeepAlivePeriod int `toml:"keep_alive_period"`
	// Number of successfully processed messages to re-establish the TCP
	// connection after.  Defaults to 0 (never)
	ReconnectAfter int64 `toml:"reconnect_after"`
	// Specifies whether or not Heka's stream framing wil be applied to the
	// output. We do some magic to default to true if ProtobufEncoder is used,
	// false otherwise.
	UseFraming *bool `toml:"use_framing"`
	// Defaults to true for TcpOutput.
	UseBuffering *bool `toml:"use_buffering"`
	Buffering    QueueBufferConfig
}

func (t *TcpOutput) ConfigStruct() interface{} {
	b := true
	queueConfig := QueueBufferConfig{
		CursorUpdateCount: 50,
		MaxBufferSize:     0,
		MaxFileSize:       128 * 1024 * 1024,
		FullAction:        "shutdown",
	}
	return &TcpOutputConfig{
		Addresses:    []string{"localhost:9125"},
		Encoder:      "ProtobufEncoder",
		UseBuffering: &b,
		Buffering:    queueConfig,
	}
}

func (t *TcpOutput) SetName(name string) {
	re := regexp.MustCompile("\\W")
	t.name = re.ReplaceAllString(name, "_")
}

func (t *TcpOutput) Init(config interface{}) (err error) {
	t.conf = config.(*TcpOutputConfig)
	t.addresses = t.conf.Addresses
	t.connections = make([]net.Conn, len(t.addresses))
	t.serverTimeout = make([]time.Time, len(t.addresses))

	if t.conf.LocalAddress != "" {
		// Error out if use_tls and local_address options are both set for now.
		if t.conf.UseTls {
			return fmt.Errorf("Cannot combine local_address %s and use_tls config options",
				t.localAddress)
		}
		t.localAddress, err = net.ResolveTCPAddr("tcp", t.conf.LocalAddress)
	}

	if t.conf.KeepAlivePeriod != 0 {
		t.keepAliveDuration = time.Duration(t.conf.KeepAlivePeriod) * time.Second
	}

	return
}

func (t *TcpOutput) Prepare(or OutputRunner, h PluginHelper) (err error) {
	if t.conf.UseFraming == nil {
		// Nothing was specified, we'll default to framing IFF ProtobufEncoder
		// is being used.
		if _, ok := or.Encoder().(*ProtobufEncoder); ok {
			or.SetUseFraming(true)
		}
	}

	t.pConfig = h.PipelineConfig()
	t.or = or

	return nil
}

func (t *TcpOutput) cleanupConn(i int) {
	if t.connections[i] != nil {
		t.connections[i].Close()
		t.connections[i] = nil
		t.serverTimeout[i] = time.Now().Add(30 * time.Second)
	}
}

func (t *TcpOutput) CleanUp() {
	for i := range t.connections {
		t.cleanupConn(i)
	}
}

func (t *TcpOutput) ProcessMessage(pack *PipelinePack) (err error) {
	defer func() {
		t.activeServer++
	}()

	var (
		n      int
		record []byte
	)
	for attempt := range t.addresses {
		i := int((t.activeServer + int64(attempt)) % int64(len(t.addresses)))
		if err != nil {
			// Print the last error since it won't be returned
			t.or.LogError(err)
		}

		if t.connections[i] == nil {
			if attempt == len(t.addresses)-1 || t.serverTimeout[i].Before(time.Now()) {
				if err = t.connect(i); err != nil {
					// Explicitly set t.connections[i] to nil because Go, see
					// http://golang.org/doc/faq#nil_error.
					t.connections[i] = nil
					t.serverTimeout[i] = time.Now().Add(30 * time.Second)
					err = NewRetryMessageError("can't connect: %s", err)
				}
			} else {
				continue
			}
		}

		if record, err = t.or.Encode(pack); err != nil {
			atomic.AddInt64(&t.dropMessageCount, 1)
			return fmt.Errorf("can't encode: %s", err)
		}

		if n, err = t.connections[i].Write(record); err != nil {
			t.cleanupConn(i)
			err = NewRetryMessageError("writing to %s: %s", t.addresses[i], err)
		} else if n != len(record) {
			t.cleanupConn(i)
			err = NewRetryMessageError("truncated output to: %s", t.addresses[i])
		} else {
			atomic.AddInt64(&t.processMessageCount, 1)
			t.or.UpdateCursor(pack.QueueCursor)
			if t.conf.ReconnectAfter > 0 &&
				atomic.LoadInt64(&t.processMessageCount)%t.conf.ReconnectAfter == 0 {

				t.cleanupConn(i)
			}
		}
	}

	return err
}

func (t *TcpOutput) connect(i int) (err error) {
	dialer := &net.Dialer{LocalAddr: t.localAddress}

	if t.conf.UseTls {
		var goTlsConf *tls.Config
		if goTlsConf, err = CreateGoTlsConfig(&t.conf.Tls); err != nil {
			return fmt.Errorf("TLS init error: %s", err)
		}
		// We should use DialWithDialer but its not in GOLANG release yet.
		// https://code.google.com/p/go/source/detail?r=3d37606fb79393f22a69573afe31f0b0cd4866e3&name=default
		// t.connection, err = tls.DialWithDialer(dialer, "tcp", t.address, goTlsConf)
		t.connections[i], err = tls.Dial("tcp", t.addresses[i], goTlsConf)
	} else {
		t.connections[i], err = dialer.Dial("tcp", t.addresses[i])
	}
	if err == nil && t.conf.KeepAlive {
		tcpConn, ok := t.connections[i].(*net.TCPConn)
		if !ok {
			t.or.LogError(fmt.Errorf("KeepAlive only supported for TCP Connections."))
		} else {
			tcpConn.SetKeepAlive(t.conf.KeepAlive)
			if t.keepAliveDuration != 0 {
				tcpConn.SetKeepAlivePeriod(t.keepAliveDuration)
			}
		}
	}
	return
}

// Satisfies the `pipeline.ReportingPlugin` interface to provide plugin state
// information to the Heka report and dashboard.
func (t *TcpOutput) ReportMsg(msg *message.Message) error {
	t.reportLock.Lock()
	defer t.reportLock.Unlock()

	message.NewInt64Field(msg, "ProcessMessageCount",
		atomic.LoadInt64(&t.processMessageCount), "count")
	message.NewInt64Field(msg, "DropMessageCount",
		atomic.LoadInt64(&t.dropMessageCount), "count")

	return nil
}

func init() {
	RegisterPlugin("TcpOutput", func() interface{} {
		return new(TcpOutput)
	})
}
